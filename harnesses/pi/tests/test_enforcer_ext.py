"""Pi's enforcer extension (harnesses/pi/image/extensions/enforcer/index.ts) under
the host's node (type stripping): its file-tool write rule. Skipped without node."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from glove.harness import get_profile
from tests.helpers import path_rule_cases

EXT = Path(__file__).resolve().parents[1] / "image" / "extensions" / "enforcer" / "index.ts"
pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="needs node")


def _node(tmp_path: Path, body: str) -> dict:
    """Run `body` (JS, with the extension imported as `ext`) and return what it prints as JSON."""
    driver = tmp_path / "driver.mjs"
    driver.write_text(f"import * as ext from {json.dumps(EXT.as_uri())};\n{body}\n")
    out = subprocess.run(["node", "--no-warnings", str(driver)], capture_output=True, text=True, check=True)
    return json.loads(out.stdout)


def test_resolve_write_path_as_pi_would(tmp_path):
    # Pi's own path forms; the rule itself: test_the_shared_path_rule
    work, home = tmp_path / "work", tmp_path / "home"
    work.mkdir()
    home.mkdir()
    (work / "link").symlink_to(home)
    (work / "dangling").symlink_to(home / "not-yet")  # a write would create the target
    (work / "loop").symlink_to(work / "loop")
    w = str(work.resolve())
    got = _node(tmp_path, f"""
const w = {json.dumps(w)};
console.log(JSON.stringify({{
  at: ext.resolveWritePath("@" + w + "/a.py", "/"),
  url: ext.resolveWritePath("file://" + w + "/a.py", "/"),
  link: ext.resolveWritePath("link/planted", w),
  tilde: ext.resolveWritePath("~/x", w),
  dangling: ext.resolveWritePath("dangling", w),
  loop: ext.resolveWritePath("loop/x", w),
}}));""")
    home_r = str(home.resolve())
    assert got["at"] == got["url"] == f"{w}/a.py"
    assert got["link"] == f"{home_r}/planted"  # the symlink is followed, as the write would
    assert got["tilde"].endswith("/x") and not got["tilde"].startswith(w)
    assert got["dangling"] == f"{home_r}/not-yet"  # followed, though its target doesn't exist
    assert got["loop"] is None


def test_inside_roots():
    got = subprocess.run(["node", "--no-warnings", "--input-type=module", "-e", f"""
import * as ext from {json.dumps(EXT.as_uri())};
const r = ["/work", "/tmp"];
console.log(JSON.stringify([ext.insideRoots("/work", r), ext.insideRoots("/work/a", r), ext.insideRoots("/tmp/x", r),
  ext.insideRoots("/workx/a", r), ext.insideRoots("/home/agent/.pi/agent/SYSTEM.md", r)]));"""],
                         capture_output=True, text=True, check=True)
    assert json.loads(got.stdout) == [True, True, True, False, False]


def test_every_tool_is_blocked_without_the_inventory(tmp_path):
    # no /etc/glove/enforcer/{tools,write-roots}.json on the host: every tool is blocked, read included
    got = _node(tmp_path, """
const handlers = [];
await ext.default({ on: (ev, fn) => { if (ev === "tool_call") handlers.push(fn); } });
const call = (toolName, input) => handlers.map((h) => h({ toolName, input }, { cwd: "/work" })).find((r) => r);
console.log(JSON.stringify({ write: call("write", { path: "/work/a", content: "x" }) ?? null,
                             read: call("read", { path: "/home/agent/x" }) ?? null }));""")
    for v in got.values():
        assert v["block"] is True and "inventory is missing" in v["reason"]


def test_tools_are_classified_by_the_inventory(tmp_path):
    work = tmp_path.resolve()
    inv = tmp_path / "tools.json"
    inv.write_text(json.dumps({c: list(get_profile("pi").tools.get(c, ())) for c in ("shell", "file_write", "allow")}))
    got = _node(tmp_path, f"""
const h = ext.toolCallHandler(["nono", "wrap", "--"], [{json.dumps(str(work))}], ext.loadTools({json.dumps(str(inv))}));
const call = (toolName, input) => {{ const r = h({{ toolName, input }}, {{ cwd: {json.dumps(str(work))} }});
  return {{ r: r ?? null, input }}; }};
console.log(JSON.stringify({{
  bash: call("bash", {{ command: "ls" }}),
  write: call("write", {{ path: "a.py", content: "x" }}),
  write_out: call("write", {{ path: "/etc/x", content: "x" }}),
  read: call("read", {{ path: "/etc/passwd" }}),
  unknown: call("mcp", {{ server: "x" }}),
  renamed: call("bash2", {{ command: "ls" }}),
}}));""")
    assert got["bash"]["r"] is None and got["bash"]["input"]["command"] == "nono wrap -- bash -c 'ls'"
    assert got["write"]["r"] is None and got["write"]["input"]["path"] == f"{work}/a.py"
    assert got["write_out"]["r"]["block"] and got["read"]["r"] is None
    for k in ("unknown", "renamed"):  # a tool glove hasn't classed: blocked, its input untouched
        assert got[k]["r"]["block"] and "not in this session's tool inventory" in got[k]["r"]["reason"]
    assert got["renamed"]["input"]["command"] == "ls"


def test_load_tools(tmp_path):
    good = {"shell": ["bash"], "file_write": [], "allow": ["read"]}
    bad = ["not json", "[1]", json.dumps({"shell": ["bash"], "file_write": []}),
           json.dumps({"shell": "bash", "file_write": [], "allow": []}),
           json.dumps({"shell": [1], "file_write": [], "allow": []})]
    paths = []
    for i, text in enumerate([json.dumps(good), *bad]):
        (tmp_path / f"t{i}.json").write_text(text)
        paths.append(str(tmp_path / f"t{i}.json"))
    got = _node(tmp_path, f"""
const r = {json.dumps([*paths, str(tmp_path / "missing.json")])}.map((p) => ext.loadTools(p));
console.log(JSON.stringify(r.map((t) => t && Object.fromEntries(Object.entries(t).map(([c, s]) => [c, [...s]])))));""")
    assert got[0] == good
    assert got[1:] == [None] * (len(bad) + 1)  # each malformed one, and a missing file


def test_the_shared_path_rule(tmp_path):
    work, cases = path_rule_cases(tmp_path / "t")
    got = _node(tmp_path, f"""
const w = {json.dumps(work)};
console.log(JSON.stringify({json.dumps([p for p, _ in cases])}.map((p) => {{
  const real = ext.resolveWritePath(p, w);
  return real !== null && ext.insideRoots(real, [w]) ? real : null;
}})));""")
    assert dict(zip([p for p, _ in cases], got, strict=True)) == dict(cases)
