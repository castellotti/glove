"""Pi's enforcer extension (harnesses/pi/image/extensions/enforcer/index.ts) under
the host's node (type stripping): its file-tool write rule. Skipped without node."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

EXT = Path(__file__).resolve().parents[1] / "image" / "extensions" / "enforcer" / "index.ts"
pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="needs node")


def _node(tmp_path: Path, body: str) -> dict:
    """Run `body` (JS, with the extension imported as `ext`) and return what it prints as JSON."""
    driver = tmp_path / "driver.mjs"
    driver.write_text(f"import * as ext from {json.dumps(EXT.as_uri())};\n{body}\n")
    out = subprocess.run(["node", "--no-warnings", str(driver)], capture_output=True, text=True, check=True)
    return json.loads(out.stdout)


def test_resolve_write_path_as_pi_would(tmp_path):
    work, home = tmp_path / "work", tmp_path / "home"
    (work / "real").mkdir(parents=True)
    home.mkdir()
    (work / "link").symlink_to(home)
    (work / "alias").symlink_to(work / "real")
    (work / "dangling").symlink_to(home / "not-yet")  # a write would create the target
    (work / "loop").symlink_to(work / "loop")
    w = str(work.resolve())
    got = _node(tmp_path, f"""
const w = {json.dumps(w)};
console.log(JSON.stringify({{
  rel: ext.resolveWritePath("sub/a.py", w),
  at: ext.resolveWritePath("@" + w + "/a.py", "/"),
  url: ext.resolveWritePath("file://" + w + "/a.py", "/"),
  link: ext.resolveWritePath("link/planted", w),
  dotdot: ext.resolveWritePath("link/../x", w),
  alias: ext.resolveWritePath("alias/a.py", w),
  tilde: ext.resolveWritePath("~/x", w),
  odd: ext.resolveWritePath(w + "/a\\u00A0b", w),
  dangling: ext.resolveWritePath("dangling", w),
  loop: ext.resolveWritePath("loop/x", w),
  trailing: ext.resolveWritePath(w + "/a.py ", w),
}}));""")
    home_r = str(home.resolve())
    assert got["rel"] == f"{w}/sub/a.py"
    assert got["at"] == got["url"] == f"{w}/a.py"
    assert got["link"] == f"{home_r}/planted"  # the symlink is followed, as the write would
    assert got["dotdot"] == f"{tmp_path.resolve()!s}/x"  # `..` after the link: its target's parent
    assert got["alias"] == f"{w}/real/a.py"
    assert got["tilde"].endswith("/x") and not got["tilde"].startswith(w)
    assert got["odd"] is None  # a space Pi would normalize: refused
    assert got["dangling"] == f"{home_r}/not-yet"  # followed, though its target doesn't exist
    assert got["loop"] is None and got["trailing"] is None


def test_inside_roots():
    got = subprocess.run(["node", "--no-warnings", "--input-type=module", "-e", f"""
import * as ext from {json.dumps(EXT.as_uri())};
const r = ["/work", "/tmp"];
console.log(JSON.stringify([ext.insideRoots("/work", r), ext.insideRoots("/work/a", r), ext.insideRoots("/tmp/x", r),
  ext.insideRoots("/workx/a", r), ext.insideRoots("/home/agent/.pi/agent/SYSTEM.md", r)]));"""],
                         capture_output=True, text=True, check=True)
    assert json.loads(got.stdout) == [True, True, True, False, False]


def test_file_tools_fail_closed_without_the_write_roots(tmp_path):
    # no /etc/glove/enforcer/write-roots.json on the host: write/edit are blocked, other tools pass
    got = _node(tmp_path, """
const handlers = [];
await ext.default({ on: (ev, fn) => { if (ev === "tool_call") handlers.push(fn); } });
const call = (toolName, input) => handlers.map((h) => h({ toolName, input }, { cwd: "/work" })).find((r) => r);
console.log(JSON.stringify({ write: call("write", { path: "/work/a", content: "x" }) ?? null,
                             read: call("read", { path: "/home/agent/x" }) ?? null }));""")
    assert got["write"]["block"] is True and "fail closed" in got["write"]["reason"]
    assert got["read"] is None
