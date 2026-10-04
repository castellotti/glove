"""Generate tests/fixtures/netobs-v3/ — the v3 grant states Layman renders
(Layman handoff §9), through glove's own code paths.

    uv run python extensions/observe/tests/fixtures/generate.py [out-dir]

One directory per scenario, each holding `home/`: a tree shaped like
~/.glove (registry.json, observe/<id>/, control/<id>/):

  observe-only            observe on, filter never granted (no control/<id>/)
  observe-filter          observe + filter: control/<id>/rules.json enforced
  observe-no-transcripts  observe {transcripts: false}: no transcripts/ dir
  filter-revoked          filter removed after a grant: control/<id>/ gone,
                          grants.filter.granted false (rules.revoked.json stays
                          in the session dir, which is not part of ~/.glove)
  orphaned                the session dir was deleted: registry row + export
  not-observable          a registry row only (grants null), no export
  claude-code             observe on a Claude Code session: its transcript
                          layout (-work/<uuid>.jsonl + subagents/); WebFetch
                          flows through `proxy` as Pi's do

Sessions are planned with `glove plan` (session.json, grants, registry rows),
flows come from the gate's own record builders and status.json from the
collector's writer. Timestamps, ULIDs and machine paths are normalised so the
output is stable; `test_netobs_v3_fixture.py` keeps the checked-in copy equal
to a fresh run.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[4]
OUT = REPO / "tests" / "fixtures" / "netobs-v3"
T0 = "2026-10-01T12:00:00.000Z"
SCENARIOS = {
    "observe-only": "  observe: {}\n",
    "observe-filter": "  observe: {}\n  filter: {}\n",
    "observe-no-transcripts": "  observe: {transcripts: false}\n",
    "filter-revoked": "  observe: {}\n  filter: {}\n",  # then filter is removed
    "orphaned": "  observe: {}\n",  # then the session dir is deleted
    "not-observable": "",
    "claude-code": "  observe: {}\n",
}
LLM = '{provider: llama.cpp, location: host, endpoint: "127.0.0.1:8080", model: test-model}'
CC_LLM = '{provider: anthropic-compatible, location: host, endpoint: "127.0.0.1:8080", model: claude-test}'
CC_SESSION = "7c1d2e3f-0000-4000-8000-0f1a2b3c4d5e"


def _session_file(extra: str, harness: str = "pi") -> str:
    llm, template = (CC_LLM, "claude-code") if harness == "claude-code" else (LLM, "pi-search")
    return (f"glove: 3\ntemplate: {template}\nharness: {harness}\nextensions:\n  llm: {llm}\n  direct: {{}}\n"
            f"  webfetch: {{}}\n{extra}")


def _flows(net: Path, sid: str, *, filtered: bool) -> None:
    """Two closed flows from the gate's own builder: one allowed, and one
    blocked by a rule (filter) or by the SSRF guard (observe only). Claude
    Code's own WebFetch goes through the same `proxy` endpoint as Pi's web_fetch."""
    from extensions.gate.netgate.records import flow_record

    blocked_rule = "r_fixture_1" if filtered else "builtin:ssrf-guard"
    recs = [
        flow_record(phase="close", flow_id="f_1", env=sid, session=sid, t=1.0, t_open=0.5, t_close=1.0,
                    service="proxy", tool="web_fetch", client="harness", proto="http-connect",
                    dest_host="en.wikipedia.org", dest_port=443, dest_ip=None, resolution="unavailable",
                    scope="direct", route_kind="direct", route_upstream=f"http://glove-{sid}-direct-proxy:8888",
                    up=512, down=40960, verdict="allow", rule=None, close_reason="eof", request=None, run="g_1"),
        flow_record(phase="close", flow_id="f_2", env=sid, session=sid, t=2.0, t_open=2.0, t_close=2.0,
                    service="proxy", tool="web_fetch", client="harness", proto="http-connect",
                    dest_host="ads.example.com" if filtered else "169.254.169.254", dest_port=443, dest_ip=None,
                    resolution="unavailable" if filtered else "literal", scope="direct" if filtered else "local",
                    route_kind="direct", route_upstream=f"http://glove-{sid}-direct-proxy:8888", up=48, down=120,
                    verdict="block", rule=blocked_rule, close_reason="blocked", request=None, run="g_1"),
    ]
    (net / "flows.ndjson").write_text("".join(json.dumps(r, separators=(",", ":")) + "\n" for r in recs))


def _cc_transcript(root: Path) -> None:
    """Claude Code's layout under projects/: -work/<session uuid>.jsonl and its
    subagents' transcripts in -work/<session uuid>/subagents/."""
    t = root / "-work"
    (t / CC_SESSION / "subagents").mkdir(parents=True)
    base = {"sessionId": CC_SESSION, "cwd": "/work", "timestamp": T0, "version": "2.1.288"}
    lines = [
        {**base, "type": "user", "uuid": "u-1", "parentUuid": None,
         "message": {"role": "user", "content": "hello"}},
        {**base, "type": "assistant", "uuid": "a-1", "parentUuid": "u-1",
         "message": {"role": "assistant", "model": "claude-test", "content": [
             {"type": "tool_use", "id": "toolu_1", "name": "WebFetch",
              "input": {"url": "https://en.wikipedia.org/", "prompt": "summarise"}}]}},
    ]
    (t / f"{CC_SESSION}.jsonl").write_text("".join(json.dumps(x) + "\n" for x in lines))
    sub = {**base, "type": "user", "uuid": "s-1", "parentUuid": None, "isSidechain": True, "agentId": "a1b2c3",
           "message": {"role": "user", "content": "look it up"}}
    (t / CC_SESSION / "subagents" / "agent-a1b2c3.jsonl").write_text(json.dumps(sub) + "\n")


def _status(net: Path, control: Path | None) -> None:
    from extensions.gate.netgate.collector import Collector

    c = Collector(net, str(net / "unused.sock"), rules_path=(control / "rules.json") if control else None)
    c.write_status("running")


_ISO = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z")
_ULID = re.compile(r"r_[0-9A-HJKMNP-TV-Z]{26}")


def _normalise(home: Path, tmp: str) -> None:
    """Stable timestamps, rule ids, image tags and paths in every JSON file."""
    for f in sorted(home.rglob("*")):
        if not f.is_file() or f.suffix not in (".json", ".ndjson", ".jsonl"):
            continue
        text = f.read_text()
        text = _ISO.sub(T0, text)
        text = _ULID.sub("r_fixture_1", text)
        text = re.sub(r"glove/ext-gate-netgate:[0-9a-f]+", "glove/ext-gate-netgate:fixture", text)
        for root in sorted({tmp.rstrip("/"), os.path.realpath(tmp)}, key=len, reverse=True):
            text = text.replace(root + "/sessions", "/home/user/work")
        f.write_text(text)


def generate(out: Path) -> None:
    from typer.testing import CliRunner

    from glove import registry
    from glove.cli import app

    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    tmp = tempfile.mkdtemp(prefix="netobs-v3-")
    old_home = os.environ.get("GLOVE_HOME")
    old_cwd = os.getcwd()
    try:
        for name, extra in SCENARIOS.items():
            home = out / name / "home"
            os.environ["GLOVE_HOME"] = str(home)
            d = Path(tmp) / "sessions" / name
            (d / "work").mkdir(parents=True)
            harness = "claude-code" if name == "claude-code" else "pi"
            (d / "glove-session.yml").write_text(_session_file(extra, harness))
            # a fixed id, so the fixture is stable (`glove plan` keeps an existing one)
            (d / ".glove").mkdir(mode=0o700)
            sid = f"{name}-0f1a2b"
            (d / ".glove" / "id").write_text(sid + "\n")
            runner = CliRunner()
            os.chdir(d)
            result = runner.invoke(app, ["plan"])
            assert result.exit_code == 0, result.output
            obs, ctl = registry.observe_dir(sid), registry.control_dir(sid)
            if name == "observe-filter":
                assert runner.invoke(app, ["filter", "block", "ads.example.com", "--note", "fixture"]).exit_code == 0
            if name == "filter-revoked":
                assert runner.invoke(app, ["filter", "block", "ads.example.com"]).exit_code == 0
                (d / "glove-session.yml").write_text(_session_file("  observe: {}\n"))
                assert runner.invoke(app, ["plan"]).exit_code == 0
                assert not ctl.exists()
            _normalise(home, tmp)  # rules.json first: status.json records its real sha256
            if (obs / "net").is_dir():
                _flows(obs / "net", sid, filtered=name == "observe-filter")
                _status(obs / "net", ctl if ctl.is_dir() else None)
            if (obs / "transcripts").is_dir() and harness == "claude-code":
                _cc_transcript(obs / "transcripts")
            elif (obs / "transcripts").is_dir():
                t = obs / "transcripts" / "--work--"
                t.mkdir()
                (t / "20261001_0f1a2b3c.jsonl").write_text(
                    json.dumps({"type": "session", "id": "0f1a2b3c", "timestamp": T0, "cwd": "/work"}) + "\n"
                    + json.dumps({"type": "message", "timestamp": T0,
                                  "message": {"role": "user", "content": [{"type": "text", "text": "hello"}]}}) + "\n")
            if name == "orphaned":
                os.chdir(old_cwd)
                shutil.rmtree(d)
            for leftover in (home / "config.yml", home / "registry.json.lock"):
                leftover.unlink(missing_ok=True)
            _normalise(home, tmp)
    finally:
        os.chdir(old_cwd)
        if old_home is None:
            os.environ.pop("GLOVE_HOME", None)
        else:
            os.environ["GLOVE_HOME"] = old_home
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.path.insert(0, str(REPO))
    generate(Path(sys.argv[1]) if len(sys.argv) > 1 else OUT)
    print(f"wrote {sys.argv[1] if len(sys.argv) > 1 else OUT}")
