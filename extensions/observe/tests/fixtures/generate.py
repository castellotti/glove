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
                          layout (-work/<uuid>.jsonl + subagents/); its own
                          WebFetch flows through `proxy` (Pi's fetch_url, as
                          Vibe's, through `webfetch-mcp` and `webfetch-egress`)
  llm-auth                glove injects the provider key: two model calls,
                          each an `llm` flow (harness → the llm-auth sidecar)
                          and the `llm-upstream` flow it causes (client llm,
                          SNI api.anthropic.com, scope cloud)
  llm-auth-oauth          the same on Claude Code with `auth: oauth`: llm-auth
                          serves TLS by the provider's name, so the `llm` hop's
                          dest.host is api.anthropic.com (at the sidecar's port)
  github                  the gh/git relay: `github-egress` flows (client github,
                          tool gh) to api.github.com and github.com; Pi's bash
                          calls in the transcript
  ssh                     hosts build (192.168.1.20) and db (db.lan): one
                          allowed `ssh-build` flow (scope lan) and one
                          `builtin:lan-only` refusal (db.lan resolved public)
  downloads               Vibe with `webfetch: {downloads: work}`: each MCP hop
                          (`webfetch-mcp`, `webdownload-mcp`) and the egress
                          flow behind it; Vibe's transcript layout before
                          2.26 (session_<ts>_<id>/messages.jsonl + meta.json;
                          2.26 writes a journal under unified/ instead)

Sessions are planned with `glove plan` (session.json, grants, registry rows),
each flow is the gate's own record (its ForwardSpec built from the service's
session.json entry), written by the collector, which also writes status.json.
Flow times are offsets from T0: a hop's flow spans the egress flow it caused.
Transcripts are hand-written in each harness's layout; their tool outputs are
illustrative. Timestamps, ULIDs and machine paths are normalised so the
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
from dataclasses import dataclass
from pathlib import Path
from typing import NamedTuple

from extensions.gate.netgate import guard

REPO = Path(__file__).resolve().parents[4]
OUT = REPO / "tests" / "fixtures" / "netobs-v3"
T0 = "2026-10-01T12:00:00.000Z"
LLM = '{provider: llama.cpp, location: host, endpoint: "127.0.0.1:8080", model: test-model}'
TEMPLATE = {"pi": "pi-search", "vibe": "vibe-search", "claude-code": "claude-code"}
CC_SESSION = "7c1d2e3f-0000-4000-8000-0f1a2b3c4d5e"


class Flow(NamedTuple):
    """One closed flow. `dest` is the CONNECT target of an http-proxy gate, or
    the SNI a tcp gate peeks (None: no TLS, so the configured upstream). Times
    are seconds after T0: a hop's inner flow (the sidecar's own egress) opens
    after and closes before the harness's flow through it."""

    service: str
    dest: str | None
    up: int
    down: int
    opened: float
    closed: float
    rule: str | None = None  # the blocking rule; the verdict is the scenario's, not the gate's


@dataclass(frozen=True)
class Scenario:
    extra: str  # extensions beside llm, direct and webfetch
    harness: str = "pi"
    llm: str = LLM
    webfetch: str = "{}"
    # Pi's fetch_url: the harness's MCP hop and the fetcher's egress flow behind it
    flows: tuple[Flow, ...] = (Flow("webfetch-egress", "en.wikipedia.org:443", 512, 40960, .6, .9),
                               Flow("webfetch-mcp", None, 300, 9000, .5, 1),
                               Flow("webfetch-egress", "169.254.169.254:443", 48, 120, 2, 2, guard.GUARD_RULE))
    bash: tuple[tuple[str, str, bool], ...] = ()  # Pi's bash calls: (command, output, is_error)
    files: tuple[tuple[str, str], ...] = ()  # session-dir files `glove plan` checks (not part of ~/.glove)


def _model_calls(sni: str | None, up: int, down: int) -> tuple[Flow, ...]:
    """Two model calls through llm-auth: the `llm-upstream` call each harness `llm` flow causes."""
    out: list[Flow] = []
    for k in (10, 20):
        out += [Flow("llm-upstream", "api.anthropic.com", 1400, 5200, k + .1, k + 3),
                Flow("llm", sni, up, down, k, k + 3.1)]
    return tuple(out)


OBSERVE = "  observe: {}\n"
AUTH_LLM = "{provider: anthropic, location: internet, model: claude-test, api_key: keychain:fixture-llm"
SCENARIOS = {
    "observe-only": Scenario(OBSERVE),
    "observe-filter": Scenario(OBSERVE + "  filter: {}\n", flows=(
        *Scenario.flows[:2], Flow("webfetch-egress", "ads.example.com:443", 48, 120, 2, 2, "r_fixture_1"))),
    "observe-no-transcripts": Scenario("  observe: {transcripts: false}\n"),
    "filter-revoked": Scenario(OBSERVE + "  filter: {}\n"),  # then filter is removed
    "orphaned": Scenario(OBSERVE),  # then the session dir is deleted
    "not-observable": Scenario(""),
    "claude-code": Scenario(OBSERVE, harness="claude-code", llm=(
        '{provider: anthropic-compatible, location: host, endpoint: "127.0.0.1:8080", model: claude-test}'),
        flows=(Flow("proxy", "en.wikipedia.org:443", 512, 40960, .5, 1),
               Flow("proxy", "169.254.169.254:443", 48, 120, 2, 2, guard.GUARD_RULE))),
    # the harness's `llm` hop is plain HTTP to llm-auth (dest: the sidecar);
    # `llm-upstream` carries llm-auth's TLS to the provider (dest: its SNI)
    "llm-auth": Scenario(OBSERVE, llm=AUTH_LLM + "}", flows=_model_calls(None, 900, 2400)),
    # oauth (Claude Code only): llm-auth serves TLS by the provider's name, so
    # the harness's hop shows the provider's SNI (at the sidecar's port)
    "llm-auth-oauth": Scenario(OBSERVE, harness="claude-code", llm=AUTH_LLM + ", auth: oauth}",
                               flows=_model_calls("api.anthropic.com", 1500, 5300)),
    "github": Scenario(
        "  github: {token: keychain:fixture-gh}\n" + OBSERVE,
        flows=(Flow("github-egress", "api.github.com:443", 2100, 8400, 1, 2),
               Flow("github-egress", "github.com:443", 3300, 182000, 3, 5)),
        bash=(("gh pr list --repo octo-org/widgets", "12\tFix the widget\tfix-widget\tOPEN\n", False),
              ("git clone https://github.com/octo-org/widgets", "Cloning into 'widgets'...\n", False))),
    # db.lan resolved to a public address: the gate never dials it (the refused
    # ssh's text is a live refusal's, the gate's address standing in)
    "ssh": Scenario(
        "  ssh:\n    key: keychain:fixture-ssh\n    known_hosts: local/known_hosts\n    hosts:\n"
        '      - {name: build, to: "192.168.1.20:22", user: ci}\n'
        '      - {name: db, to: "db.lan:22", user: ops}\n' + OBSERVE,
        flows=(Flow("ssh-build", None, 3100, 4200, 1, 4), Flow("ssh-db", None, 0, 0, 5, 5, guard.LAN_ONLY_RULE)),
        bash=(("ssh build uptime", " 12:00:00 up 3 days,  2:14,  0 users,  load average: 0.08, 0.03, 0.01\n", False),
              ("ssh db hostname", "Connection closed by 172.20.0.5 port 22\n", True)),
        files=(("local/known_hosts",
                "192.168.1.20 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureFixtureFixtureFixtureFixtureFixture01\n"
                "db.lan ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureFixtureFixtureFixtureFixtureFixture02\n"),)),
    "downloads": Scenario(
        OBSERVE, harness="vibe", webfetch="{downloads: work}",
        flows=(Flow("webfetch-egress", "example.com:443", 600, 1300, 1.1, 2),
               Flow("webfetch-mcp", None, 700, 900, 1, 2.1),
               Flow("webdownload-egress", "releases.example.org:443", 800, 10485760, 3.1, 9),
               Flow("webdownload-mcp", None, 800, 600, 3, 9.1))),
}


def _session_file(sc: Scenario, extra: str) -> str:
    return (f"glove: 3\ntemplate: {TEMPLATE[sc.harness]}\nharness: {sc.harness}\nextensions:\n"
            f"  llm: {sc.llm}\n  direct: {{}}\n  webfetch: {sc.webfetch}\n{extra}")


def _net(net: Path, sc: Scenario, control: Path | None) -> None:
    """flows.ndjson and status.json as a running session's gates and collector
    write them: each flow is built by the gate's own classes (`ForwardSpec` from
    the service's session.json entry, `_Flow`, the record builder: scope,
    dest.ip and resolution are the gate's) and ingested by the collector.
    Claude Code's own WebFetch goes through the `proxy` endpoint."""
    from datetime import datetime

    from extensions.gate.netgate.__main__ import _parse_upstream
    from extensions.gate.netgate.collector import Collector
    from extensions.gate.netgate.forward import Forwarder, ForwardSpec, _Flow

    t0 = datetime.fromisoformat(T0).timestamp()
    facts = json.loads((net / "session.json").read_text())
    services = {s["service"]: s for s in facts["services"]}
    c = Collector(net, str(net / "unused.sock"), rules_path=(control / "rules.json") if control else None)
    for n, f in enumerate(sc.flows, 1):
        s = services[f.service]
        host, port = _parse_upstream(s["upstream"], s["mode"])
        spec = ForwardSpec(service=f.service, listen_port=int(s["listen"].rpartition(":")[2]), upstream_host=host,
                           upstream_port=port, env=facts["env"], session=facts["session"], tool=s["tool"],
                           scope=s["scope"] or "local", resolve=facts["resolve"], mode=s["mode"],
                           route_kind=s["route"]["kind"], client=s["client"])
        gate = Forwarder(spec, sink=None)
        gate.run_id = f"g_{f.service}"  # one run per gate, named so the fixture is stable
        flow = _Flow(s["client"], spec)
        flow.id, flow.t_open, flow.up, flow.down = f"f_{n}", t0 + f.opened, f.up, f.down
        if spec.mode == "http-proxy":
            flow.proto = "http-connect"
            host, _, p = f.dest.rpartition(":")
            spec.classify_proxy_dest(flow, host, int(p))
        elif f.dest:
            flow.host = f.dest
            flow.ip, flow.resolution = spec.display_ip(f.dest)
        flow.verdict, flow.rule, flow.close_reason = ("block", f.rule, "blocked") if f.rule else ("allow", None, "eof")
        c.ingest(json.dumps(gate._record(flow, "close", t0 + f.closed)).encode())
    c.write_status("running")


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


def _pi_transcript(root: Path, bash: tuple) -> None:
    """Pi's layout under sessions/: --work--/<ts>_<id>.jsonl, a message per line."""
    t = root / "--work--"
    t.mkdir()
    lines = [{"type": "session", "id": "0f1a2b3c", "timestamp": T0, "cwd": "/work"},
             {"type": "message", "timestamp": T0,
              "message": {"role": "user", "content": [{"type": "text", "text": "hello"}]}}]
    for i, (command, output, is_error) in enumerate(bash, 1):
        lines += [{"type": "message", "timestamp": T0, "message": {"role": "assistant", "content": [
                      {"type": "toolCall", "id": f"call_{i}", "name": "bash", "arguments": {"command": command}}]}},
                  {"type": "message", "timestamp": T0, "message": {
                      "role": "toolResult", "toolCallId": f"call_{i}", "toolName": "bash",
                      "content": [{"type": "text", "text": output}], "isError": is_error}}]
    (t / "20261001_0f1a2b3c.jsonl").write_text("".join(json.dumps(x) + "\n" for x in lines))


def _vibe_transcript(root: Path, sid: str) -> None:
    """Vibe's layout under logs/session/ before 2.26 (copied from a 2.x
    session): session_<ts>_<id>/messages.jsonl (one message per line, MCP
    tools named <server>_<tool>) beside its meta.json."""
    t = root / "session_20261001_120000_0f1a2b3c"
    t.mkdir()
    calls = [({"url": "https://example.com"}, "webfetch", "fetch_url",
              "Example Domain\n\n[fetched: https://example.com | text/html | via egress]"),
             ({"url": "https://releases.example.org/data.tar.gz"}, "webdownload", "web_download",
              "saved: /work/downloads/data.tar.gz\nbytes: 10485760\nsha256: " + "ab" * 32
              + "\ncontent_type: application/gzip\nfinal_url: https://releases.example.org/data.tar.gz")]
    lines: list[dict] = [{"role": "user", "content": "fetch example.com, then download the data tarball",
                          "message_id": "m-1"}]
    for i, (args, server, tool, result) in enumerate(calls, 1):
        name = f"{server}_{tool}"
        out = {"ok": True, "server": f"http://glove-{sid}-{server}-mcp:8000/mcp", "tool": tool, "text": None,
               "structured": {"result": result}}
        lines += [{"role": "assistant", "content": "", "message_id": f"a-{i}", "tool_calls": [
                      {"id": f"call_{i}", "index": 0, "type": "function",
                       "function": {"name": name, "arguments": json.dumps(args)}}]},
                  {"role": "tool", "name": name, "tool_call_id": f"call_{i}", "message_id": f"t-{i}",
                   "content": "\n".join(f"{k}: {v}" for k, v in out.items()), "tool_result": {"output": out}}]
    (t / "messages.jsonl").write_text("".join(json.dumps(x) + "\n" for x in lines))
    (t / "meta.json").write_text(json.dumps({"session_id": "0f1a2b3c", "start_time": T0, "end_time": T0,
                                             "environment": {"working_directory": "/work"}}, indent=2) + "\n")


_ISO = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z")
_ULID = re.compile(r"r_[0-9A-HJKMNP-TV-Z]{26}")


def _normalise(home: Path, tmp: str) -> None:
    """Stable timestamps, rule ids, image tags and paths in every JSON file."""
    for f in sorted(home.rglob("*")):
        if not f.is_file() or f.suffix not in (".json", ".ndjson", ".jsonl"):
            continue
        text = f.read_text()
        if f.name != "flows.ndjson":  # flow times are the scenario's own, offsets from T0
            text = _ISO.sub(T0, text)
        text = _ULID.sub("r_fixture_1", text)
        # idempotent (this runs twice): `\b` never matches the `f` of `fixture`
        text = re.sub(r"glove/ext-gate-netgate:[0-9a-f]+\b", "glove/ext-gate-netgate:fixture", text)
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
        for name, sc in SCENARIOS.items():
            home = out / name / "home"
            os.environ["GLOVE_HOME"] = str(home)
            d = Path(tmp) / "sessions" / name
            (d / "work").mkdir(parents=True)
            (d / "glove-session.yml").write_text(_session_file(sc, sc.extra))
            for rel, text in sc.files:
                (d / rel).parent.mkdir(parents=True, exist_ok=True)
                (d / rel).write_text(text)
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
                (d / "glove-session.yml").write_text(_session_file(sc, OBSERVE))
                assert runner.invoke(app, ["plan"]).exit_code == 0
                assert not ctl.exists()
            _normalise(home, tmp)  # rules.json first: status.json records its real sha256
            if (obs / "net").is_dir():
                _net(obs / "net", sc, ctl if ctl.is_dir() else None)
            tx = obs / "transcripts"
            if tx.is_dir() and sc.harness == "claude-code":
                _cc_transcript(tx)
            elif tx.is_dir() and sc.harness == "vibe":
                _vibe_transcript(tx, sid)
            elif tx.is_dir():
                _pi_transcript(tx, sc.bash)
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
    generate(Path(sys.argv[1]) if len(sys.argv) > 1 else OUT)
    print(f"wrote {sys.argv[1] if len(sys.argv) > 1 else OUT}")
