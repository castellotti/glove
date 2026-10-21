"""`playwright` host mode: pinned MCP, per-session profile and ports, refusals, wiring."""

from __future__ import annotations

import json
import subprocess
import sys
from types import SimpleNamespace

import pytest
import yaml
from helpers import make_cfg, make_session

from glove import sessiondir as sdm
from glove.extensions import IN_TREE_DIR, ExtensionError, hook_context, launch_env, load_module, materialize
from glove.extsession import run_teardown
from glove.plan import build_session_plan

HOOKS = load_module(IN_TREE_DIR / "playwright" / "hooks.py", "playwright")


def _plan(tmp_path, harness="pi", extra=None, **settings):
    work = tmp_path / "work"
    work.mkdir(parents=True, exist_ok=True)
    cfg = make_cfg(harness=harness, name="s", workdir=str(work),
                   extensions={"playwright": {"mode": "host", **settings}, **(extra or {})})
    return build_session_plan(cfg, home_dir=str(tmp_path / "h"), state_dir=str(tmp_path / "ext"))


def _services(plan):
    comp = plan.composition
    ctx = hook_context(comp, next(a for a in comp.active if a.name == "playwright"))
    return {s.name: s for s in HOOKS.host_services(ctx, ctx.slot["browser"]["host_ports"])}


def _ports(plan):
    hs = _services(plan)
    return hs["mcp"].port, hs["chrome"].port


def _launched(tmp_path, ports='{"mcp": 40001, "cdp": 40002}'):
    """A session dir host mode launched in (its recorded ports)."""
    sd = sdm.SessionDir(tmp_path)
    (sd.ext / "playwright").mkdir(parents=True, exist_ok=True)
    (sd.ext / "playwright" / "host-ports.json").write_text(ports + "\n")
    return sd


def test_host_services_are_pinned_and_per_session(tmp_path):
    plan = _plan(tmp_path)
    hs = _services(plan)
    assert set(hs) == {"chrome", "mcp"}
    mcp_port, cdp_port = hs["mcp"].port, hs["chrome"].port
    assert mcp_port != cdp_port and not {mcp_port, cdp_port} & {8931, 9222}  # free ports, per session
    mcp = hs["mcp"].command
    assert "npx -y playwright-core@1.63.0 mcp " in mcp
    assert "@latest" not in mcp and "@playwright/mcp" not in mcp
    assert f"--port {mcp_port} --allowed-hosts glove-s-browser:{mcp_port} " in mcp
    assert f"--cdp-endpoint http://127.0.0.1:{cdp_port} " in mcp
    assert f"--output-dir {tmp_path / 'ext' / 'playwright' / 'output'}" in mcp
    chrome = hs["chrome"]
    assert f"--remote-debugging-port={cdp_port} " in chrome.command
    assert f"--user-data-dir={tmp_path / 'ext' / 'playwright' / 'host-profile'}" in chrome.command
    assert chrome.keep is False
    assert "images" not in plan.derived_dockerfile if plan.derived_dockerfile else True


def test_ports_are_recorded_and_reused(tmp_path):
    plan = _plan(tmp_path)
    first = _ports(plan)
    materialize(plan.composition)
    saved = json.loads((tmp_path / "ext" / "playwright" / "host-ports.json").read_text())
    assert (saved["mcp"], saved["cdp"]) == first
    plan2 = _plan(tmp_path)
    assert _ports(plan2) == first  # a kept Chrome is found again on the next launch


def test_ports_can_be_pinned(tmp_path):
    plan = _plan(tmp_path, port=8931, cdp_port=9222)
    assert _ports(plan) == (8931, 9222)


def test_keep_browser_opt_in(tmp_path):
    plan = _plan(tmp_path, keep_browser=True)
    hs = _services(plan)
    assert hs["chrome"].keep is True and hs["mcp"].keep is False


@pytest.fixture
def tmux(monkeypatch):
    """The services module's tmux calls (`calls`); a port answers once a command naming it
    started (`up`), and `kill-session` succeeds for a session in `running`."""
    hs = sys.modules["glove_ext.playwright.host.services"]
    t = SimpleNamespace(calls=[], up=[], running=set())

    def run(argv, **_):
        t.calls.append(argv)
        if argv[1] == "new-session":
            t.up.append(argv[-1])
        return subprocess.CompletedProcess(argv, 0 if argv[1] != "kill-session" or argv[-1] in t.running else 1)

    monkeypatch.setattr(hs.shutil, "which", lambda tool: f"/bin/{tool}")
    monkeypatch.setattr(hs.subprocess, "run", run)
    monkeypatch.setattr(hs, "_port_open", lambda port: any(f"{port} " in c for c in t.up))
    return t


def test_launch_env_starts_them_in_tmux(tmp_path, tmux):
    plan = _plan(tmp_path)
    materialize(plan.composition)
    assert launch_env(plan.composition) == {}
    started = {c[4]: c[5] for c in tmux.calls if c[1] == "new-session"}
    assert set(started) == {"glove-s-host-playwright-chrome", "glove-s-host-playwright-mcp"}
    assert started["glove-s-host-playwright-mcp"] == _services(plan)["mcp"].command
    tmux.calls.clear()
    assert launch_env(plan.composition) == {}  # already answering: reused, never restarted
    assert not tmux.calls


def test_sidecar_modes_start_nothing_on_the_host(tmp_path, tmux):
    cfg = make_cfg(name="s", workdir=str(tmp_path), extensions={"direct": {}, "playwright": {}})
    plan = build_session_plan(cfg, home_dir=str(tmp_path / "h"), state_dir=str(tmp_path / "ext"))
    launch_env(plan.composition)
    assert not tmux.calls


@pytest.mark.parametrize(("keep", "killed"), [(False, ["chrome", "mcp"]), (True, ["mcp"])])
def test_glove_down_stops_them_unless_the_browser_is_kept(tmp_path, tmux, keep, killed, capsys):
    sd = sdm.SessionDir(tmp_path)
    tmux.running = {"glove-s-0a0b0c-host-playwright-chrome", "glove-s-0a0b0c-host-playwright-mcp"}
    run_teardown(sd, "s-0a0b0c", "docker", {"playwright": {"mode": "host", "keep_browser": True}})
    assert not tmux.calls and not capsys.readouterr().out  # host mode never launched: nothing to stop
    _launched(tmp_path)
    run_teardown(sd, "s-0a0b0c", "docker", {"playwright": {"mode": "host", "keep_browser": keep}, "direct": {}})
    assert [c[-1] for c in tmux.calls] == [f"glove-s-0a0b0c-host-playwright-{n}" for n in killed]
    assert capsys.readouterr().out.count(": stopped") == len(killed)
    # a session switched to a sidecar mode since: what host mode left running still stops
    run_teardown(sd, "s-0a0b0c", "docker", {"playwright": {"mode": "headless"}})
    assert capsys.readouterr().out.count(": stopped") == 2
    tmux.running = set()
    run_teardown(sd, "s-0a0b0c", "docker", {"playwright": {}})
    assert ": stopped" not in capsys.readouterr().out  # nothing was running: says nothing


def test_glove_down_stops_a_host_service_started_before_round_16(tmp_path, monkeypatch, capsys):
    hs = sys.modules["glove_ext.playwright.host.services"]
    sd = _launched(tmp_path)
    old = sd.state / "host-logs"  # core's, without tmux
    old.mkdir()
    (old / "playwright-chrome.pid").write_text("4242")
    killed = []
    monkeypatch.setattr(hs.shutil, "which", lambda tool: None)
    monkeypatch.setattr(hs.os, "getpgid", lambda pid: pid)
    monkeypatch.setattr(hs.os, "killpg", lambda pgid, sig: killed.append(pgid))
    run_teardown(sd, "s-0a0b0c", "docker", {"playwright": {"mode": "host"}})
    assert killed == [4242] and not (old / "playwright-chrome.pid").exists()
    assert "playwright chrome: stopped" in capsys.readouterr().out


def test_a_failing_teardown_is_a_warning(tmp_path, monkeypatch):
    monkeypatch.setattr(sys.modules["glove_ext.playwright.host.services"], "stop", lambda *a: 1 / 0)
    sd = _launched(tmp_path, "{}")
    warnings = run_teardown(sd, "s-0a0b0c", "docker", {"playwright": {"mode": "host"}})
    assert warnings == ["extension 'playwright': teardown: division by zero"]

    def broken():
        raise ExtensionError("bad manifest")

    monkeypatch.setattr("glove.extsession.discover", broken)
    assert run_teardown(sd, "s", "docker", {}) == ["teardown hooks skipped: bad manifest"]


def test_glove_plan_and_policy_show_what_runs_on_the_host(tmp_path):
    from typer.testing import CliRunner

    from glove.cli import app

    d = make_session(tmp_path / "s", "  playwright: {mode: host}\n")
    for cmd in ("plan", "policy"):
        out = " ".join(CliRunner().invoke(app, [cmd, str(d)]).output.split())  # as wrapped to any width
        assert "resolved (playwright): runs on the host (chrome) = " in out, out
        assert "runs on the host (mcp) = npx -y playwright-core@" in out


def test_glove_check_shows_what_runs_on_the_host(tmp_path):
    from glove.doctor import extension_checks

    plan = _plan(tmp_path)
    checks = {c.name: c for c in extension_checks({}, harness="pi", comp=plan.composition)}
    assert checks["playwright host: mcp"].status == "info"
    assert checks["playwright host: mcp"].detail == _services(plan)["mcp"].command


def test_harness_wiring(tmp_path):
    plan = _plan(tmp_path, tools=["browser_navigate", "browser_snapshot"])
    [pw] = [s for _, s in plan.composition.mcp if s["name"] == "playwright"]
    assert pw["url"] == "http://glove-s-browser:8931/mcp" and pw["tools"] == ["browser_navigate", "browser_snapshot"]
    assert not any(k.startswith("BROWSER_") for k in plan.environment)
    fwd = next(s for s in plan.network.sidecars if s.role == "browser")
    assert fwd.target == f"host.docker.internal:{_ports(plan)[0]}" and fwd.host_gateway
    assert "/opt/glove/ext/" not in " ".join(plan.command)
    assert not any(doc.get("services") for _, doc in plan.composition.fragments)  # no sidecar
    assert "REAL Chrome on the operator's own desktop" in dict(plan.composition.rendered_briefs())["playwright"]


def test_vibe_refused_without_ack(tmp_path):
    with pytest.raises(ExtensionError, match="browser_run_code_unsafe"):
        _plan(tmp_path, harness="vibe")
    plan = _plan(tmp_path / "ok", harness="vibe", i_accept_host_rce=True)
    pw = next(s for _, s in plan.composition.mcp if s["name"] == "playwright")
    assert pw["url"] == "http://glove-s-browser:8931/mcp" and "browser_run_code_unsafe" not in pw["tools"]


@pytest.mark.parametrize("egress", ["vpn", "tor"])
def test_host_mode_refused_behind_an_anonymising_egress(tmp_path, egress):
    settings = {"vpn": {"provider": "custom", "wireguard_key": "env:WG_KEY"}, "tor": {}}[egress]
    with pytest.raises(ExtensionError, match="bypasses the session's vpn/tor egress"):
        _plan(tmp_path, extra={egress: settings})
    _plan(tmp_path / "direct", extra={"direct": {}})  # no anonymity to lose


def test_every_mcp_harness_but_pi_needs_the_host_rce_ack():
    # the rule names harnesses (`when` has no "not pi"): a new one must join it,
    # unless, like Pi, a glove hook refuses every tool its inventory lacks
    from glove.harness import get_profile, known_harnesses

    rules = yaml.safe_load((IN_TREE_DIR / "playwright" / "extension.yml").read_text())["validate"]
    [rule] = [r["when"] for r in rules if "i_accept_host_rce" in r["when"]]
    want = [h for h in known_harnesses() if h != "pi" and get_profile(h).renders("mcp")]
    assert sorted(rule["harness"]) == want


def test_host_mode_never_allows_run_code(tmp_path):
    tools = ["browser_navigate", "browser_run_code_unsafe"]
    plan = _plan(tmp_path, tools=tools)
    [pw] = [s for _, s in plan.composition.mcp if s["name"] == "playwright"]
    assert pw["tools"] == ["browser_navigate"]
    assert "mcp__playwright__browser_run_code_unsafe" not in plan.policies["tools.json"]  # Pi's enforcer refuses it
    # in a sidecar mode it reaches only the sidecar
    headless = _plan(tmp_path / "h", extra={"direct": {}}, tools=tools, mode="headless")
    assert next(s for _, s in headless.composition.mcp if s["name"] == "playwright")["tools"] == tools

