"""observe (host side): settings, the netgate per endpoint, the collector,
export roots, session.json, grants, transcripts and the CLI."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml
from helpers import make_cfg, make_session
from typer.testing import CliRunner

from extensions.gate.gatelib import classify_scope, collect_command
from glove.cli import app
from glove.config import AddDir
from glove.extensions import ExtensionError, materialize
from glove.hardening import HardeningError
from glove.plan import build_session_plan
from glove.runtimes.docker import DockerRuntime

runner = CliRunner()
SID = "ps"
PI_SEARCH = {"direct": {}, "search": {}, "webfetch": {}}


def plan_for(tmp_path, *, exts=None, observe=None, home=None, add_dirs=None, harness="pi"):
    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    extensions = {**(PI_SEARCH if exts is None else exts)}
    if observe is not False:
        extensions["observe"] = observe or {}
    cfg = make_cfg(harness=harness, workdir=str(work), name=SID, extensions=extensions, subnet="172.31.9.0/24")
    if add_dirs:
        cfg.add_dirs = add_dirs
    sdir = tmp_path / "sess" / ".glove"
    return build_session_plan(cfg, env_id=SID, home_dir=str(home or sdir / "home"), cwd=str(work), uid=501,
                              gid=20, state_dir=str(sdir / "ext"), session_dir=str(tmp_path / "sess"))


def render(tmp_path, *, runtime=None, overrides=frozenset(), **kw):
    plan = plan_for(tmp_path, **kw)
    text = (runtime or DockerRuntime()).render(plan, tmp_path / "sess" / ".glove", overrides=overrides).compose_yaml
    return plan, yaml.safe_load(text), text


def gates(doc: dict) -> dict:
    return {k: v for k, v in doc["services"].items() if "ext-gate-netgate" in str(v.get("image", ""))}


def flag(cmd: list[str], name: str) -> str | None:
    return cmd[cmd.index(name) + 1] if name in cmd else None


# --- settings -----------------------------------------------------------------------


@pytest.mark.parametrize(("observe", "match"), [
    ({"record": "everything"}, "must be one of"),
    ({"record_headers": True}, "needs observe.record: full"),
    ({"retain": "5s"}, "at least 60s"),
    ({"retain": "soon"}, "duration"),
    ({"resolver": "http://x:1"}, "unknown resolver scheme"),
    ({"resolver": "dns://gluetun:53", "resolve": "none"}, "pick one"),
    ({"exit_identity_url": "http://x"}, "https://"),
    ({"resolve": "host"}, "must be one of"),  # never the host resolver
    ({"enabled": True}, "unknown setting"),  # the v2 master switch is gone: presence enables
])
def test_settings_are_validated(tmp_path, observe, match):
    with pytest.raises(ExtensionError, match=match):
        plan_for(tmp_path, observe=observe)


def test_the_v2_top_level_observe_key_points_at_the_extension(tmp_path, monkeypatch):
    d = make_session(tmp_path / "wd", "observe: {enabled: true}\n")
    monkeypatch.chdir(d)
    out = runner.invoke(app, ["plan"])
    assert out.exit_code == 1 and "extensions: {observe: {}}" in out.output


@pytest.mark.parametrize(("host", "gw", "scope"), [
    ("host.docker.internal", True, "local"), ("searxng", False, "local"), ("10.0.0.5", False, "local"),
    ("api.example.com", False, "direct"), ("8.8.8.8", False, "direct"),
])
def test_classify_scope_by_shape(host, gw, scope):
    assert classify_scope(host, gw) == scope


# --- the forwarder slot: a netgate per endpoint ----------------------------------------


def test_every_endpoint_becomes_a_gate_dropin(tmp_path):
    plan, doc, _ = render(tmp_path)
    g = gates(doc)
    assert set(g) == {"glove-ps-llm", "glove-ps-search", "glove-ps-proxy", "glove-ps-searxng-egress",
                      "glove-ps-netgate"}
    assert not any(s.get("image") == plan.forwarder_image for s in doc["services"].values())
    proxy = g["glove-ps-proxy"]
    # same name, networks and port as the socat it replaces
    assert set(proxy["networks"]) == {"glove-ps-net", "glove-ps-egress"}
    assert proxy["networks"]["glove-ps-net"]["aliases"] == ["glove-ps-proxy-ingress"]
    cmd = proxy["command"]
    assert (flag(cmd, "--mode"), flag(cmd, "--upstream"), flag(cmd, "--route"), flag(cmd, "--listen")) == \
        ("http-proxy", "chain:http://glove-ps-direct-proxy:8888", "direct", "8888")
    assert flag(cmd, "--tool") == "web_fetch"
    llm = g["glove-ps-llm"]["command"]
    assert (flag(llm, "--mode"), flag(llm, "--upstream"), flag(llm, "--scope")) == \
        ("tcp", "tcp:host.docker.internal:8080", "local")
    assert g["glove-ps-llm"]["extra_hosts"] == ["host.docker.internal:host-gateway"]
    assert "glove-ps-hostgw" in g["glove-ps-llm"]["networks"]


def test_skip_keeps_an_endpoint_on_socat(tmp_path):
    plan, doc, _ = render(tmp_path, observe={"skip": ["llm"]})
    assert doc["services"]["glove-ps-llm"]["image"] == plan.forwarder_image
    assert "glove-ps-llm" not in gates(doc)


def test_searxng_reaches_egress_only_through_its_gate(tmp_path):
    _, doc, _ = render(tmp_path)
    sx = doc["services"]["glove-ps-searxng"]
    assert set(sx["networks"]) == {"glove-ps-searchnet"}  # off the egress network
    hop = gates(doc)["glove-ps-searxng-egress"]
    assert set(hop["networks"]) == {"glove-ps-searchnet", "glove-ps-egress"}  # never the harness net
    assert (flag(hop["command"], "--client"), flag(hop["command"], "--mode")) == ("searxng", "http-proxy")
    assert "--ingress-alias" not in hop["command"]
    # without observe there is no hop: SearXNG dials the egress proxy itself
    (tmp_path / "plain").mkdir()
    _, doc2, _ = render(tmp_path / "plain", observe=False)
    assert "glove-ps-searxng-egress" not in doc2["services"]
    assert set(doc2["services"]["glove-ps-searxng"]["networks"]) == {"glove-ps-egress", "glove-ps-searchnet"}


def test_searxng_settings_point_at_the_hop(tmp_path):
    plan = plan_for(tmp_path)
    materialize(plan.composition)
    doc = yaml.safe_load((tmp_path / "sess" / ".glove" / "ext" / "search" / "searxng" / "settings.yml").read_text())
    assert doc["outgoing"]["proxies"] == {"all://": ["http://glove-ps-searxng-egress:8888"]}


def test_collector_has_no_network_and_a_tmpfs_event_volume(tmp_path):
    _, doc, _ = render(tmp_path)
    col = doc["services"]["glove-ps-netgate"]
    assert col["network_mode"] == "none" and not {"networks", "ports", "extra_hosts"} & set(col)
    assert col["command"] == collect_command(rules=False)
    vol = doc["volumes"]["glove-ps-observe-events"]
    assert vol["driver_opts"] == {"type": "tmpfs", "device": "tmpfs", "o": "size=1m,mode=0700,uid=501,gid=20"}
    assert all(any(v.get("source") == "glove-ps-observe-events" for v in s["volumes"]) for s in gates(doc).values())


def test_resolver_and_exit_identity_only_on_proxy_gates(tmp_path):
    _, doc, _ = render(tmp_path, exts={"tor": {}, "search": {}, "webfetch": {}},
                       observe={"exit_identity": "via-proxy"})
    g = gates(doc)
    proxy, hop, llm = (g[f"glove-ps-{n}"]["command"] for n in ("proxy", "searxng-egress", "llm"))
    assert flag(proxy, "--resolver") == flag(hop, "--resolver") == "tor-socks://glove-ps-tor:9150"
    assert flag(proxy, "--route") == "tor"
    assert flag(proxy, "--exit-url") == "https://am.i.mullvad.net/json"
    assert "--exit-url" not in hop and "--resolver" not in llm and "--exit-url" not in llm


def test_gates_are_hardened_and_unprivileged(tmp_path):
    _, doc, _ = render(tmp_path)
    for name, svc in gates(doc).items():
        assert svc["cap_drop"] == ["ALL"] and "cap_add" not in svc and "privileged" not in svc, name
        assert "no-new-privileges:true" in svc["security_opt"] and svc["read_only"] is True, name
        assert svc["user"] == "501:20" and "ports" not in svc, name
        for key in ("pid", "ipc", "network_mode"):
            assert "harness" not in str(svc.get(key, "")) and not str(svc.get(key, "")).startswith("container:")


def test_gates_never_mount_the_harness_home_or_state(tmp_path):
    plan, doc, _ = render(tmp_path)
    home = os.path.realpath(plan.home_dir)
    for name, svc in gates(doc).items():
        for v in svc.get("volumes", []):
            if v["type"] == "bind":
                src = os.path.realpath(v["source"])
                assert not (src.startswith(home) or home.startswith(src + os.sep)), name
                assert src == os.path.realpath(plan.composition.export_dirs["observe"] / "net"), name


@pytest.mark.skipif(not shutil.which("docker"), reason="docker not installed")
def test_rendered_project_passes_docker_compose_config(tmp_path):
    _, _, text = render(tmp_path, observe={})
    f = tmp_path / "docker-compose.yml"
    f.write_text(text)
    proc = subprocess.run(["docker", "compose", "-f", str(f), "config", "-q"], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr


# --- export isolation (§3.4; not waivable) ----------------------------------------------


def _roots(tmp_path) -> tuple[Path, Path]:
    g = Path(os.environ["GLOVE_HOME"])
    return g / "observe" / SID, g / "control" / SID


@pytest.mark.parametrize("where", ["root", "net", "inside_net", "glove_home"])
def test_a_harness_bind_over_the_observe_export_refuses_render(tmp_path, where):
    obs, _ = _roots(tmp_path)
    home = {"root": obs, "net": obs / "net", "inside_net": obs / "net" / "h", "glove_home": obs.parent.parent}[where]
    with pytest.raises(HardeningError, match="overlaps the harness mount"):
        render(tmp_path, home=home)


def test_an_add_dir_exposing_the_control_root_refuses_render(tmp_path):
    _, ctl = _roots(tmp_path)
    ctl.parent.mkdir(parents=True)
    with pytest.raises(HardeningError, match="overlaps the harness mount"):
        render(tmp_path, add_dirs=[AddDir(str(ctl.parent), "ro")], exts={"direct": {}, "webfetch": {}, "filter": {}})


def test_isolation_is_not_waivable(tmp_path):
    every_key = frozenset({"user", "cap-drop", "cap-add", "no-new-privileges", "read-only", "seccomp", "ipc",
                           "pids", "memory", "docker-sock"})
    obs, _ = _roots(tmp_path)
    with pytest.raises(HardeningError, match="overlaps the harness mount"):
        render(tmp_path, home=obs, overrides=every_key)


def test_events_volume_and_exports_never_reach_the_harness(tmp_path):
    _, doc, _ = render(tmp_path, exts={**PI_SEARCH, "filter": {}})
    harness = doc["services"]["glove-ps-harness"]
    text = json.dumps(harness)
    assert "observe-events" not in text and "netgate-control" not in text and "/net\"" not in text
    obs, ctl = _roots(tmp_path)
    binds = [v["source"] for v in harness["volumes"] if v["type"] == "bind"]
    assert str(obs / "transcripts") in binds  # the one export the harness writes
    assert not any(b.startswith(str(ctl)) or b == str(obs) or b.startswith(str(obs / "net")) for b in binds)


# --- transcripts ----------------------------------------------------------------------


@pytest.mark.parametrize(("harness", "target"), [("pi", "/home/agent/.pi/agent/sessions"),
                                                 ("vibe", "/home/agent/.vibe/logs/session")])
def test_transcripts_bind_over_the_harness_transcript_dir(tmp_path, harness, target):
    exts = {"direct": {}, "search": {}} if harness == "vibe" else PI_SEARCH
    _, doc, _ = render(tmp_path, harness=harness, exts=exts)
    obs, _ = _roots(tmp_path)
    vols = doc["services"]["glove-ps-harness"]["volumes"]
    t = next(v for v in vols if v.get("target") == target)
    assert t["source"] == str(obs / "transcripts") and not t.get("read_only")
    # after the home bind, so it overlays it
    assert vols.index(t) > next(i for i, v in enumerate(vols) if v.get("target") == "/home/agent")


def test_transcripts_false_exports_flows_only(tmp_path):
    plan, doc, _ = render(tmp_path, observe={"transcripts": False})
    assert plan.transcripts_host_dir is None
    vols = doc["services"]["glove-ps-harness"]["volumes"]
    assert not any(str(v.get("target", "")).endswith("/sessions") for v in vols)


# --- CLI: plan/up materialise the exports, grants, session.json ---------------------------


@pytest.fixture
def ghome(tmp_path, monkeypatch):
    g = tmp_path / "ghome"
    monkeypatch.setenv("GLOVE_HOME", str(g))
    return g


def _session(tmp_path, monkeypatch, extensions: str) -> tuple[Path, str]:
    d = make_session(tmp_path / "wd")
    text = (d / "glove-session.yml").read_text() + extensions
    (d / "glove-session.yml").write_text(text)
    monkeypatch.chdir(d)
    out = runner.invoke(app, ["plan"])
    assert out.exit_code == 0, out.output
    return d, (d / ".glove" / "id").read_text().strip()


def _set_extensions(d: Path, extensions: str) -> None:
    text = (d / "glove-session.yml").read_text().split("  observe:")[0]
    (d / "glove-session.yml").write_text(text + extensions)


def test_plan_materialises_the_observe_export_and_session_json(ghome, tmp_path, monkeypatch):
    _, sid = _session(tmp_path, monkeypatch, "  observe: {}\n")
    ndir = ghome / "observe" / sid / "net"
    assert os.stat(ghome / "observe" / sid).st_mode & 0o777 == 0o700
    assert os.stat(ndir).st_mode & 0o777 == 0o700
    assert os.stat(ndir / "session.json").st_mode & 0o777 == 0o600
    assert (ghome / "observe" / sid / "transcripts").is_dir()
    facts = json.loads((ndir / "session.json").read_text())
    assert (facts["v"], facts["type"], facts["env"], facts["session"], facts["harness"]) == \
        (1, "session", sid, sid, "pi")
    assert facts["gate"] == "0.2.0" and facts["image"].startswith("glove/ext-gate-netgate:")
    llm = next(s for s in facts["services"] if s["service"] == "llm")
    assert llm["observed"] and llm["tool"] == "llm" and llm["route"] == {"kind": "tcp",
                                                                          "upstream": "tcp:host.docker.internal:8080"}
    assert facts["grants"] == {"observe": {"net": True, "transcripts": True}, "filter": {"granted": False}}
    assert not (ghome / "control" / sid).exists()  # observe alone never creates it
    row = json.loads((ghome / "registry.json").read_text())["sessions"][0]
    assert row["grants"] == facts["grants"]


def test_filter_grant_and_revocation(ghome, tmp_path, monkeypatch):
    d, sid = _session(tmp_path, monkeypatch, "  observe: {}\n  filter: {}\n")
    ctl = ghome / "control" / sid
    assert ctl.is_dir() and os.stat(ctl).st_mode & 0o777 == 0o700
    facts = json.loads((ghome / "observe" / sid / "net" / "session.json").read_text())
    since = facts["grants"]["filter"]["since"]
    assert facts["grants"]["filter"] == {"granted": True, "since": since}
    compose = yaml.safe_load((d / ".glove" / "compose.yml").read_text())
    for name, svc in gates(compose).items():
        assert any(v.get("target") == "/etc/glove/netgate-control" and v["read_only"] for v in svc["volumes"]), name
        assert "--rules" in svc["command"], name
    # the grant keeps its original `since` across launches
    assert runner.invoke(app, ["plan"]).exit_code == 0
    again = json.loads((ghome / "observe" / sid / "net" / "session.json").read_text())
    assert again["grants"]["filter"]["since"] == since
    # removing filter revokes: rules.json moves into the session dir, the dir goes
    (ctl / "rules.json").write_text('{"v": 1}')
    _set_extensions(d, "  observe: {}\n")
    out = runner.invoke(app, ["plan"])
    assert out.exit_code == 0, out.output
    assert not ctl.exists() and "revoked" in out.output
    assert (d / ".glove" / "ext" / "filter" / "rules.revoked.json").read_text() == '{"v": 1}'
    facts = json.loads((ghome / "observe" / sid / "net" / "session.json").read_text())
    assert facts["grants"]["filter"] == {"granted": False}


def test_filter_requires_observe(ghome, tmp_path, monkeypatch):
    d = make_session(tmp_path / "wd", "")
    (d / "glove-session.yml").write_text((d / "glove-session.yml").read_text() + "  filter: {}\n")
    monkeypatch.chdir(d)
    out = runner.invoke(app, ["plan"])
    assert out.exit_code == 1 and "requires 'observe'" in out.output


def test_unobserved_session_has_no_exports_and_null_grants(ghome, tmp_path, monkeypatch):
    _, sid = _session(tmp_path, monkeypatch, "")
    assert not (ghome / "observe" / sid).exists() and not (ghome / "control" / sid).exists()
    row = json.loads((ghome / "registry.json").read_text())["sessions"][0]
    assert row["grants"] == {"observe": None, "filter": None}
    out = runner.invoke(app, ["observe", "status"])
    assert out.exit_code == 1 and "not observed" in out.output


def test_observe_status_and_flows(ghome, tmp_path, monkeypatch):
    _, sid = _session(tmp_path, monkeypatch, "  observe: {}\n")
    ndir = ghome / "observe" / sid / "net"
    rec = {"v": 1, "type": "flow", "phase": "close", "id": "f_X", "env": sid, "session": sid,
           "t": "2026-09-23T04:12:33.412Z", "service": "llm", "tool": "llm", "client": "harness",
           "dest": {"host": "host.docker.internal", "port": 8080, "ip": None, "resolution": "unavailable"},
           "scope": "local", "bytes": {"up": 10, "down": 2048}, "verdict": "allow", "close_reason": "eof"}
    (ndir / "flows.ndjson").write_text(json.dumps(rec) + "\n")
    status = runner.invoke(app, ["observe", "status", "--json"])
    assert status.exit_code == 0, status.output
    data = json.loads(status.output)
    assert data["observed"] is True and data["gate_state"] == "absent"
    assert data["flows"]["by_service"]["llm"] == {"flows": 1, "active": 0, "up": 10, "down": 2048}
    assert "tcp → tcp:host.docker.internal:8080" in runner.invoke(app, ["observe", "status"]).output
    flows = runner.invoke(app, ["observe", "flows", "--json"])
    assert json.loads(flows.output.strip())["id"] == "f_X"
    assert runner.invoke(app, ["observe", "flows", "--json", "--tail", "0"]).output.strip() == ""
    assert "(eof)" in runner.invoke(app, ["observe", "flows"]).output


def test_record_full_warns_loudly(ghome, tmp_path, monkeypatch):
    d = make_session(tmp_path / "wd")
    (d / "glove-session.yml").write_text((d / "glove-session.yml").read_text()
                                         + "  observe: {record: full, record_headers: true}\n")
    monkeypatch.chdir(d)
    out = runner.invoke(app, ["plan"])
    assert out.exit_code == 0 and "observe.record: full" in out.output and "request headers" in out.output


# --- podman ---------------------------------------------------------------------------


@pytest.mark.parametrize(("rootless", "selinux", "opts"), [
    (True, False, "size=1m,mode=0700,uid=0,gid=0"),
    (False, False, "size=1m,mode=0700,uid=501,gid=20"),
    (True, True, 'size=1m,mode=0700,uid=0,gid=0,context="system_u:object_r:container_file_t:s0"'),
])
def test_podman_tmpfs_owner_and_selinux_bind_labels(tmp_path, monkeypatch, rootless, selinux, opts):
    from glove.runtimes.podman import PodmanRuntime

    rt = PodmanRuntime()
    rt._rootless = rootless
    monkeypatch.setattr(PodmanRuntime, "selinux_enabled", lambda self: selinux)
    _, doc, _ = render(tmp_path, runtime=rt)
    assert doc["volumes"]["glove-ps-observe-events"]["driver_opts"]["o"] == opts
    binds = [m for s in gates(doc).values() for m in s["volumes"] if m["type"] == "bind"]
    assert binds and all(m["bind"] == {"selinux": "z"} for m in binds)
    # keep-id where a sidecar must be the session uid: the collector writes net/,
    # and every gate shares the events tmpfs with it; SearXNG/valkey never
    for name, svc in gates(doc).items():
        assert svc.get("userns_mode") == ("keep-id" if rootless else None), name
    assert "userns_mode" not in doc["services"]["glove-ps-valkey"]


@pytest.mark.parametrize("extra", [{}, {"filter": {}}])
def test_glove_check_extension_checks_render_with_observe(extra):
    """`glove check` composes the extensions once more without a session (M9 bug:
    the collector's export bind was undefined there, so every observe session failed)."""
    from glove.doctor import extension_checks

    llm = {"provider": "llama.cpp", "location": "host", "endpoint": "127.0.0.1:8080"}
    checks = extension_checks({"llm": llm, **PI_SEARCH, "observe": {}, **extra}, harness="pi")
    assert [c for c in checks if c.status == "fail"] == []
    assert not Path("/nonexistent").exists()
