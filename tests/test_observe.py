"""Network observability (host side): config, gate specs, render, net/, CLI."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from glove.cli import app
from glove.config import Config, ConfigError, Service, load_config
from glove.network import build_network_plan
from glove.observe import (
    classify_scope,
    ensure_net_dir,
    net_dir,
    netgate_image,
    parse_observe,
    session_facts,
)
from glove.plan import build_session_plan
from glove.runtimes.docker import DockerRuntime

runner = CliRunner()


def pi_search_services() -> list[Service]:
    """The glove-pi-search service set (configs/pi-search.glove.yaml, tokens filled
    with the .env.example defaults: LLM_HOST=host.docker.internal, LLM_PORT=8080)."""
    return [
        Service(name="llm", to="host.docker.internal:8080", port=8080, host_gateway=True),
        Service(name="search", to="searxng:8080", port=8080, join_network="pi-search-egress"),
        Service(name="proxy", to="egress-proxy:8888", port=8888, join_network="pi-search-egress"),
    ]


def render(tmp_path, *, observe=None, services=None, home=None, add_dirs=None, uid=501, gid=20,
           overrides=frozenset()):
    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    sdir = tmp_path / "ghome" / "envs" / "ps" / "sessions" / "ps"
    cfg = Config(harness="pi", workdir=str(work), name="ps", net=["service"], plugins=["search"],
                 observe={"enabled": True} if observe is None else observe)
    cfg.services = pi_search_services() if services is None else services
    if add_dirs:
        cfg.add_dirs = add_dirs
    plan = build_session_plan(
        cfg, env_id="ps", home_dir=str(home or sdir / "home"), cwd=str(work), uid=uid, gid=gid
    )
    if plan.observe is not None:
        plan.net_host_dir = str(ensure_net_dir(net_dir(sdir)))
    rendered = DockerRuntime().render(plan, sdir, overrides=overrides)
    return plan, yaml.safe_load(rendered.compose_yaml), rendered.compose_yaml


# --- config ----------------------------------------------------------------


def test_observe_off_by_default():
    assert parse_observe(Config()) is None
    cfg = Config(harness="pi", name="s", net=["service"])
    cfg.services = pi_search_services()
    assert all(s.gate is None for s in build_network_plan(cfg, "s").sidecars)


def test_observe_true_shorthand_and_defaults():
    s = parse_observe(Config(observe=True))
    assert (s.record, s.resolve, s.keep) == ("metadata", "in-tunnel", 8)


@pytest.mark.parametrize(
    ("observe", "match"),
    [
        ({"enabled": True, "record": "full"}, "M5"),
        ({"enabled": True, "resolve": "host"}, "in-tunnel|none"),
        ({"enabled": True, "exit_identity": "gluetun://x"}, "unknown observe keys"),
        ({"enabled": True, "rotate_mb": 0}, "rotate_mb"),
        ("yes", "mapping"),
    ],
)
def test_observe_rejects(observe, match):
    with pytest.raises(ConfigError, match=match):
        parse_observe(Config(observe=observe))


def test_service_modes_beyond_m1_are_rejected():
    cfg = Config(harness="pi", name="s", net=["service"], observe={"enabled": True})
    cfg.services = [Service(name="proxy", to="egress-proxy:8888",
                            observe={"mode": "http-proxy", "upstream": "chain:http://egress-proxy:8888"})]
    with pytest.raises(ConfigError, match="M2"):
        build_network_plan(cfg, "s")


def test_service_observe_block_without_global_enable_errors():
    cfg = Config(harness="pi", name="s", net=["service"])
    cfg.services = [Service(name="llm", to="h:1", observe={"tool": "llm"})]
    with pytest.raises(ConfigError, match=r"observe\.enabled"):
        build_network_plan(cfg, "s")


def test_gate_specs_for_pi_search():
    cfg = Config(harness="pi", name="s", net=["service"], observe={"enabled": True})
    cfg.services = pi_search_services()
    gates = {s.role: s.gate for s in build_network_plan(cfg, "s").sidecars}
    assert gates["llm"].tool == "llm" and gates["llm"].scope == "local"
    assert gates["search"].tool == "web_search"
    assert gates["proxy"].tool == "web_fetch"
    assert gates["llm"].upstream == "tcp:host.docker.internal:8080"


def test_per_service_opt_out_and_annotations():
    cfg = Config(harness="pi", name="s", net=["service"], observe={"enabled": True})
    cfg.services = [
        Service(name="llm", to="host.docker.internal:8080", observe=False),
        Service(name="api", to="api.example.com:443", join_network="n",
                observe={"tool": "custom", "scope": "tunnelled"}),
    ]
    sc = {s.role: s for s in build_network_plan(cfg, "s").sidecars}
    assert sc["llm"].gate is None
    assert (sc["api"].gate.tool, sc["api"].gate.scope) == ("custom", "tunnelled")


@pytest.mark.parametrize(
    ("host", "gw", "scope"),
    [
        ("host.docker.internal", False, "local"),
        ("llm.lan", True, "local"),
        ("searxng", False, "local"),
        ("10.0.0.5", False, "local"),
        ("169.254.169.254", False, "local"),
        ("8.8.8.8", False, "direct"),
        ("api.example.com", False, "direct"),
    ],
)
def test_classify_scope_by_shape(host, gw, scope):
    assert classify_scope(host, gw) == scope


def test_service_observe_round_trips_through_effective_yaml(tmp_path):
    cfg = Config(harness="pi", observe={"enabled": True})
    cfg.services = [Service(name="llm", to="h:1", observe={"tool": "llm"})]
    p = tmp_path / "eff.yaml"
    p.write_text(cfg.to_yaml())
    back = load_config(p)
    assert back.observe == {"enabled": True}
    assert back.services[0].observe == {"tool": "llm"}


# --- render ----------------------------------------------------------------


def test_render_replaces_socat_with_gate_dropin(tmp_path):
    plan, doc, _ = render(tmp_path)
    svcs = doc["services"]
    for role, port, target in [("llm", 8080, "tcp:host.docker.internal:8080"),
                               ("search", 8080, "tcp:searxng:8080"),
                               ("proxy", 8888, "tcp:egress-proxy:8888")]:
        s = svcs[f"glove-ps-{role}"]
        assert s["container_name"] == f"glove-ps-{role}"  # same DNS name as socat
        assert s["image"] == netgate_image()
        cmd = s["command"]
        assert cmd[0] == "forward"
        assert cmd[cmd.index("--listen") + 1] == str(port)
        assert cmd[cmd.index("--upstream") + 1] == target
    # networks match what the socat sidecar joined
    assert set(svcs["glove-ps-llm"]["networks"]) == {"glove-ps-net", "glove-ps-egress"}
    assert svcs["glove-ps-llm"]["extra_hosts"] == ["host.docker.internal:host-gateway"]
    assert set(svcs["glove-ps-search"]["networks"]) == {"glove-ps-net", "pi-search-egress"}
    assert svcs["glove-ps-search"]["networks"]["glove-ps-net"]["aliases"] == ["glove-ps-search-ingress"]
    # the harness still dials the same endpoints
    assert plan.environment.get("SEARXNG_URL") == "http://glove-ps-search:8080"


def test_render_adds_collector_and_tmpfs_event_volume(tmp_path):
    plan, doc, _ = render(tmp_path)
    col = doc["services"]["glove-ps-netgate"]
    assert col["network_mode"] == "none"
    assert "networks" not in col
    binds = [v for v in col["volumes"] if v["type"] == "bind"]
    assert [(b["source"], b["target"]) for b in binds] == [(plan.net_host_dir, "/var/lib/glove/net")]
    vol = doc["volumes"]["glove-ps-netgate-events"]
    assert vol["driver_opts"]["type"] == "tmpfs"
    assert "uid=501" in vol["driver_opts"]["o"] and "mode=0700" in vol["driver_opts"]["o"]


def test_mixed_observed_and_plain_services(tmp_path):
    services = pi_search_services()
    services[1] = Service(name="search", to="searxng:8080", join_network="pi-search-egress", observe=False)
    _, doc, _ = render(tmp_path, services=services)
    assert doc["services"]["glove-ps-search"]["image"] == "glove/forwarder:0.2.0"
    assert doc["services"]["glove-ps-search"]["command"].startswith("TCP4-LISTEN:8080")
    assert doc["services"]["glove-ps-llm"]["image"] == netgate_image()


def test_session_facts(tmp_path):
    plan, _, _ = render(tmp_path)
    facts = session_facts(plan)
    assert (facts["v"], facts["type"], facts["env"], facts["session"]) == (1, "session", "ps", "ps")
    assert facts["record"] == "metadata" and facts["gate"] == "0.1.0"
    by = {s["service"]: s for s in facts["services"]}
    assert by["proxy"]["listen"] == "glove-ps-proxy:8888"
    assert by["llm"]["route"] == {"kind": "tcp", "upstream": "tcp:host.docker.internal:8080"}
    assert all(s["observed"] for s in facts["services"])


def test_netgate_image_tag_tracks_sources():
    tag = netgate_image()
    assert tag.startswith("glove/netgate:0.1.0-") and len(tag.rsplit("-", 1)[1]) == 10


@pytest.mark.skipif(not shutil.which("docker"), reason="docker not installed")
def test_rendered_project_passes_docker_compose_config(tmp_path):
    _, _, text = render(tmp_path)
    f = tmp_path / "docker-compose.yml"
    f.write_text(text)
    proc = subprocess.run(["docker", "compose", "-f", str(f), "config", "-q"], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr


PI_SEARCH_TEMPLATE = Path.home() / "development/castellotti/glove-pi-search/configs/pi-search.glove.yaml"


@pytest.mark.skipif(not PI_SEARCH_TEMPLATE.is_file(), reason="glove-pi-search checkout not present")
def test_real_pi_search_config_renders_with_observe(tmp_path):
    """The first test configuration, read from the sibling repo (never modified),
    tokens filled with .env.example defaults, plus `observe: {enabled: true}`."""
    text = (PI_SEARCH_TEMPLATE.read_text()
            .replace("__LLM_HOST__", "host.docker.internal").replace("__LLM_PORT__", "8080")
            .replace("__LLM_MODEL__", "m").replace("__GLOVE_HOME__", str(tmp_path / "gh")))
    data = yaml.safe_load(text)
    data["observe"] = {"enabled": True}
    data["name"] = "pi-search"
    work = tmp_path / "work"
    work.mkdir()
    data["workdir"] = str(work)
    cfg_path = tmp_path / "eff.yaml"
    cfg_path.write_text(yaml.safe_dump(data))
    cfg = load_config(cfg_path)
    plan = build_session_plan(cfg, env_id="pi-search", home_dir=str(tmp_path / "gh/homes/pi-search"),
                              cwd=str(work), uid=501, gid=20)
    sdir = tmp_path / "gh/envs/pi-search/sessions/pi-search"
    plan.net_host_dir = str(ensure_net_dir(net_dir(sdir)))
    doc = yaml.safe_load(DockerRuntime().render(plan, sdir).compose_yaml)
    gated = {k for k, v in doc["services"].items() if v.get("image") == netgate_image()}
    assert gated == {"glove-pi-search-llm", "glove-pi-search-search", "glove-pi-search-proxy",
                     "glove-pi-search-netgate"}
    # GLOVE_FETCH_PROXY (hand-written in the config) still names a live listener
    h = doc["services"]["glove-pi-search-harness"]["environment"]
    assert h["GLOVE_FETCH_PROXY"] == "http://glove-pi-search-proxy:8888"


# --- CLI -------------------------------------------------------------------


@pytest.fixture
def ghome(tmp_path, monkeypatch):
    g = tmp_path / "ghome"
    monkeypatch.setenv("GLOVE_HOME", str(g))
    return g


def _observed_run(tmp_path, monkeypatch, *extra) -> tuple:
    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    wd = tmp_path / "pi-local"
    wd.mkdir(exist_ok=True)
    monkeypatch.chdir(wd)
    assert runner.invoke(app, ["init", "pi"]).exit_code == 0
    over = tmp_path / "over.yaml"
    over.write_text(
        "net: [service]\nmodel: m\nobserve: {enabled: true}\n"
        "services:\n  - { name: llm, to: host.docker.internal:8080, port: 8080 }\n"
    )
    return runner.invoke(app, ["run", "pi", "--config", str(over), "--workdir", str(work), "--dry-run", *extra])


def test_cli_dry_run_materialises_net_dir(ghome, tmp_path, monkeypatch):
    result = _observed_run(tmp_path, monkeypatch)
    assert result.exit_code == 0, result.output
    sdir = ghome / "envs" / "pi-local" / "sessions" / "pi-local"
    ndir = sdir / "net"
    assert ndir.is_dir() and (sdir / "home").is_dir()
    assert ndir.parent == (sdir / "home").parent  # a sibling of home/
    assert os.stat(ndir).st_mode & 0o777 == 0o700
    assert os.stat(ndir / "session.json").st_mode & 0o777 == 0o600
    facts = json.loads((ndir / "session.json").read_text())
    assert facts["session"] == "pi-local" and facts["services"][0]["tool"] == "llm"
    assert "network observability" in result.output


def test_cli_net_status_and_flows(ghome, tmp_path, monkeypatch):
    assert _observed_run(tmp_path, monkeypatch).exit_code == 0
    ndir = ghome / "envs" / "pi-local" / "sessions" / "pi-local" / "net"
    rec = {"v": 1, "type": "flow", "phase": "close", "id": "f_X", "env": "pi-local", "session": "pi-local",
           "t": "2026-09-23T04:12:33.412Z", "service": "llm", "tool": "llm", "client": "harness",
           "dest": {"host": "host.docker.internal", "port": 8080, "ip": None, "resolution": "unavailable"},
           "scope": "local", "bytes": {"up": 10, "down": 2048}, "verdict": "allow", "close_reason": "eof"}
    (ndir / "flows.ndjson").write_text(json.dumps(rec) + "\n")

    status = runner.invoke(app, ["net", "status", "--json"])
    assert status.exit_code == 0, status.output
    data = json.loads(status.output)
    assert data["observed"] is True and data["gate_state"] == "absent"
    assert data["flows"]["by_service"]["llm"] == {"flows": 1, "active": 0, "up": 10, "down": 2048}

    text = runner.invoke(app, ["net", "status"])
    assert "llm" in text.output and "tcp → tcp:host.docker.internal:8080" in text.output

    flows = runner.invoke(app, ["net", "flows", "--json"])
    assert flows.exit_code == 0
    assert json.loads(flows.output.strip())["id"] == "f_X"
    assert runner.invoke(app, ["net", "flows", "--json", "--tail", "0"]).output.strip() == ""
    human = runner.invoke(app, ["net", "flows"])
    assert "host.docker.internal:8080" in human.output and "(eof)" in human.output


def test_cli_net_status_unobserved_session(ghome, tmp_path, monkeypatch):
    wd = tmp_path / "wd"
    wd.mkdir()
    monkeypatch.chdir(wd)
    assert runner.invoke(app, ["init", "pi"]).exit_code == 0
    result = runner.invoke(app, ["net", "status"])
    assert result.exit_code == 1
    assert "not observed" in result.output
