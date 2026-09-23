"""The non-negotiable invariants of network observability, each as a test.

docs/planning/network-observability.md §2.6 / §7:

1. the gate exposes no telemetry or control API on the internal network;
2. it never gains NET_ADMIN, never joins the harness's network or PID namespace,
   and never mounts the harness home;
3. net/ is a sibling of home/ and has no harness mount;
4. no host DNS resolution of a destination hostname, ever, on any code path;
5. telemetry failure degrades to dropping records, never to dropping traffic
   (the behavioural tests live in tests/test_netgate.py; the structural half —
   the send path cannot block — is here).

Also: the emitted records match the normative handoff schema, parsed straight
out of docs/planning/network-observability-layman-handoff.md.
"""

from __future__ import annotations

import ast
import asyncio
import json
import os
import re
import socket
from pathlib import Path

import pytest
from test_observe import render
from typer.testing import CliRunner

from glove.cli import app
from glove.config import AddDir
from glove.hardening import HardeningError
from glove.netgate.collector import Collector
from glove.netgate.forward import EventSink, Forwarder, ForwardSpec
from glove.netgate.records import flow_record

ROOT = Path(__file__).resolve().parents[1]
NETGATE = ROOT / "glove" / "netgate"
HANDOFF = ROOT / "docs" / "planning" / "network-observability-layman-handoff.md"


def _gate_services(doc: dict) -> dict:
    return {k: v for k, v in doc["services"].items() if "netgate" in str(v.get("image", ""))}


# --- 1. no API on the internal network --------------------------------------


def test_collector_has_no_network_at_all(tmp_path):
    _, doc, _ = render(tmp_path)
    col = doc["services"]["glove-ps-netgate"]
    assert col["network_mode"] == "none"
    assert not {"networks", "ports", "expose", "extra_hosts"} & set(col)


def test_forwarders_publish_nothing_but_their_forward_port(tmp_path):
    _, doc, _ = render(tmp_path)
    for name, svc in _gate_services(doc).items():
        assert "ports" not in svc and "expose" not in svc, name
        if svc["command"][0] == "forward":
            assert svc["command"].count("--listen") == 1


def test_forwarder_binds_exactly_one_socket():
    async def main():
        fwd = Forwarder(
            ForwardSpec(service="s", listen_port=0, upstream_host="127.0.0.1", upstream_port=9,
                        env="e", session="e", listen_host="127.0.0.1"),
            EventSink(None),
        )
        await fwd.start()
        sockets = list(fwd._server.sockets)
        await fwd.stop()
        return sockets

    socks = asyncio.run(main())
    assert len(socks) == 1 and socks[0].family == socket.AF_INET


def test_collector_listens_only_on_a_unix_socket(tmp_path):
    import tempfile

    d = tempfile.mkdtemp(dir="/tmp")
    c = Collector(tmp_path, f"{d}/ev.sock")
    c._bind()
    try:
        assert c._sock.family == socket.AF_UNIX and c._sock.type == socket.SOCK_DGRAM
        assert os.stat(f"{d}/ev.sock").st_mode & 0o077 == 0  # owner-only
    finally:
        c._sock.close()


def test_events_volume_is_not_mounted_into_the_harness(tmp_path):
    _, doc, _ = render(tmp_path)
    harness = doc["services"]["glove-ps-harness"]
    assert not any(v.get("type") == "volume" for v in harness["volumes"])
    assert "glove-ps-netgate-events" not in json.dumps(harness)


# --- 2. no NET_ADMIN, no harness namespaces, no harness home -----------------


def test_gate_services_are_hardened_and_unprivileged(tmp_path):
    _, doc, _ = render(tmp_path)
    gates = _gate_services(doc)
    assert len(gates) == 4  # llm, search, proxy forwarders + collector
    for name, svc in gates.items():
        assert svc["cap_drop"] == ["ALL"], name
        assert "cap_add" not in svc, name
        assert "privileged" not in svc, name
        assert "no-new-privileges:true" in svc["security_opt"], name
        assert svc["read_only"] is True, name
        assert svc["user"] == "501:20", name
        assert "NET_ADMIN" not in json.dumps(svc), name


def test_gate_never_shares_harness_namespaces(tmp_path):
    _, doc, _ = render(tmp_path)
    for name, svc in _gate_services(doc).items():
        for key in ("network_mode", "pid", "ipc", "cgroup", "uts", "userns_mode"):
            assert "harness" not in str(svc.get(key, "")), (name, key)
            assert not str(svc.get(key, "")).startswith(("service:", "container:")), (name, key)
        assert "pid" not in svc, name


def test_gate_never_mounts_the_harness_home(tmp_path):
    plan, doc, _ = render(tmp_path)
    home = os.path.realpath(plan.home_dir)
    for name, svc in _gate_services(doc).items():
        for v in svc.get("volumes", []):
            if v["type"] == "bind":
                src = os.path.realpath(v["source"])
                assert not (src == home or src.startswith(home + os.sep) or home.startswith(src + os.sep)), name
                # the only binds: net/ (collector, rw) and the rules dir (read-only)
                allowed = {os.path.realpath(plan.net_host_dir): False, os.path.realpath(plan.control_host_dir): True}
                assert src in allowed, name
                assert v.get("read_only", False) == allowed[src], name


def test_relocated_home_is_still_not_mounted_into_the_gate(tmp_path):
    # glove-pi-search relocates the home to ~/.glove/homes/pi-search.
    home = tmp_path / "ghome" / "homes" / "pi-search"
    plan, doc, _ = render(tmp_path, home=home)
    assert "homes/pi-search" not in json.dumps(_gate_services(doc))
    assert Path(plan.net_host_dir).parent.name == "ps"  # net/ stays in the session dir


# --- 3. net/ is a sibling of home/ with no harness mount ----------------------


def test_net_dir_is_a_sibling_of_home_and_absent_from_harness(tmp_path):
    plan, doc, _ = render(tmp_path)
    assert Path(plan.net_host_dir).parent == Path(plan.home_dir).parent
    net = os.path.realpath(plan.net_host_dir)
    for v in doc["services"]["glove-ps-harness"]["volumes"]:
        if v["type"] == "bind":
            src = os.path.realpath(v["source"])
            assert not net.startswith(src + os.sep) and src != net and not src.startswith(net + os.sep)
            assert "/net" not in v["target"]


@pytest.mark.parametrize("where", ["session_dir", "net_dir", "inside_net"])
def test_home_overlapping_net_refuses_render(tmp_path, where):
    sdir = tmp_path / "ghome" / "envs" / "ps" / "sessions" / "ps"
    home = {"session_dir": sdir, "net_dir": sdir / "net", "inside_net": sdir / "net" / "h"}[where]
    with pytest.raises(HardeningError, match="overlaps the harness mount"):
        render(tmp_path, home=home)


@pytest.mark.parametrize("where", ["control_root", "rules_dir"])
def test_home_overlapping_control_refuses_render(tmp_path, where):
    ctl = tmp_path / "ghome" / "control"
    home = {"control_root": ctl, "rules_dir": ctl / "ps" / "ps" / "h"}[where]
    with pytest.raises(HardeningError, match=r"control/ \(rules\.json\).*rewrite its own network rules"):
        render(tmp_path, home=home)


def test_rules_dir_is_never_in_the_harness(tmp_path):
    plan, doc, _ = render(tmp_path)
    assert "netgate-control" not in json.dumps(doc["services"]["glove-ps-harness"])
    ctl = os.path.realpath(plan.control_host_dir)
    for v in doc["services"]["glove-ps-harness"]["volumes"]:
        if v["type"] == "bind":
            src = os.path.realpath(v["source"])
            assert not (ctl.startswith(src + os.sep) or src == ctl or src.startswith(ctl + os.sep))


def test_add_dir_exposing_net_refuses_render(tmp_path):
    exposed = tmp_path / "ghome"
    exposed.mkdir(parents=True)
    with pytest.raises(HardeningError, match="could read or forge"):
        render(tmp_path, add_dirs=[AddDir(str(exposed), "ro")])


def test_isolation_is_not_waivable(tmp_path):
    # Waive every hardening row (--i-know-what-i-am-doing for all keys): the
    # net/ isolation check has no key, so the render must still refuse.
    every_key = frozenset({"user", "cap-drop", "cap-add", "no-new-privileges", "read-only", "seccomp",
                           "ipc", "pids", "memory", "host-gateway", "docker-sock", "net", "observe"})
    sdir = tmp_path / "ghome" / "envs" / "ps" / "sessions" / "ps"
    with pytest.raises(HardeningError, match="overlaps the harness mount"):
        render(tmp_path, home=sdir, overrides=every_key)


# --- 4. no host DNS resolution of a destination hostname ---------------------

RESOLVERS = {"getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr", "getnameinfo",
             "getfqdn", "open_connection", "create_connection"}
# The only name lookups the gate may perform (see glove/netgate/forward.py):
ALLOWED = {
    ("forward.py", "_dial_upstream"): {"open_connection"},  # the operator-configured target
    ("forward.py", "_ingress_addresses"): {"getaddrinfo"},  # glove's own ingress alias
}


def _resolver_calls(path: Path):
    tree = ast.parse(path.read_text())
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for node in ast.walk(fn):
            if isinstance(node, ast.Call):
                f = node.func
                name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)
                if name in RESOLVERS:
                    yield fn.name, name


def test_gate_resolves_names_only_in_allowlisted_functions():
    seen = set()
    for path in sorted(NETGATE.glob("*.py")):
        for fn, call in _resolver_calls(path):
            allowed = ALLOWED.get((path.name, fn), set())
            assert call in allowed, f"{path.name}:{fn} calls {call} — a new name-resolution path " \
                                    "must be reviewed against invariant 4 and added to ALLOWED"
            seen.add((path.name, fn))
    assert seen == set(ALLOWED)


@pytest.mark.parametrize("module", ["observe.py", "netview.py"])
def test_host_side_modules_never_touch_sockets(module):
    tree = ast.parse((ROOT / "glove" / module).read_text())
    imported = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    imported |= {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert not {"socket", "urllib", "urllib.request", "http.client", "ssl"} & imported


@pytest.fixture
def no_dns(monkeypatch):
    """Any name resolution on the host process becomes a test failure."""

    def boom(*a, **k):
        raise AssertionError(f"host DNS lookup attempted: {a!r}")

    for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr", "getnameinfo",
                 "getfqdn", "create_connection"):
        monkeypatch.setattr(socket, name, boom)


def test_render_and_cli_never_resolve(no_dns, tmp_path, monkeypatch):
    monkeypatch.setenv("GLOVE_HOME", str(tmp_path / "ghome"))
    work = tmp_path / "work"
    work.mkdir()
    wd = tmp_path / "wd"
    wd.mkdir()
    monkeypatch.chdir(wd)
    runner = CliRunner()
    assert runner.invoke(app, ["init", "pi"]).exit_code == 0
    over = tmp_path / "o.yaml"
    over.write_text(
        "net: [service]\nmodel: m\nobserve: {enabled: true}\nservices:\n"
        "  - { name: llm, to: llm.example.com:8080, port: 8080 }\n"
        "  - { name: proxy, to: egress-proxy:8888, join_network: pi-search-egress }\n"
    )
    r = runner.invoke(app, ["run", "pi", "--config", str(over), "--workdir", str(work), "--dry-run"])
    assert r.exit_code == 0, r.output
    ndir = tmp_path / "ghome/envs/wd/sessions/wd/net"
    (ndir / "flows.ndjson").write_text(json.dumps({
        "v": 1, "type": "flow", "phase": "open", "id": "f_1", "service": "llm",
        "dest": {"host": "some.destination.example", "port": 443, "ip": None, "resolution": "unavailable"},
        "bytes": {"up": 0, "down": 0}}) + "\n")
    for args in (["net", "status"], ["net", "status", "--json"], ["net", "flows"], ["net", "flows", "--json"]):
        res = runner.invoke(app, args)
        assert res.exception is None or isinstance(res.exception, SystemExit), (args, res.output)
    facts = json.loads((ndir / "session.json").read_text())
    # the dotted target is recorded as written, and classified `direct` by shape
    assert facts["services"][0]["upstream"] == "tcp:llm.example.com:8080"
    assert facts["services"][0]["scope"] == "direct"


def test_gate_never_resolves_for_an_ip_literal_upstream(no_dns, tmp_path):
    """With an IP-literal target (and no ingress alias) the forwarder performs
    zero lookups — the dest IP is the literal, `resolution: literal`."""

    async def main():
        async def echo(r, w):
            w.write(await r.read(5))
            await w.drain()
            w.close()

        server = await asyncio.start_server(echo, "127.0.0.1", 0, family=socket.AF_INET)
        port = server.sockets[0].getsockname()[1]
        records: list[dict] = []
        sink = EventSink(None)
        sink.send = lambda rec: records.append(rec) or True
        fwd = Forwarder(ForwardSpec(service="s", listen_port=0, upstream_host="127.0.0.1", upstream_port=port,
                                    env="e", session="e", listen_host="127.0.0.1"), sink)
        await fwd.start()
        r, w = await asyncio.open_connection("127.0.0.1", fwd.port, family=socket.AF_INET)
        w.write(b"hello")
        got = await r.read()
        w.close()
        await asyncio.sleep(0.05)
        await fwd.stop()
        server.close()
        return got, records

    got, records = asyncio.run(asyncio.wait_for(main(), 10))
    assert got == b"hello"
    assert records[-1]["dest"]["ip"] == "127.0.0.1" and records[-1]["dest"]["resolution"] == "literal"


def test_hostname_target_is_recorded_unresolved():
    spec = ForwardSpec(service="s", listen_port=1, upstream_host="searxng", upstream_port=8080,
                       env="e", session="e")
    assert spec.dest_ip_and_resolution() == (None, "unavailable")
    spec_none = ForwardSpec(service="s", listen_port=1, upstream_host="searxng", upstream_port=8080,
                            env="e", session="e", resolve="none")
    assert spec_none.dest_ip_and_resolution() == (None, "disabled")


# --- 5. telemetry cannot block traffic (structural half) ---------------------


def test_event_sink_is_non_blocking_and_never_raises(tmp_path):
    sink = EventSink(str(tmp_path / "missing.sock"))
    assert sink._sock.getblocking() is False
    assert sink.send({"x": object()}) is False  # unserialisable
    assert sink.send({"ok": 1}) is False  # no listener
    assert sink.dropped == 2


# --- schema conformance with the normative handoff brief ---------------------


def _jsonc_blocks(section: str) -> list[dict]:
    text = HANDOFF.read_text()
    start = text.index(section)
    blocks = re.findall(r"```jsonc\n(.*?)```", text[start:], flags=re.S)
    out = []
    for b in blocks:
        b = re.sub(r"(?m)(^|\s)//.*$", "", b)  # strip // comments (not the // in URLs)
        b = b.replace("…", "x")
        out.append(json.loads(b))
    return out


def _shape(obj):
    if isinstance(obj, dict):
        return {k: _shape(v) for k, v in obj.items()}
    return None


def test_flow_record_matches_handoff_schema_exactly():
    spec_flow = _jsonc_blocks("## 2. Flow schema")[0]
    ours = flow_record(phase="open", flow_id="f_x", env="e", session="e", t=0, t_open=0, t_close=None,
                       service="llm", tool="llm", client="harness", proto="tcp", dest_host="h", dest_port=1,
                       dest_ip=None, resolution="unavailable", scope="local", route_kind="tcp",
                       route_upstream="tcp:h:1", up=0, down=0)
    assert _shape(ours) == _shape(spec_flow)
    assert list(ours) == list(spec_flow)  # same key order as the brief
    assert list(ours["dest"]) == list(spec_flow["dest"])


def test_status_json_carries_every_handoff_field(tmp_path):
    spec_status = _jsonc_blocks("### `status.json`")[0]
    ours = Collector(tmp_path, "/tmp/unused.sock").status("running")
    for key, sub in _shape(spec_status).items():
        assert key in ours, key
        if isinstance(sub, dict):
            assert set(sub) <= set(ours[key]), key
    assert ours["v"] == 1 and ours["record"] == "metadata"
