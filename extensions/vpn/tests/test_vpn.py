"""`vpn` (v3 M4): gluetun egress, compose secrets and the register hook."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml
from helpers import hook_ctx, make_cfg, render

from glove.extensions import ExtensionError, launch_env, load_module, secret_env_var

HOOKS = load_module(Path(__file__).parents[1] / "hooks.py", "vpn")
KEY = "a" * 43 + "="


def _render(tmp_path, **settings):
    cfg = make_cfg(name="s", workdir=str(tmp_path), extensions={"vpn": settings}, subnet="172.31.7.0/24")
    plan, text = render(cfg, tmp_path)
    return plan, yaml.safe_load(text)


def test_gluetun_privileges_secret_and_firewall(tmp_path):
    plan, doc = _render(tmp_path, provider="custom", wireguard_key="keychain:wg", addresses="10.0.0.2/32",
                        public_key=KEY, endpoint="192.0.2.1:51820")
    g = doc["services"]["glove-s-gluetun"]
    assert set(g["networks"]) == {"glove-s-egress", "glove-s-wan"}
    assert "user" not in g and g["read_only"] is False  # root + writable rootfs: declared privileges
    assert g["cap_add"] == ["NET_ADMIN"] and g["devices"] == ["/dev/net/tun:/dev/net/tun"]
    assert g["cap_drop"] == ["ALL"] and "no-new-privileges:true" in g["security_opt"]
    # gluetun's DNS server on :53, the gates' resolver: podman does not allow low ports by default
    assert g["sysctls"] == {"net.ipv4.ip_unprivileged_port_start": 0} and "NET_BIND_SERVICE" not in g["cap_add"]
    env = g["environment"]
    assert env["VPN_SERVICE_PROVIDER"] == "custom" and env["WIREGUARD_ADDRESSES"] == "10.0.0.2/32"
    assert env["WIREGUARD_PUBLIC_KEY"] == KEY
    assert (env["WIREGUARD_ENDPOINT_IP"], env["WIREGUARD_ENDPOINT_PORT"]) == ("192.0.2.1", "51820")
    assert env["FIREWALL_OUTBOUND_SUBNETS"] == "172.31.7.0/24"
    assert env["HTTP_CONTROL_SERVER_ADDRESS"] == "127.0.0.1:8000"
    assert g["secrets"] == [{"source": "glove-s-vpn-wireguard_private_key",
                             "target": "/run/glove-secrets/wireguard_private_key"}]
    # not /run/secrets: podman mounts its own dir there at start, hiding the file
    assert env["WIREGUARD_PRIVATE_KEY_SECRETFILE"] == "/run/glove-secrets/wireguard_private_key"
    assert doc["secrets"]["glove-s-vpn-wireguard_private_key"] == {
        "environment": secret_env_var("vpn-wireguard_private_key")}
    assert "wireguard_key" not in yaml.safe_dump(env)  # the ref never reaches the container
    assert plan.composition.privileges["vpn/gluetun"]
    assert [v["kind"] for _, v in plan.composition.verify] == ["container-healthy", "http-ok", "hook"]
    # stated in the fragment: podman drops the HEALTHCHECK of an OCI-manifest image
    assert g["healthcheck"]["test"] == ["CMD-SHELL", "/gluetun-entrypoint healthcheck"]


def test_quad9_by_default_and_no_lookup(tmp_path):
    plan, doc = _render(tmp_path, provider="custom", wireguard_key="keychain:wg")
    env = doc["services"]["glove-s-gluetun"]["environment"]
    assert env["PUBLICIP_ENABLED"] == "off" and "PUBLICIP_API" not in env
    assert (env["DNS_UPSTREAM_RESOLVERS"], env["HEALTH_TARGET_ADDRESSES"], env["HEALTH_ICMP_TARGET_IPS"]) == (
        "quad9", "dns.quad9.net:443", "9.9.9.9")
    assert plan.composition.verify[1][1]["url"] == "https://on.quad9.net"  # the proxy passes traffic
    check = plan.composition.verify[2][1]
    assert check["source"] == "exec" and check["argv"] == ["cat", "/run/glove-exit/ip"]
    assert check["host_check_url"] == "" and check["retries"] == 15
    # the operator's own choices; empty lists leave gluetun's defaults
    plan, doc = _render(tmp_path, provider="custom", wireguard_key="keychain:wg", publicip_api="echoip#https://ip.example",
                        dns_upstream=["cloudflare", "google"], health_targets=[], health_icmp=[],
                        host_check_url="https://mine.example/ip")
    env = doc["services"]["glove-s-gluetun"]["environment"]
    assert (env["PUBLICIP_ENABLED"], env["PUBLICIP_API"], env["PUBLICIP_FILE"]) == (
        "on", "echoip#https://ip.example", "/run/glove-exit/ip")
    assert env["DNS_UPSTREAM_RESOLVERS"] == "cloudflare,google"
    assert "HEALTH_TARGET_ADDRESSES" not in env and "HEALTH_ICMP_TARGET_IPS" not in env
    checks = [v for _, v in plan.composition.verify]
    assert [v["kind"] for v in checks] == ["container-healthy", "http-ok", "hook"]
    assert checks[2]["retries"] == 15 and checks[2]["argv"] == ["cat", "/run/glove-exit/ip"]
    assert checks[2]["host_check_url"] == "https://mine.example/ip"


KILL_SWITCH = """-P INPUT DROP
-P OUTPUT DROP
-A OUTPUT -o lo -j ACCEPT
-A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A OUTPUT -d 172.31.7.0/24 -o eth0 -j ACCEPT
-A OUTPUT -d 198.51.100.7/32 -o eth0 -p udp -m udp --dport 51820 -j ACCEPT
-A OUTPUT -d 198.51.100.9/32 -o tun0 -p tcp -m tcp --dport 443 -j ACCEPT
-A OUTPUT -o tun0 -j ACCEPT
"""


@pytest.mark.parametrize(("tables", "want"), [
    ({"iptables": KILL_SWITCH}, "198.51.100.7\n"),
    # gluetun may use the legacy tables: read both, an endpoint twice is one
    ({"iptables": KILL_SWITCH, "iptables-legacy": KILL_SWITCH}, "198.51.100.7\n"),
    ({"ip6tables": "-A OUTPUT -d 2001:db8::7/128 -o eth0 -p tcp -m tcp --dport 1194 -j ACCEPT\n"}, "2001:db8::7\n"),
    ({"iptables": KILL_SWITCH.replace("198.51.100.7/32 -o eth0", "198.51.100.7/32 -o tun0")}, ""),  # no endpoint
    ({"iptables": KILL_SWITCH, "ip6tables": "-A OUTPUT -d 2001:db8::7/128 -o eth0 -p udp -m udp --dport 1 -j ACCEPT"},
     "198.51.100.7\n2001:db8::7\n"),  # two: core's check refuses it
])
def test_the_endpoint_is_read_from_the_kill_switch(tmp_path, tables, want):
    import subprocess

    _, doc = _render(tmp_path, provider="custom", wireguard_key="keychain:wg")
    entry = doc["services"]["glove-s-gluetun"]["entrypoint"]
    assert entry[:2] == ["/bin/sh", "-c"] and entry[2].endswith("& exec /gluetun-entrypoint")
    shared = tmp_path / "exit"  # vpn's `exit` volume, at /run/glove-exit in gluetun
    shared.mkdir()
    # one round of the loop, in the foreground (core renders `$` as compose's `$$`)
    script = (entry[2].replace("$$", "$").replace("/run/glove-exit", str(shared))
              .replace("sleep $n; done) &", "break; done);").replace("exec /gluetun-entrypoint", "true"))
    stubs = tmp_path / "bin"
    stubs.mkdir()
    for t in ("iptables", "iptables-legacy", "ip6tables", "ip6tables-legacy"):
        (stubs / f"{t}.out").write_text(tables.get(t, ""))
        (stubs / t).write_text(f"#!/bin/sh\ncat '{stubs / t}.out'\n")
        (stubs / t).chmod(0o755)

    def once(script: str) -> str | None:
        r = subprocess.run(["sh", "-c", script], capture_output=True, text=True,
                           env={"PATH": f"{stubs}:/usr/bin:/bin"}, check=True)
        assert not r.stdout and not r.stderr
        f = shared / "ip"
        assert sorted(x.name for x in shared.iterdir()) == (["ip"] if f.exists() else [])
        return f.read_text() if f.exists() else None

    # absent until known (every start removes it); one endpoint is written, none or two are not
    assert once(script) == (want.strip() if want.count("\n") == 1 else None)
    # a later round, once 192.0.2.1 was known: a new one is written (a reconnect),
    # none or two empty it (the tunnel moved or is down)
    (shared / "ip").write_text("192.0.2.1")
    later = script.removeprefix(f"rm -f {shared}/ip;").replace("(last=;", "(last=192.0.2.1;")
    assert later.count("192.0.2.1") == 1 and once(later) == (want.strip() if want.count("\n") == 1 else "")


def test_the_exit_file_is_shared_with_observe_and_emptied_at_start(tmp_path):
    plan, doc = _render(tmp_path, provider="custom", wireguard_key="keychain:wg")
    g = doc["services"]["glove-s-gluetun"]
    assert {"type": "volume", "source": "glove-s-vpn-exit", "target": "/run/glove-exit"} in g["volumes"]
    assert doc["volumes"]["glove-s-vpn-exit"] == {"name": "glove-s-vpn-exit"}  # gluetun's root owns it
    assert g["entrypoint"][2].startswith("rm -f /run/glove-exit/ip;")
    ex = plan.composition.slot_exports("egress")
    assert ex["exit_identity"] == {"source": "vpn-endpoint", "volume": "exit", "file": "ip"}
    assert ex["shares"] == ["exit"]  # only this volume reaches observe's gate (read-only)
    plan, doc = _render(tmp_path, provider="custom", wireguard_key="keychain:wg", publicip_api="echoip#https://ip.example")
    assert plan.composition.slot_exports("egress")["exit_identity"]["source"] == "gluetun:publicip"
    # gluetun writes it itself: no endpoint loop
    assert doc["services"]["glove-s-gluetun"]["entrypoint"] == [
        "/bin/sh", "-c", "rm -f /run/glove-exit/ip && exec /gluetun-entrypoint"]


@pytest.mark.parametrize("settings", [
    {"publicip_api": 'echoip#https://x" EXTRA: "1'}, {"dns_upstream": ["quad9,cloudflare\n"]},
    {"health_icmp": ["9.9.9.9 "]}, {"host_check_url": "ftp://x"},
])
def test_new_settings_cannot_escape_their_value(tmp_path, settings):
    with pytest.raises(ExtensionError, match="must match"):
        _render(tmp_path, provider="custom", wireguard_key="keychain:wg", **settings)


def test_openvpn_uses_two_secrets(tmp_path):
    _, doc = _render(tmp_path, provider="x", type="openvpn", openvpn_user="keychain:u", openvpn_password="keychain:p")
    targets = [s["target"] for s in doc["services"]["glove-s-gluetun"]["secrets"]]
    assert targets == ["/run/glove-secrets/openvpn_user", "/run/glove-secrets/openvpn_password"]
    env = doc["services"]["glove-s-gluetun"]["environment"]
    assert (env["OPENVPN_USER_SECRETFILE"], env["OPENVPN_PASSWORD_SECRETFILE"]) == tuple(targets)


@pytest.mark.parametrize(("settings", "match"), [
    ({"provider": "x"}, "wireguard_key"),
    ({"provider": "x", "type": "openvpn"}, "openvpn_user"),
    ({"provider": "x", "wireguard_key": "k"}, "reference"),
    ({"provider": "x", "register_hook": "local/h.sh", "register_user": "keychain:u", "register_pass": "keychain:p"},
     "provider: custom"),
    ({"provider": "custom", "register_hook": "work/h.sh", "register_user": "keychain:u",
      "register_pass": "keychain:p"}, "local/"),
    ({"provider": "custom", "register_hook": "local/h.sh"}, "register_user"),
    ({"provider": "custom", "register_hook": "/etc/h.sh", "register_user": "keychain:u",
      "register_pass": "keychain:p"}, "inside the session"),
    # custom has no server list for gluetun to filter (it would refuse to start)
    ({"provider": "custom", "register_hook": "local/h.sh", "register_user": "keychain:u",
      "register_pass": "keychain:p", "countries": ["Sweden"]}, "vpn.countries .* set `location:` instead"),
    ({"provider": "custom", "wireguard_key": "keychain:wg", "cities": ["Stockholm"]}, "vpn.cities .* remove it"),
    ({"provider": "x", "wireguard_key": "keychain:wg", "location": "here"}, "vpn.location is for the register_hook"),
])
def test_bad_settings_are_refused(tmp_path, settings, match):
    with pytest.raises(ExtensionError, match=match):
        _render(tmp_path, **settings)


def _hook(tmp_path, body: str, *, name="local/register.sh", mode=0o755) -> Path:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(mode)
    return path


def test_register_hook_contract(tmp_path):
    session = tmp_path / "sess"
    _hook(session, 'read u; read p; [ "$u" = alice ] && [ "$p" = s3cret ] || exit 3\n'
                   f'echo WIREGUARD_PRIVATE_KEY={KEY}\necho WIREGUARD_PUBLIC_KEY=pub\n'
                   'echo WIREGUARD_ENDPOINT_IP=192.0.2.1\necho WIREGUARD_ENDPOINT_PORT=1337\n'
                   'echo WIREGUARD_ADDRESSES=10.1.2.3/32\necho progress >&2\n')
    ctx = hook_ctx(settings={"register_hook": "local/register.sh", "register_user": "keychain:u",
                             "register_pass": "keychain:p"}, session_dir=session)
    out = HOOKS.launch_env(ctx, {"keychain:u": "alice", "keychain:p": "s3cret"}.__getitem__)
    assert out == {"secrets": {"wireguard_private_key": KEY},
                   "env": {"WIREGUARD_PUBLIC_KEY": "pub", "WIREGUARD_ENDPOINT_IP": "192.0.2.1",
                           "WIREGUARD_ENDPOINT_PORT": "1337", "WIREGUARD_ADDRESSES": "10.1.2.3/32"}}


def test_the_hook_gets_location_as_vpn_location_only(tmp_path, monkeypatch):
    session = tmp_path / "sess"
    _hook(session, 'read u; read p; [ "$VPN_LOCATION" = "${WANT-}" ] || exit 3\n'
                   f'echo WIREGUARD_PRIVATE_KEY={KEY}\necho WIREGUARD_PUBLIC_KEY=pub\n'
                   'echo WIREGUARD_ENDPOINT_IP=192.0.2.1\necho WIREGUARD_ENDPOINT_PORT=1337\n'
                   'echo WIREGUARD_ADDRESSES=10.1.2.3/32\n')
    settings = {"register_hook": "local/register.sh", "register_user": "keychain:u", "register_pass": "keychain:p"}
    monkeypatch.setenv("VPN_LOCATION", "from-the-shell")  # never passed on
    monkeypatch.setenv("WANT", "region_2")
    HOOKS.launch_env(hook_ctx(settings={**settings, "location": "region_2"}, session_dir=session), str)
    monkeypatch.setenv("WANT", "")
    HOOKS.launch_env(hook_ctx(settings=settings, session_dir=session), str)


def test_hook_must_stay_in_local(tmp_path):
    session = tmp_path / "sess"
    target = _hook(session, "exit 0\n", name="work/evil.sh")
    (session / "local").mkdir()
    os.symlink(target, session / "local" / "link.sh")
    with pytest.raises(ValueError, match="outside the session's local/"):
        HOOKS.hook_path(session, "local/link.sh")
    _hook(session, "exit 0\n", name="local/noexec.sh", mode=0o644)
    with pytest.raises(ValueError, match="not an executable"):
        HOOKS.hook_path(session, "local/noexec.sh")


@pytest.mark.parametrize(("out", "match"), [
    (f"WIREGUARD_PRIVATE_KEY={KEY}\nOTHER=1\n", "unexpected line"),
    (f"WIREGUARD_PRIVATE_KEY={KEY}\n", "did not print"),
    ("WIREGUARD_PRIVATE_KEY=short\nWIREGUARD_PUBLIC_KEY=p\nWIREGUARD_ENDPOINT_IP=1\n"
     "WIREGUARD_ENDPOINT_PORT=1\nWIREGUARD_ADDRESSES=a\n", "not a WireGuard key"),
])
def test_hook_output_is_strict(out, match):
    with pytest.raises(ValueError, match=match):
        HOOKS.parse_hook_output(out)


def test_hook_values_reach_compose_only_through_the_environment(tmp_path, monkeypatch):
    session = tmp_path / "sess"
    _hook(session, f"echo WIREGUARD_PRIVATE_KEY={KEY}\necho WIREGUARD_PUBLIC_KEY=pub\n"
                   "echo WIREGUARD_ENDPOINT_IP=192.0.2.1\necho WIREGUARD_ENDPOINT_PORT=1\n"
                   "echo WIREGUARD_ADDRESSES=10.1.2.3/32\n")
    monkeypatch.setenv("U", "u")
    monkeypatch.setenv("P", "p")
    cfg = make_cfg(name="s", workdir=str(session), extensions={"vpn": {
        "provider": "custom", "register_hook": "local/register.sh",
        "register_user": "env:U", "register_pass": "env:P"}})
    from glove.plan import build_session_plan, secret_env

    plan = build_session_plan(cfg, home_dir=str(tmp_path / "h"), state_dir=str(tmp_path / "x"),
                              session_dir=str(session))
    from glove.runtimes.docker import DockerRuntime

    doc = yaml.safe_load(DockerRuntime().render(plan, tmp_path).compose_yaml)
    env = doc["services"]["glove-s-gluetun"]["environment"]
    assert env["VPN_SERVICE_PROVIDER"] == "custom"
    assert env["WIREGUARD_PUBLIC_KEY"] is None and env["WIREGUARD_ENDPOINT_IP"] is None  # from glove's env
    secrets = secret_env(plan)
    assert secrets[secret_env_var("vpn-wireguard_private_key")] == KEY
    assert secrets["WIREGUARD_ENDPOINT_IP"] == "192.0.2.1"
    assert KEY not in (tmp_path / "x").as_posix() and not any(KEY in p.read_text() for p in tmp_path.rglob("*.yml"))
    assert launch_env(plan.composition)["WIREGUARD_ADDRESSES"] == "10.1.2.3/32"


def test_diagnose_reads_the_tun_counter():
    ctx = hook_ctx(settings={"register_hook": None})
    check = {"service": "gluetun"}
    assert "never answered" in HOOKS.diagnose(ctx, check, lambda s, a: (0, "0"))
    assert "passes traffic" in HOOKS.diagnose(ctx, check, lambda s, a: (0, "1234"))
    assert "no tunnel interface" in HOOKS.diagnose(ctx, check, lambda s, a: (1, ""))
    assert HOOKS.diagnose(ctx, {"service": "other"}, lambda s, a: (0, "0")) is None
