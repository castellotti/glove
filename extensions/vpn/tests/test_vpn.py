"""`vpn` (v3 M4): gluetun egress, compose secrets and the register hook."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml
from helpers import make_cfg, render

from glove.extensions import ExtensionError, launch_env, load_module, secret_env_var

HOOKS = load_module(Path(__file__).parents[1] / "hooks.py", "vpn")
KEY = "a" * 43 + "="


def _render(tmp_path, **settings):
    cfg = make_cfg(name="s", workdir=str(tmp_path), extensions={"vpn": settings}, subnet="172.31.7.0/24")
    plan, text = render(cfg, tmp_path)
    return plan, yaml.safe_load(text)


def test_gluetun_privileges_secret_and_firewall(tmp_path):
    plan, doc = _render(tmp_path, provider="mullvad", wireguard_key="keychain:wg", addresses="10.0.0.2/32")
    g = doc["services"]["glove-s-gluetun"]
    assert set(g["networks"]) == {"glove-s-egress", "glove-s-wan"}
    assert "user" not in g and g["read_only"] is False  # root + writable rootfs: declared privileges
    assert g["cap_add"] == ["NET_ADMIN"] and g["devices"] == ["/dev/net/tun:/dev/net/tun"]
    assert g["cap_drop"] == ["ALL"] and "no-new-privileges:true" in g["security_opt"]
    # gluetun's DNS server on :53, the gates' resolver: podman does not allow low ports by default
    assert g["sysctls"] == {"net.ipv4.ip_unprivileged_port_start": 0} and "NET_BIND_SERVICE" not in g["cap_add"]
    env = g["environment"]
    assert env["VPN_SERVICE_PROVIDER"] == "mullvad" and env["WIREGUARD_ADDRESSES"] == "10.0.0.2/32"
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
    assert [v["kind"] for _, v in plan.composition.verify] == ["container-healthy", "exit-ip-differs"]
    # stated in the fragment: podman drops the HEALTHCHECK of an OCI-manifest image
    assert g["healthcheck"]["test"] == ["CMD-SHELL", "/gluetun-entrypoint healthcheck"]


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
    ctx = {"settings": {"register_hook": "local/register.sh", "register_user": "keychain:u",
                        "register_pass": "keychain:p"}, "session_dir": session}
    out = HOOKS.launch_env(ctx, {"keychain:u": "alice", "keychain:p": "s3cret"}.__getitem__)
    assert out == {"secrets": {"wireguard_private_key": KEY},
                   "env": {"WIREGUARD_PUBLIC_KEY": "pub", "WIREGUARD_ENDPOINT_IP": "192.0.2.1",
                           "WIREGUARD_ENDPOINT_PORT": "1337", "WIREGUARD_ADDRESSES": "10.1.2.3/32"}}


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

    plan = build_session_plan(cfg, env_id="s", home_dir=str(tmp_path / "h"), state_dir=str(tmp_path / "x"),
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
    ctx = {"settings": {"register_hook": None}}
    check = {"service": "gluetun"}
    assert "never answered" in HOOKS.diagnose(ctx, check, lambda s, a: (0, "0"))
    assert "passes traffic" in HOOKS.diagnose(ctx, check, lambda s, a: (0, "1234"))
    assert "no tunnel interface" in HOOKS.diagnose(ctx, check, lambda s, a: (1, ""))
    assert HOOKS.diagnose(ctx, {"service": "other"}, lambda s, a: (0, "0")) is None
