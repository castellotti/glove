"""`ssh`: `ssh <host> <command>` relayed to a key-holding sidecar — the policy,
the hooks (hosts → endpoints, known_hosts, the key) and the rendered session."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml
from helpers import make_cfg, render

from glove.extensions import ExtensionError, load_module

HERE = Path(__file__).resolve().parent.parent
policy = load_module(HERE / "relay_policy.py", "ssh_relay_policy")
hooks = load_module(HERE / "hooks.py", "ssh_hooks")
Refused = policy.Refused
HOSTS = [{"name": "build", "to": "192.168.1.10:22", "user": "dev"},
         {"name": "nas", "to": "nas.lan:2222", "user": "admin"}]


class Req:
    def __init__(self, argv):
        self.argv = argv
        self.settings = {"hosts": [{**h, "forwarder": {"host": f"glove-s-ssh-{h['name']}", "port": 22}}
                                   for h in HOSTS]}


def ssh(*args):
    return policy.prepare(Req(["ssh", *args]), {})


def _opt(argv, key):
    return [argv[i + 1] for i, a in enumerate(argv[:-1]) if a == "-o" and argv[i + 1].startswith(key + "=")]


# --- the policy ----------------------------------------------------------------------


def test_a_command_to_a_named_host():
    argv = ssh("build", "uname", "-a")
    assert argv[0] == "ssh" and argv[-4:] == ["--", "glove-s-ssh-build", "uname", "-a"]
    assert argv[argv.index("-l") + 1] == "dev" and argv[argv.index("-p") + 1] == "22"
    assert argv[1:3] == ["-F", "/dev/null"]
    assert _opt(argv, "StrictHostKeyChecking") == ["StrictHostKeyChecking=yes"]
    assert _opt(argv, "HostKeyAlias") == ["HostKeyAlias=192.168.1.10"]
    for forced in ("ProxyCommand=none", "ForwardAgent=no", "ClearAllForwardings=yes", "PermitLocalCommand=no",
                   "RequestTTY=no", "ControlPath=none", "BatchMode=yes"):
        assert forced in argv


def test_a_host_off_port_22_is_looked_up_as_host_port():
    argv = ssh("admin@nas", "df")
    assert _opt(argv, "HostKeyAlias") == ["HostKeyAlias=[nas.lan]:2222"]
    assert argv[argv.index("-p") + 1] == "22"  # the forwarder listens on 22


def test_allowed_options_come_after_the_forced_ones():
    argv = ssh("-q", "-vv", "-o", "ConnectTimeout=5", "-oBatchMode=yes", "--", "build", "true")
    i = argv.index("ConnectTimeout=5")
    assert argv.index("StrictHostKeyChecking=yes") < i  # ssh keeps the first value for a key
    assert "-q" in argv and "-vv" in argv and "BatchMode=yes" in argv


@pytest.mark.parametrize("args,why", [
    (["-L", "8080:localhost:80", "build", "true"], "not relayed"),
    (["-R", "9000:localhost:22", "build", "true"], "not relayed"),
    (["-D", "1080", "build", "true"], "not relayed"),
    (["-J", "x", "build", "true"], "not relayed"),
    (["-W", "h:22", "build"], "not relayed"),
    (["-i", "/work/k", "build", "true"], "not relayed"),
    (["-vvvv", "build", "true"], "not relayed"),
    (["-F", "/work/cfg", "build", "true"], "not relayed"),
    (["-A", "build", "true"], "not relayed"),
    (["-t", "build", "true"], "not relayed"),
    (["-N", "build"], "not relayed"),
    (["-qL8080:h:80", "build", "true"], "not relayed"),
    (["-o", "ProxyCommand=sh -c x", "build", "true"], "not relayed"),
    (["-oProxyJump=x", "build", "true"], "not relayed"),
    (["-o", "LocalCommand=id", "build", "true"], "not relayed"),
    (["-o", "ConnectTimeout=5;id", "build", "true"], "not relayed"),
    (["-o"], "not relayed"),
    (["other", "true"], "not a host of this session"),
    (["root@build", "true"], "reached as dev"),
    (["build"], "runs a command"),
    ([], "name a host"),
])
def test_refused(args, why):
    with pytest.raises(Refused, match=why):
        ssh(*args)


def test_setup_loads_the_key_into_an_agent_only(monkeypatch, tmp_path):
    calls = []

    def fake_run(argv, **kw):
        calls.append((argv, kw.get("input")))
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(policy.subprocess, "run", fake_run)
    monkeypatch.setattr(policy, "_passwd", lambda: {"LD_PRELOAD": "x"})
    monkeypatch.setenv("RELAY_SSH_KEY", "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----")
    monkeypatch.setattr(policy.os, "makedirs", lambda *a, **k: None)
    env = policy.setup({})
    assert env["SSH_AUTH_SOCK"] == policy.AGENT and "RELAY_SSH_KEY" not in env
    assert calls[0][0][:1] == ["ssh-agent"] and calls[1][0] == ["ssh-add", "-q", "-"]
    assert calls[1][1].startswith(b"-----BEGIN") and calls[1][1].endswith(b"-----\n")


def test_the_key_may_be_base64_of_the_pem():
    import base64

    pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n"
    assert policy._key(base64.b64encode(pem.encode()).decode()) == pem.encode()
    with pytest.raises(SystemExit):
        policy._key("not a key!")


# --- hooks ------------------------------------------------------------------------------


def test_hosts_become_lan_endpoints_for_the_sidecar_only():
    eps = hooks.contribute({"settings": {"hosts": HOSTS, "known_hosts": "local/kh"}})["endpoints"]
    assert set(eps) == {"ssh-build", "ssh-nas"}
    assert eps["ssh-nas"] == {"harness": False, "port": 22,
                              "target": {"address": "nas.lan:2222", "via": "lan"},
                              "listen_networks": ["sshnet"],
                              "observe": {"tool": "ssh", "scope": "lan"}}


@pytest.mark.parametrize("bad,why", [
    ([], "at least one host"),
    ([{"name": "Build", "to": "h:22", "user": "u"}], "name must match"),
    ([{"name": "b", "to": "h", "user": "u"}], "<host>:<port>"),
    ([{"name": "b", "to": "h:99999", "user": "u"}], "<host>:<port>"),
    ([{"name": "b", "to": "h;id:22", "user": "u"}], "<host>:<port>"),
    ([{"name": "b", "to": "h:22", "user": "-oProxyCommand=x"}], "user must match"),
    ([{"name": "b", "to": "h:22"}], "want"),
    ([{"name": "b", "to": "h:22", "user": "u", "key": "x"}], "want"),
    ([{"name": "b", "to": "h:22", "user": "u"}, {"name": "b", "to": "i:22", "user": "u"}], "twice"),
    # `$` would admit a trailing newline; every pattern is fullmatch'd
    ([{"name": "b\n", "to": "h:22", "user": "u"}], "name must match"),
    ([{"name": "b", "to": "h\n:22", "user": "u"}], "<host>:<port>"),
    ([{"name": "b", "to": "h:22", "user": "u\n"}], "user must match"),
])
def test_bad_hosts(bad, why):
    with pytest.raises(ValueError, match=why):
        hooks.hosts({"hosts": bad})


def test_known_hosts_must_be_a_file_in_the_session_and_is_copied_to_state(tmp_path):
    (tmp_path / "local").mkdir()
    ctx = {"settings": {"hosts": HOSTS, "known_hosts": "local/kh"}, "session_dir": tmp_path,
           "state_dir": tmp_path / "state"}
    with pytest.raises(ValueError, match="not a file in the session directory"):
        hooks.contribute(ctx)
    (tmp_path / "local" / "kh").write_text("192.168.1.10 ssh-ed25519 AAAA\n")
    hooks.contribute(ctx)
    (tmp_path / "state").mkdir()
    hooks.materialize(ctx)
    assert (tmp_path / "state" / "known_hosts").read_text() == "192.168.1.10 ssh-ed25519 AAAA\n"
    (tmp_path / "out").write_text("x")
    with pytest.raises(ValueError, match="not a file in the session directory"):
        hooks.contribute({**ctx, "settings": {**ctx["settings"], "known_hosts": "local/../../out"}})


def test_launch_env_resolves_the_key_in_memory():
    assert hooks.launch_env({"settings": {"key": "keychain:x"}}, lambda r: "KEY\n") == {"env": {"RELAY_SSH_KEY": "KEY"}}
    with pytest.raises(ValueError, match="empty"):
        hooks.launch_env({"settings": {"key": "env:X"}}, lambda r: "")


# --- the session --------------------------------------------------------------------------

CC_LLM = {"provider": "anthropic-compatible", "location": "host", "endpoint": "127.0.0.1:8080", "model": "m"}


def _render(tmp_path, harness="claude-code", observe=False, enforcer=None):
    exts = {"ssh": {"key": "env:K", "hosts": HOSTS, "known_hosts": "local/kh"}, **({"observe": {}} if observe else {})}
    if harness == "claude-code":
        exts["llm"] = CC_LLM
    (tmp_path / "w").mkdir(exist_ok=True)
    cfg = make_cfg(harness=harness, name="s", workdir=str(tmp_path / "w"), extensions=exts,
                   **({"enforcer": enforcer} if enforcer else {}))
    plan, text = render(cfg, tmp_path)
    return plan, yaml.safe_load(text)


@pytest.mark.parametrize("observe", [False, True])
def test_the_relay_sidecar_and_its_forwarders(tmp_path, observe):
    plan, doc = _render(tmp_path, observe=observe)
    svc = doc["services"]["glove-s-ssh"]
    assert svc["read_only"] is True and svc["cap_drop"] == ["ALL"] and set(svc["networks"]) == {"glove-s-sshnet"}
    targets = {v["target"] for v in svc["volumes"]}
    assert "/work" not in targets and {"/opt/glove/ssh/known_hosts", "/run/glove/ssh"} <= targets
    assert svc["environment"]["RELAY_SSH_KEY"] is None
    assert svc["command"][2:] == ["--channel", "/run/glove/ssh", "--policy", "/opt/glove/ssh/relay_policy.py"]
    assert svc["healthcheck"]["test"] == ["CMD", "test", "-p", "/run/glove/ssh/door"]
    assert json.loads(svc["environment"]["RELAY_SETTINGS"]) == Req([]).settings  # each host with its forwarder
    assert "github/gh" not in plan.composition.privileges and "ssh/ssh" not in plan.composition.privileges
    for name, target in (("build", "192.168.1.10:22"), ("nas", "nas.lan:2222")):
        fwd = doc["services"][f"glove-s-ssh-{name}"]
        assert set(fwd["networks"]) == {"glove-s-lan", "glove-s-sshnet"}
        if observe:  # netgate checks each connection
            assert "--lan-only" in fwd["command"] and target in json.dumps(fwd["command"])
        else:  # socat's entrypoint checks once, at start
            assert fwd["entrypoint"] == ["/usr/local/bin/glove-lan-forward"]
            assert fwd["command"] == ["22", *target.split(":")]
    on_lan = [n for n, s in doc["services"].items() if "glove-s-lan" in (s.get("networks") or {})]
    assert sorted(on_lan) == ["glove-s-ssh-build", "glove-s-ssh-nas"]
    assert doc["networks"]["glove-s-lan"].get("internal") is not True
    h = doc["services"]["glove-s-harness"]
    assert list(h["networks"]) == ["glove-s-net"]
    assert {"type": "volume", "source": "glove-s-chan-ssh", "target": "/run/glove/ssh"} in h["volumes"]
    assert not any(s.harness for s in plan.network.sidecars if s.role.startswith("ssh-"))
    if observe:
        facts = {s.role: s.facts for s in plan.network.sidecars}
        assert facts["ssh-build"]["client"] == "ssh" and facts["ssh-build"]["scope"] == "lan"


@pytest.mark.parametrize("harness", ["claude-code", "pi", "vibe"])
def test_the_harness_gets_the_shim(tmp_path, harness):
    plan, _ = _render(tmp_path, harness=harness)
    assert "COPY ssh/ssh /usr/local/bin/ssh" in plan.derived_dockerfile
    assert "COPY relay/glove-relay /opt/glove/bin/glove-relay" in plan.derived_dockerfile
    assert "`build`, `nas`" in plan.composition.rendered_briefs()[-1][1]


@pytest.mark.parametrize("enforcer", ["nono", "nono+srt", "srt"])
def test_every_enforcer_grants_the_channel(tmp_path, enforcer):
    plan, _ = _render(tmp_path, enforcer=enforcer)
    if enforcer == "srt":
        assert "/run/glove/ssh" in json.loads(plan.policies["srt-settings.json"])["filesystem"]["allowWrite"]
    else:
        tool = json.loads(plan.policies["tool.json"])
        assert "/run/glove/ssh" in tool["filesystem"]["allow"] and tool["network"] == {"block": True}


def test_settings_are_required(tmp_path):
    with pytest.raises(ExtensionError, match="required"):
        cfg = make_cfg(harness="pi", name="s", workdir=str(tmp_path), extensions={"ssh": {"key": "env:K"}})
        from glove.plan import build_session_plan

        build_session_plan(cfg, home_dir=str(tmp_path / "h"), state_dir=str(tmp_path / "x"))


def test_the_shim_is_valid_bash():
    assert os.access(HERE / "shim" / "ssh", os.X_OK)
    subprocess.run(["bash", "-n", str(HERE / "shim" / "ssh")], check=True)
