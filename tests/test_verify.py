"""Core verify kinds (v3 M4) and the fail-closed sidecar start."""

from __future__ import annotations

import subprocess
from dataclasses import replace
from types import SimpleNamespace

import pytest
from helpers import make_cfg

from glove import session, verify
from glove.extensions import ExtensionError, launch_env, resolve_secrets, secret_env_var
from glove.plan import build_session_plan
from glove.verify import VerifyError, run_check, run_verify


def _plan(tmp_path, exts=None):
    cfg = make_cfg(name="s", workdir=str(tmp_path), extensions=exts or {"tor": {}})
    return build_session_plan(cfg, home_dir=str(tmp_path / "h"), state_dir=str(tmp_path / "x"))


def _quiet(_msg: str) -> None:
    pass


TOR = {"kind": "exit-confirmed", "source": "url", "url": "https://check.example/api/ip", "ip_field": "IP",
       "expect": {"IsTor": True}, "retries": 2}
GLUETUN = {"kind": "exit-confirmed", "source": "exec", "service": "gluetun", "argv": ["cat", "/tmp/gluetun/ip"],
           "retries": 2}


def _no_host_lookup(url):
    raise AssertionError(f"looked up the host's IP at {url} without host_check_url")


def test_exit_confirmed_from_a_url_through_the_egress_proxy(tmp_path, monkeypatch):
    plan = _plan(tmp_path)
    seen = {}

    def probe(provider, p, network, script, env, **kw):
        seen.update(network=network, **env)
        return 0, '{"IsTor":true,"IP":"198.51.100.7"}'

    monkeypatch.setattr(verify, "probe", probe)
    monkeypatch.setattr(verify, "host_public_ip", _no_host_lookup)
    out = run_check("docker", plan, "tor", TOR, _quiet, sleep_scale=0)
    assert out == "198.51.100.7 (via http://glove-s-privoxy:8118)"
    # probed from the egress network, through the slot's proxy
    assert seen == {"network": "egress", "U": "https://check.example/api/ip", "X": "http://glove-s-privoxy:8118"}


@pytest.mark.parametrize(("rc", "body", "match", "tries"), [
    # a JSON answer is final
    (0, '{"IsTor":false,"IP":"198.51.100.7"}', "NOT leaving through the egress", 1),
    (0, '{"IsTor":1,"IP":"198.51.100.7"}', "NOT leaving through the egress", 1),  # 1 is not true
    (0, '{"IP":"198.51.100.7"}', "NOT leaving through the egress", 1),
    (0, '{"IsTor":true,"IP":"<html>"}', "no IP address in 'IP'", 1),
    (0, '{"IsTor":true}', "no IP address in 'IP'", 1),
    # no answer, or not JSON (a fresh circuit's interstitial page): retried
    (0, "<html><body>blocked</body></html>", "did not answer JSON", 2),
    (0, "", "did not answer JSON", 2),
    (0, '["198.51.100.7"]', "did not answer JSON", 2),
    (7, "", "not passing traffic", 2),
])
def test_exit_confirmed_from_a_url_fails_closed(tmp_path, monkeypatch, rc, body, match, tries):
    plan = _plan(tmp_path)
    seen = []
    monkeypatch.setattr(verify, "probe", lambda *a, **k: seen.append(1) or (rc, body))
    with pytest.raises(VerifyError, match=match):
        run_check("docker", plan, "tor", TOR, _quiet, sleep_scale=0)
    assert len(seen) == tries


def test_exit_confirmed_from_a_url_retries_a_bad_answer(tmp_path, monkeypatch):
    plan = _plan(tmp_path)
    answers = iter([(0, "<html>connecting…</html>"), (0, '{"IsTor":true,"IP":"198.51.100.7"}')])
    monkeypatch.setattr(verify, "probe", lambda *a, **k: next(answers))
    assert run_check("docker", plan, "tor", TOR, _quiet, sleep_scale=0).startswith("198.51.100.7 ")


def _exec(monkeypatch, outs):
    calls, outs = [], iter(outs)

    def fake(cmd, **kw):
        calls.append(cmd)
        rc, out = next(outs)
        return SimpleNamespace(returncode=rc, stdout=out if isinstance(out, bytes) else out.encode(), stderr=b"")

    monkeypatch.setattr(verify.subprocess, "run", fake)
    return calls


def test_exit_confirmed_from_the_sidecar_retries_until_it_prints_an_ip(tmp_path, monkeypatch):
    plan = _plan(tmp_path, {"vpn": {"provider": "custom", "wireguard_key": "keychain:k"}})
    monkeypatch.setattr(verify, "host_public_ip", _no_host_lookup)
    calls = _exec(monkeypatch, [(0, ""), (0, "2001:db8::7\n")])  # gluetun's file is empty until its lookup
    out = run_check("docker", plan, "vpn", GLUETUN, _quiet, sleep_scale=0)
    assert out == "2001:db8::7 (from gluetun)"
    assert calls[-1] == ["docker", "exec", "glove-s-gluetun", "cat", "/tmp/gluetun/ip"]


@pytest.mark.parametrize("out", [
    (0, ""),                                   # an empty gluetun file: the tunnel is down
    (0, "198.51.100.7\n198.51.100.8\n"),       # two endpoints in the kill switch
    (0, "<html>secret-account-id</html>"),     # not an IP (and withheld)
    (0, "198.51.100.7:51820"),
    (1, "198.51.100.7"),                       # the command failed
    (0, b"\xff\xfesecret-account-id"),          # not UTF-8: still a VerifyError, still withheld
])
def test_exit_confirmed_from_the_sidecar_fails_closed(tmp_path, monkeypatch, out):
    plan = _plan(tmp_path, {"vpn": {"provider": "custom", "wireguard_key": "keychain:k"}})
    _exec(monkeypatch, [out, out])
    with pytest.raises(VerifyError, match=r"`cat /tmp/gluetun/ip` in gluetun did not print one IP address") as e:
        run_check("docker", plan, "vpn", GLUETUN, _quiet, sleep_scale=0)
    assert "secret-account-id" not in str(e.value) and e.value.service == "gluetun"


@pytest.mark.parametrize(("host", "seen", "match"), [
    ("203.0.113.1", "198.51.100.8", None),
    ("203.0.113.1", "203.0.113.1", "NOT going through the tunnel"),
    (None, "198.51.100.8", "cannot be ruled out"),       # no answer from the host, or not an IP
    ("203.0.113.1", "<html>", "named no IP address through the egress proxy"),
])
def test_host_check_url_is_opt_in_and_asks_from_both_sides(tmp_path, monkeypatch, host, seen, match):
    plan = _plan(tmp_path, {"vpn": {"provider": "custom", "wireguard_key": "keychain:k"}})
    _exec(monkeypatch, [(0, "198.51.100.7")])  # the endpoint: never compared with the host
    asked, probed = [], []
    monkeypatch.setattr(verify, "host_public_ip", lambda url: asked.append(url) or host)
    monkeypatch.setattr(verify, "probe", lambda p, pl, net, script, env, **k: probed.append(env) or (0, seen))
    item = {**GLUETUN, "host_check_url": "https://mine.example/ip"}
    if match:
        with pytest.raises(VerifyError, match=match):
            run_check("docker", plan, "vpn", item, _quiet, sleep_scale=0)
    else:
        assert run_check("docker", plan, "vpn", item, _quiet, sleep_scale=0) == (
            "198.51.100.7 (from gluetun); https://mine.example/ip: host 203.0.113.1 ≠ egress 198.51.100.8")
    assert asked == ["https://mine.example/ip"]
    assert probed in ([], [{"U": "https://mine.example/ip", "X": "http://glove-s-gluetun:8888"}])


@pytest.mark.parametrize(("body", "want"), [
    (b"203.0.113.1\n", "203.0.113.1"), (b" 2001:db8::1 ", "2001:db8::1"), (b"<html>", None), (b"", None),
])
def test_host_public_ip_must_be_an_ip(monkeypatch, body, want):
    import io

    monkeypatch.setattr(verify.urllib.request, "urlopen", lambda url, timeout: io.BytesIO(body))
    assert verify.host_public_ip("https://mine.example/ip") == want


def test_http_ok_and_tcp_open_retry_then_pass(tmp_path, monkeypatch):
    plan = _plan(tmp_path)
    answers = iter([(7, ""), (0, "200")])
    monkeypatch.setattr(verify, "probe", lambda *a, **k: next(answers))
    out = run_check("docker", plan, "x", {"kind": "http-ok", "url": "http://a/", "network": "egress"},
                    _quiet, sleep_scale=0)
    assert out == "http://a/ → HTTP 200"
    monkeypatch.setattr(verify, "probe", lambda *a, **k: (1, ""))
    with pytest.raises(VerifyError, match="not accepting connections"):
        run_check("docker", plan, "x", {"kind": "tcp-open", "host": "h", "port": 1, "retries": 2}, _quiet,
                  sleep_scale=0)


def test_container_healthy(tmp_path, monkeypatch):
    plan = _plan(tmp_path)
    states = iter(["starting", "healthy"])
    monkeypatch.setattr(verify, "_health", lambda rt, c: next(states))
    assert run_check("docker", plan, "vpn", {"kind": "container-healthy", "service": "gluetun", "timeout": 10},
                     _quiet, sleep_scale=0) == "glove-s-gluetun healthy"
    monkeypatch.setattr(verify, "_health", lambda rt, c: "none")
    with pytest.raises(VerifyError, match="no healthcheck"):
        run_check("docker", plan, "vpn", {"kind": "container-healthy", "service": "gluetun"}, _quiet, sleep_scale=0)


def test_exec_ok_runs_in_the_sidecar_and_withholds_its_output(tmp_path, monkeypatch):
    plan = _plan(tmp_path)
    calls = []

    def fake(cmd, **kw):
        calls.append(cmd)
        return SimpleNamespace(returncode=0 if cmd[-1] == "good" else 3, stdout=b"user@corp", stderr=b"")

    monkeypatch.setattr(verify.subprocess, "run", fake)
    item = {"kind": "exec-ok", "service": "relay", "argv": ["check", "good"]}
    assert run_check("docker", plan, "x", item, _quiet) == "relay: exit 0"
    assert calls[-1] == ["docker", "exec", "glove-s-relay", "check", "good"]
    with pytest.raises(VerifyError, match=r"`check bad` exited 3 in relay \(output withheld\)") as e:
        run_check("docker", plan, "x", {**item, "argv": ["check", "bad"]}, _quiet)
    assert "user@corp" not in str(e.value)


def test_a_warn_check_that_fails_lets_the_session_start(tmp_path, monkeypatch):
    plan = _plan(tmp_path)
    plan.composition.verify = [("x", {"name": "soft", "kind": "exec-ok", "service": "r", "argv": ["c"], "warn": True}),
                               ("x", {"name": "hard", "kind": "exec-ok", "service": "r", "argv": ["c"]})]
    monkeypatch.setattr(verify.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=1, stdout=b""))
    said: list[str] = []
    with pytest.raises(VerifyError, match="exited 1"):
        run_verify("docker", plan, said.append)
    assert any("⚠" in m and "a warning: the session starts anyway" in m for m in said)  # soft, then hard


def test_unknown_kind_is_refused_at_compose_time(tmp_path):
    from glove.extensions import Manifest, compose

    ext = tmp_path / "bad"
    ext.mkdir()
    (ext / "extension.yml").write_text("api: 1\nname: bad\nverify: [{name: x, kind: ping}]\n")
    from glove.extensions import discover

    manifests = {**discover(), "bad": Manifest("bad", ext, {"api": 1, "name": "bad",
                                                            "verify": [{"name": "x", "kind": "ping"}]})}
    with pytest.raises(ExtensionError, match="needs a kind"):
        compose({"llm": {"provider": "llama.cpp", "location": "host", "endpoint": "127.0.0.1:1", "model": "m"},
                 "bad": {}}, harness="pi", session="s", state_root=tmp_path, manifests=manifests)


def test_diagnose_hook_explains_a_failure(tmp_path, monkeypatch):
    plan = _plan(tmp_path, {"vpn": {"provider": "x", "wireguard_key": "keychain:k"}})
    monkeypatch.setattr(verify, "_health", lambda rt, c: "unhealthy")
    monkeypatch.setattr(verify.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=0, stdout=b"0\n"))
    monkeypatch.setattr(verify.time, "sleep", lambda s: None)
    with pytest.raises(VerifyError, match="never answered") as e:
        run_verify("docker", plan, _quiet)
    assert e.value.service == "gluetun"


# --- start_sidecars: recreate secret-using sidecars, fail closed ---------------------


def _compose_file(tmp_path, plan):
    from glove.runtimes.docker import DockerRuntime

    f = tmp_path / "compose.yml"
    f.write_text(DockerRuntime().render(plan, tmp_path).compose_yaml)
    return f


def test_secret_sidecars_are_recreated_and_verify_failure_stops_everything(tmp_path, monkeypatch):
    plan = _plan(tmp_path, {"vpn": {"provider": "x", "wireguard_key": "keychain:k"}})
    f = _compose_file(tmp_path, plan)
    calls = []

    def run(cmd, **kw):
        calls.append(cmd)
        return SimpleNamespace(returncode=0, stdout="WIREGUARD_PRIVATE_KEY: abc\nhandshake failed\n", stderr="")

    monkeypatch.setattr(session.subprocess, "run", run)

    def fail(*a, **k):
        raise VerifyError("tunnel down", service="gluetun")

    monkeypatch.setattr(verify, "run_verify", fail)
    with pytest.raises(VerifyError):
        session.start_sidecars(plan, f, provider="docker", env={})
    ups = [c for c in calls if "up" in c]
    assert ups[0][-2:] == ["--force-recreate", "glove-s-gluetun"]
    assert "glove-s-gluetun" in ups[1] and "--force-recreate" not in ups[1]
    assert ["docker", "logs", "--tail", "25", "glove-s-gluetun"] in calls
    assert calls[-1][-1] == "down"  # fail closed


def test_a_failed_up_on_a_subnet_a_foreign_network_took_is_subnet_taken(tmp_path, monkeypatch):
    from glove.runtimes.docker import DockerRuntime

    plan = _plan(tmp_path, {"vpn": {"provider": "x", "wireguard_key": "keychain:k"}})
    f = _compose_file(tmp_path, plan)
    calls = []

    def run(cmd, **kw):
        calls.append(cmd)
        if "up" in cmd:
            raise subprocess.CalledProcessError(1, cmd)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(session.subprocess, "run", run)
    mine = "172.31.5.0/27"
    plan.network = replace(plan.network, subnets={"net": mine})
    nets = {"glove-s-net": [mine], "unrelated": ["10.99.0.0/24"]}  # its own networks are no conflict
    monkeypatch.setattr(DockerRuntime, "network_subnets", lambda self: nets)
    with pytest.raises(subprocess.CalledProcessError):
        session.start_sidecars(plan, f, provider="docker", env={})
    nets["glove-other-net"] = [mine]
    with pytest.raises(session.SubnetTaken, match="glove-other-net"):
        session.start_sidecars(plan, f, provider="docker", env={})
    assert calls[-1][-1] == "down"  # stopped first, as any failed start


def test_redact_log_drops_credential_lines():
    text = "starting\n|   ├── Private key: aGV...GU=\npassword=x\nhandshake ok\n"
    assert session.redact_log(text) == "starting\nhandshake ok"


# --- launch_env guards -----------------------------------------------------------------


def _with_hook(tmp_path, monkeypatch, result):
    plan = _plan(tmp_path, {"vpn": {"provider": "x", "wireguard_key": "keychain:k"}})
    a = plan.composition.by_name("vpn")
    monkeypatch.setattr(a, "hooks", SimpleNamespace(launch_env=lambda ctx, resolve: result))
    return plan.composition


@pytest.mark.parametrize(("result", "match"), [
    ({"secrets": {"other": "x"}}, "undeclared secret"),
    ({"env": {"GLOVE_LLM_API_KEY": "x"}}, "bad env name"),
    ({"env": {"lower": "x"}}, "bad env name"),
])
def test_launch_env_rejects_what_the_extension_does_not_own(tmp_path, monkeypatch, result, match):
    with pytest.raises(ExtensionError, match=match):
        launch_env(_with_hook(tmp_path, monkeypatch, result))


def test_hook_provided_secret_wins_over_the_setting(tmp_path, monkeypatch):
    comp = _with_hook(tmp_path, monkeypatch, {"secrets": {"wireguard_private_key": "hooked"}})
    provided = launch_env(comp)
    var = secret_env_var("vpn-wireguard_private_key")
    # the keychain ref is never resolved when the hook provided the value
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("keychain read"))
    assert resolve_secrets(comp, provided=provided) == {var: "hooked"}


# --- http-refused (v3 M5: corporate's negative check) --------------------------------


@pytest.mark.parametrize(("answers", "ok", "match"), [
    ([(0, "403 000")], True, None),  # CONNECT refused by the proxy
    ([(0, "000 403")], True, None),  # a cleartext request refused
    ([(7, "000 000"), (0, "403 000")], True, None),  # proxy not up yet, then refuses
    ([(0, "200 200")], False, "let https://example.com/ through"),
    ([(7, "000 000"), (7, "000 000")], False, "did not answer"),
])
def test_http_refused(tmp_path, monkeypatch, answers, ok, match):
    plan = _plan(tmp_path)
    it = iter(answers)
    monkeypatch.setattr(verify, "probe", lambda *a, **k: next(it))
    item = {"kind": "http-refused", "url": "https://example.com/", "proxy": "http://p:8888", "retries": 2}
    if ok:
        assert run_check("docker", plan, "corporate", item, _quiet, sleep_scale=0) == \
            "https://example.com/ refused by http://p:8888"
    else:
        with pytest.raises(VerifyError, match=match):
            run_check("docker", plan, "corporate", item, _quiet, sleep_scale=0)


def test_a_failed_compose_up_stops_everything(tmp_path, monkeypatch):
    plan = _plan(tmp_path, {"tor": {}})
    f = _compose_file(tmp_path, plan)
    calls = []

    def run(cmd, **kw):
        calls.append((cmd, kw.get("env") or {}))
        if "up" in cmd:
            raise subprocess.CalledProcessError(1, cmd)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(session.subprocess, "run", run)
    with pytest.raises(subprocess.CalledProcessError):
        session.start_sidecars(plan, f, provider="podman", env={})
    assert calls[-1][0][-1] == "down"  # never a half-started egress stack
    ups = [c for c, _ in calls if "up" in c]
    assert len(ups[0]) == len(["podman", "compose", "-p", "x", "-f", "f", "up", "-d"]) + 1  # podman: one at a time
