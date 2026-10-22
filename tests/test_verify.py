"""Core verify kinds (v3 M4) and the fail-closed sidecar start."""

from __future__ import annotations

import subprocess
from dataclasses import replace
from types import SimpleNamespace

import pytest
from helpers import make_cfg

from glove import session, verify
from glove.config import ConfigError
from glove.extensions import ExtensionError, launch_env, resolve_secrets, secret_env_var
from glove.plan import build_session_plan
from glove.verify import VerifyError, run_check, run_verify


def _plan(tmp_path, exts=None):
    cfg = make_cfg(name="s", workdir=str(tmp_path), extensions=exts or {"tor": {}})
    return build_session_plan(cfg, home_dir=str(tmp_path / "h"), state_dir=str(tmp_path / "x"))


def _quiet(_msg: str) -> None:
    pass


VPN = {"vpn": {"provider": "custom", "wireguard_key": "keychain:k"}}
HOOK = {"name": "exit", "kind": "hook", "service": "gluetun", "argv": ["cat", "/x"], "retries": 2}


def _hooked(tmp_path, fn):
    plan = _plan(tmp_path, VPN)
    plan.composition.by_name("vpn").hooks["verify"] = fn
    return plan


def test_a_hook_check_gets_its_own_tools(tmp_path, monkeypatch):
    probed, execs = [], []
    monkeypatch.setattr(verify, "probe", lambda p, pl, net, script, env, **k: probed.append((net, env)) or (0, "ok"))
    monkeypatch.setattr(verify, "sidecar_exec", lambda p, s, svc, argv, t: execs.append((svc, argv)) or (0, "out"))
    tries = []

    def check(ctx, item, tools):
        assert ctx.name == "vpn" and item == HOOK and item is not HOOK  # a copy
        item.update(service="harness", argv=["id"])  # changes nothing it runs
        assert tools.fetch("https://a/") == (0, "ok") and tools.run() == (0, "out")
        assert tools.retry(lambda: tries.append(1) or (False, "no"), "x") == (False, "no")
        return f"fine via {tools.proxy}"

    assert run_check("docker", _hooked(tmp_path, check), "vpn", HOOK, _quiet, sleep_scale=0) == (
        "fine via http://glove-s-gluetun:8888")
    assert probed == [("egress", {"U": "https://a/", "X": "http://glove-s-gluetun:8888"})]
    assert execs == [("gluetun", ["cat", "/x"])]  # only its own argv in its own sidecar
    assert len(tries) == 2  # the check's `retries`


def _raise(e):
    def check(ctx, item, tools):
        raise e
    return check


@pytest.mark.parametrize(("fn", "match"), [
    (_raise(ConfigError("tunnel leaks")), r"^verify vpn/exit: tunnel leaks$"),
    (_raise(RuntimeError("a bug")), r"^verify vpn/exit: RuntimeError$"),  # a crash confirmed nothing
    (_raise(ValueError("secret-account-id")), r"^verify vpn/exit: ValueError$"),  # a parse bug: withheld
    (lambda ctx, item, tools: None, "confirmed nothing"),
    (lambda ctx, item, tools: "", "confirmed nothing"),
    (lambda ctx, item, tools: True, "want a one-line result"),
])
def test_a_hook_check_fails_closed(tmp_path, fn, match):
    with pytest.raises(VerifyError, match=match) as e:
        run_check("docker", _hooked(tmp_path, fn), "vpn", HOOK, _quiet, sleep_scale=0)
    assert e.value.service == "gluetun"


def test_a_hook_check_of_an_unselected_extension_fails(tmp_path):
    with pytest.raises(VerifyError, match="extension 'tor' is not selected"):
        run_check("docker", _plan(tmp_path, VPN), "tor", HOOK, _quiet, sleep_scale=0)


def test_a_hook_check_without_argv_runs_nothing(tmp_path):
    with pytest.raises(VerifyError, match="this check has no `argv`"):
        run_check("docker", _hooked(tmp_path, lambda ctx, item, tools: tools.run()), "vpn",
                  {"name": "exit", "kind": "hook"}, _quiet, sleep_scale=0)


def _sidecars(monkeypatch):
    calls = []
    monkeypatch.setattr(session.subprocess, "run",
                        lambda cmd, **kw: calls.append(cmd) or SimpleNamespace(returncode=0, stdout="", stderr=""))
    return calls


@pytest.mark.parametrize(("diagnose", "match"), [
    (_raise(RuntimeError("diagnose bug")), r"RuntimeError\n\(its diagnose hook failed: RuntimeError\('diagnose bug'\)"),
    (lambda ctx, check, run: "the handshake never completed", r"RuntimeError\nthe handshake never completed"),
])
def test_a_crashing_hook_check_stops_the_sidecars(tmp_path, monkeypatch, diagnose, match):
    plan = _hooked(tmp_path, _raise(RuntimeError("a bug")))
    plan.composition.by_name("vpn").hooks["diagnose"] = diagnose
    plan.composition.verify = [("vpn", HOOK)]
    f = _compose_file(tmp_path, plan)
    calls = _sidecars(monkeypatch)
    with pytest.raises(VerifyError, match=match):
        session.start_sidecars(plan, f, provider="docker", env={})
    assert [c[-2:] for c in calls[-2:]] == [["rm", "-fsv"], ["down", "--remove-orphans"]]  # fail closed


def test_any_failure_during_verify_stops_the_sidecars(tmp_path, monkeypatch):
    plan = _plan(tmp_path, VPN)
    f = _compose_file(tmp_path, plan)
    calls = _sidecars(monkeypatch)
    monkeypatch.setattr(verify, "run_verify", _raise(KeyboardInterrupt()))
    with pytest.raises(KeyboardInterrupt):
        session.start_sidecars(plan, f, provider="docker", env={})
    assert [c[-2:] for c in calls[-2:]] == [["rm", "-fsv"], ["down", "--remove-orphans"]]  # fail closed


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


def test_consecutive_exec_ok_checks_run_at_once_bounded_and_report_in_order(tmp_path, monkeypatch):
    import threading
    import time

    plan = _plan(tmp_path)
    n = verify.EXEC_POOL + 2
    plan.composition.verify = [("x", {"name": f"c{i}", "kind": "exec-ok", "service": "r", "argv": [str(i)],
                                      "warn": i == 1}) for i in range(n)]
    lock, running, peak = threading.Lock(), [0], [0]

    def slow(cmd, **kw):
        with lock:
            running[0] += 1
            peak[0] = max(peak[0], running[0])
        time.sleep(0.2)
        with lock:
            running[0] -= 1
        return SimpleNamespace(returncode=5 if cmd[-1] == "1" else 0, stdout=b"")

    monkeypatch.setattr(verify.subprocess, "run", slow)
    said: list[str] = []
    t0 = time.monotonic()
    run_verify("docker", plan, said.append)
    assert time.monotonic() - t0 < 0.2 * n / 2  # not one after another
    assert peak[0] == verify.EXEC_POOL  # bounded
    names = [m.split("/")[1].split(" ")[0] for m in said if m.startswith("  verify")]
    assert names == [f"c{i}" for i in range(n)]
    assert "⚠" in said[3] and "exited 5" in said[3]  # c1's warning, after c1's line


def test_a_failed_exec_ok_check_stops_the_launch_and_cancels_the_rest(tmp_path, monkeypatch):
    import time
    from concurrent.futures import ThreadPoolExecutor

    plan = _plan(tmp_path)
    monkeypatch.setattr(verify, "EXEC_POOL", 1)
    pool = ThreadPoolExecutor(1)
    monkeypatch.setattr(verify, "ThreadPoolExecutor", lambda n: pool)
    plan.composition.verify = [("x", {"name": f"c{i}", "kind": "exec-ok", "service": "r", "argv": [str(i)]})
                               for i in range(4)]
    ran: list[str] = []

    def fake(cmd, **kw):
        ran.append(cmd[-1])
        if cmd[-1] != "0":
            time.sleep(0.2)  # c1 is still running when c0's failure stops the launch
        return SimpleNamespace(returncode=1 if cmd[-1] == "0" else 0, stdout=b"")

    monkeypatch.setattr(verify.subprocess, "run", fake)
    with pytest.raises(VerifyError, match="c0"):
        run_verify("docker", plan, _quiet)
    pool.shutdown(wait=True)  # c1, if it started, ends on `fake`, not on the host's docker
    assert ran[0] == "0" and not {"2", "3"} & set(ran)  # still queued: never started


def test_unknown_kind_is_refused_at_compose_time(tmp_path):
    from glove.extensions import Manifest, compose

    ext = tmp_path / "bad"
    ext.mkdir()
    (ext / "extension.yml").write_text("api: 2\nname: bad\nverify: [{name: x, kind: ping}]\n")
    from glove.extensions import discover

    manifests = {**discover(), "bad": Manifest("bad", ext, {"api": 2, "name": "bad",
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
    assert [c[-2:] for c in calls[-2:]] == [["rm", "-fsv"], ["down", "--remove-orphans"]]  # fail closed


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
    assert calls[-1][-2:] == ["down", "--remove-orphans"]  # stopped first, as any failed start


def test_redact_log_drops_credential_lines():
    text = "starting\n|   ├── Private key: aGV...GU=\npassword=x\nhandshake ok\n"
    assert session.redact_log(text) == "starting\nhandshake ok"


# --- launch_env guards -----------------------------------------------------------------


def _with_hook(tmp_path, monkeypatch, result):
    plan = _plan(tmp_path, {"vpn": {"provider": "x", "wireguard_key": "keychain:k"}})
    a = plan.composition.by_name("vpn")
    monkeypatch.setattr(a, "hooks", {"launch_env": lambda ctx, resolve: result})
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
    assert [c[0][-2:] for c in calls[-2:]] == [["rm", "-fsv"], ["down", "--remove-orphans"]]  # never half-started
    ups = [c for c, _ in calls if "up" in c]
    up = ["podman", "compose", "-p", "x", "-f", "f", "up", "-d", "--remove-orphans"]
    assert len(ups[0]) == len(up) + 1  # podman: one at a time


def test_exec_ok_checks_of_two_extensions_never_overlap(tmp_path, monkeypatch):
    import threading
    import time

    plan = _plan(tmp_path)
    plan.composition.verify = [(ext, {"name": ext, "kind": "exec-ok", "service": "r", "argv": [ext]})
                               for ext in ("x", "y")]
    lock, running, peak = threading.Lock(), [0], [0]

    def slow(cmd, **kw):
        with lock:
            running[0] += 1
            peak[0] = max(peak[0], running[0])
        time.sleep(0.1)
        with lock:
            running[0] -= 1
        return SimpleNamespace(returncode=0, stdout=b"")

    monkeypatch.setattr(verify.subprocess, "run", slow)
    run_verify("docker", plan, _quiet)
    assert peak[0] == 1  # y's waits for x's, as before
