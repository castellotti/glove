"""`session.probe_http`: one throwaway curl container per probe; inside it,
curl is retried only while nothing answers yet (a fast refusal), never after a
timeout. The loop itself was run live against a refused, then answering, port."""

from __future__ import annotations

import subprocess

import pytest
from helpers import make_cfg

from glove import session
from glove.cafile import trust_script
from glove.plan import build_session_plan


@pytest.fixture
def plan(tmp_path):
    (tmp_path / "work").mkdir()
    cfg = make_cfg(harness="pi", workdir=str(tmp_path / "work"), name="s")
    return build_session_plan(cfg, home_dir=str(tmp_path / "h"), uid=501, gid=20)


def _run(monkeypatch, out, err=""):
    calls = []

    def run(cmd, **kw):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, out, err)
    monkeypatch.setattr(session.subprocess, "run", run)
    return calls


def test_an_answer_is_its_status_and_body(plan, monkeypatch):
    _run(monkeypatch, "200 0\n{}")
    assert session.probe_http("docker", plan, "http://x/v1/models") == (200, "{}")


def test_no_answer_is_status_0_with_curls_message(plan, monkeypatch):
    _run(monkeypatch, "000 28\n", "curl: (28) Operation timed out")
    assert session.probe_http("docker", plan, "http://x/") == (0, "curl: (28) Operation timed out")


def test_a_failed_probe_container_is_status_0(plan, monkeypatch):
    _run(monkeypatch, "", "docker: Error response from daemon")
    assert session.probe_http("docker", plan, "http://x/") == (0, "docker: Error response from daemon")


def test_one_container_retries_only_fast_failures_after_every_flag(plan, monkeypatch):
    calls = _run(monkeypatch, "200 0\n")
    session.probe_http("docker", plan, "http://x/", body={"a": 1}, headers={"anthropic-version": "2023-06-01"})
    assert len(calls) == 1
    assert not any("GLOVE_LLM_API_KEY" in a for a in calls[0])  # a probe holds no key
    script = calls[0][-1]
    assert "for w in 1 2 3 4 0;" in script and "case $rc in 6|7|52|56)" in script
    assert script.index("); rc=$?") > max(script.index("--data"), script.rindex("-H "))


def test_it_trusts_what_the_harness_trusts(plan, monkeypatch):
    from glove.extensions import Channel

    calls = _run(monkeypatch, "200 0\n")
    session.probe_http("docker", plan, "https://x/")
    assert "--cacert" not in calls[0][-1] and not any(":ro" in a for a in calls[0])  # the image's roots only
    plan.composition.channels += [Channel("c", "e", ("svc",), read_only=True, trust="ca.pem"),
                                  Channel("r", "e", ("svc",), read_only=True), Channel("w", "e", ("svc",))]
    plan.trusted_cas = plan.composition.trusted_cas()
    session.probe_http("docker", plan, "https://x/")
    cmd = calls[1]
    assert cmd[cmd.index("glove-s-chan-c:/run/glove/c:ro") - 1] == "-v"
    assert not any("chan-r" in a or "chan-w" in a for a in cmd)  # only a channel holding a CA
    script = cmd[-1]
    # the harness's bundle, built the same way (cafile.trust_script), into the probe's /tmp
    assert script.startswith(trust_script(["/run/glove/c/ca.pem"], dest="/tmp"))
    assert "curl --cacert /tmp/bundle.pem -sS " in script


def test_on_rootless_podman_it_runs_in_the_sessions_userns(tmp_path, monkeypatch):
    """A channel is owned by the session uid as keep-id maps it: a probe in the
    default rootless map can't read it (live: curl (60), the CA unread)."""
    from glove.runtimes import podman

    (tmp_path / "work").mkdir()
    cfg = make_cfg(harness="pi", workdir=str(tmp_path / "work"), name="s", runtime="podman", enforcer="nono")
    plan = build_session_plan(cfg, home_dir=str(tmp_path / "h"), uid=501, gid=20)
    monkeypatch.setattr(podman, "_host_info", lambda cli: {"rootless": "true"})
    calls = _run(monkeypatch, "200 0\n")
    session.probe_http("podman", plan, "https://x/")
    assert calls[0][calls[0].index("--userns") + 1] == "keep-id"
    session.probe_http("docker", plan, "https://x/")
    assert "--userns" not in calls[1]


def test_the_probe_relabels_gloves_own_ca_copies_where_binds_are_labelled(tmp_path, monkeypatch):
    # TODO 1f: on SELinux the probe may run before any sidecar relabelled .glove/trust/
    from helpers import PEM

    from glove.runtimes import podman

    (tmp_path / "work").mkdir()
    (tmp_path / "ca.pem").write_text(PEM)
    for runtime, suffix in (("podman", ":ro,z"), ("docker", ":ro")):
        cfg = make_cfg(harness="pi", workdir=str(tmp_path / "work"), name="s", runtime=runtime, enforcer="nono",
                       corporate_ca=str(tmp_path / "ca.pem"))
        plan = build_session_plan(cfg, home_dir=str(tmp_path / "h"), uid=501, gid=20)
        monkeypatch.setattr(podman, "_host_info", lambda cli: {"rootless": "true"})
        calls = _run(monkeypatch, "200 0\n")
        session.probe_http(runtime, plan, "https://x/")
        assert f"{plan.trust_host_dir}:/etc/glove/trust{suffix}" in calls[0]


def test_probe_direct_runs_a_hardened_curl_on_the_default_bridge(monkeypatch):
    """`glove check` asks before anything is up: not the harness network, no
    session user namespace, no retries, IPv4 as the forwarders dial."""
    from glove.verify import PROBE_IMAGE

    calls = _run(monkeypatch, "200 0\n{}")
    assert session.probe_direct("docker", "http://x/v1/models", headers={"v": "1"}) == (200, "{}")
    cmd = calls[0]
    assert cmd[cmd.index("--network") + 1] == "bridge" and "--add-host" not in cmd and "--userns" not in cmd
    assert cmd[cmd.index("--user") + 1] == "65534:65534" and "--cap-drop" in cmd and "--read-only" in cmd
    assert cmd[-3] == PROBE_IMAGE
    script = cmd[-1]
    assert "for w in 0;" in script and "curl -4 -sS -m 20 " in script and "-H 'v: 1'" in script


@pytest.mark.parametrize("url", ["http://127.0.0.1:11434/v1/models", "http://localhost:11434/v1/models"])
def test_probe_direct_reaches_this_machine_as_a_host_gateway_forwarder(monkeypatch, url):
    seen = []

    def run(cmd, **kw):
        seen.append((cmd, kw["env"]["U"]))
        return subprocess.CompletedProcess(cmd, 0, "200 0\n", "")
    monkeypatch.setattr(session.subprocess, "run", run)
    session.probe_direct("docker", url)
    cmd, dialled = seen[0]
    assert cmd[cmd.index("--add-host") + 1] == "host.docker.internal:host-gateway"
    assert dialled == "http://host.docker.internal:11434/v1/models"


def test_probe_direct_without_a_container_runtime_is_no_answer():
    status, text = session.probe_direct("apple-container", "http://x/")
    assert status == 0 and "not implemented" in text


def test_a_hung_probe_container_is_no_answer(monkeypatch):
    def run(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, kw["timeout"])
    monkeypatch.setattr(session.subprocess, "run", run)
    assert session.probe_direct("docker", "http://x/") == (0, "the probe container timed out")


def test_check_hands_a_hook_cores_probe_with_its_own_headers():
    """As at launch: the extension's `probe_headers` export (here an oauth
    block's beta header too), and nothing the hook chooses."""
    from glove.doctor import extension_checks

    asked = []

    def probe(url, method="GET", body=None, headers=None):
        asked.append(headers)
        return 401, ""
    checks = extension_checks({"llm": {"provider": "anthropic", "auth": "oauth", "api_key": "keychain:t",
                                       "model": "claude-x"}}, harness="claude-code", probe=probe)
    assert any(c.name == "llm server" and c.status == "ok" for c in checks), checks
    assert asked and all(h.get("anthropic-beta") and h.get("anthropic-version") for h in asked)
