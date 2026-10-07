"""`session.probe_http`: one throwaway curl container per probe; inside it,
curl is retried only while nothing answers yet (a fast refusal), never after a
timeout. The loop itself was run live against a refused, then answering, port."""

from __future__ import annotations

import subprocess

import pytest
from helpers import make_cfg

from glove import session
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
    session.probe_http("docker", plan, "http://x/", body={"a": 1}, auth_env={"GLOVE_LLM_API_KEY": "k"},
                       headers={"anthropic-version": "2023-06-01"})
    assert len(calls) == 1
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
    plan.trusted_cas = plan.composition.trusted_cas
    session.probe_http("docker", plan, "https://x/")
    cmd = calls[1]
    assert cmd[cmd.index("glove-s-chan-c:/run/glove/c:ro") - 1] == "-v"
    assert not any("chan-r" in a or "chan-w" in a for a in cmd)  # only a channel holding a CA
    script = cmd[-1]
    assert script.startswith("cat /etc/ssl/certs/ca-certificates.crt /run/glove/c/ca.pem > /tmp/ca.pem")
    assert "curl --cacert /tmp/ca.pem -sS " in script
