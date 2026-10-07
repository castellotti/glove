"""`Runtime.throwaway_argv`: the one hardened throwaway container (probes and
checks), and every site that runs one goes through it."""

from __future__ import annotations

import subprocess

import pytest
from helpers import make_cfg

from glove.plan import build_session_plan
from glove.runtimes import podman
from glove.runtimes.docker import DockerRuntime
from glove.runtimes.podman import PodmanRuntime
from glove.runtimes.seccomp import default_profile_path

HARDENED = ("--rm", "no-new-privileges:true", "--read-only", "--pids-limit", "--memory")


def _flag(argv: list[str], name: str) -> str:
    return argv[argv.index(name) + 1]


def _hardened(argv: list[str]) -> bool:
    return all(f in argv for f in HARDENED) and _flag(argv, "--cap-drop") == "ALL" and \
        _flag(argv, "--tmpfs") == "/tmp" and _flag(argv, "--user") != "0" and "--privileged" not in argv


@pytest.fixture
def plan(tmp_path):
    (tmp_path / "work").mkdir()
    cfg = make_cfg(harness="pi", workdir=str(tmp_path / "work"), name="s", runtime="podman", enforcer="nono")
    return build_session_plan(cfg, home_dir=str(tmp_path / "h"), uid=501, gid=20)


def test_docker_defaults_are_the_tightest(plan):
    argv = DockerRuntime().throwaway_argv("img", ["echo", "x"], env=("A",), mounts=[("/h/ca.pem", "/c/ca.pem")])
    assert argv[:3] == ["docker", "run", "--rm"] and argv[-3:] == ["img", "echo", "x"]
    assert _hardened(argv)
    assert _flag(argv, "--network") == "none" and _flag(argv, "--user") == "65534:65534"
    assert f"seccomp={default_profile_path()}" in argv and "--userns" not in argv
    assert _flag(argv, "-e") == "A"  # a name only: the value never in an argv
    assert _flag(argv, "-v") == "/h/ca.pem:/c/ca.pem:ro"
    argv = DockerRuntime().throwaway_argv("img", [], plan=plan, seccomp="/p/nested.json", entrypoint="sh")
    assert "seccomp=/p/nested.json" in argv and "--userns" not in argv and _flag(argv, "--entrypoint") == "sh"
    assert _flag(argv, "--user") == "501:20"  # with a plan: as the harness


def test_podman_runs_in_the_sessions_userns_and_never_relabels(plan, monkeypatch):
    monkeypatch.setattr(podman, "_host_info", lambda cli: {"rootless": "true"})
    rt = PodmanRuntime()
    argv = rt.throwaway_argv("img", [], plan=plan, mounts=[("/h/ca.pem", "/c/ca.pem"), ("vol", "/v")])
    assert argv[0] == "podman" and _hardened(argv)
    assert _flag(argv, "--userns") == "keep-id"
    assert not any(a.startswith("seccomp=") for a in argv)  # podman's built-in default (moby's)
    assert "/h/ca.pem:/c/ca.pem:ro" in argv and "vol:/v:ro" in argv  # a probe never relabels a host file
    assert "--userns" not in rt.throwaway_argv("img", [])  # no plan: the runtime's own map
    assert "seccomp=/p/nested.json" in rt.throwaway_argv("img", [], seccomp="/p/nested.json")


def test_every_throwaway_site_is_hardened(plan, monkeypatch):
    from glove import session, verify
    from glove.enforcers import srt

    calls = []

    def run(cmd, **kw):  # one subprocess module: answer each site in its own words
        calls.append(cmd)
        entry = _flag(cmd, "--entrypoint") if "--entrypoint" in cmd else None
        if cmd[1] == "images":
            out = "glove/pi:1-srt-x"
        elif entry == "sh":
            out = "200 0\n"
        elif entry == "bwrap":
            out = "OK"
        else:  # the landlock probe
            out = '{"landlock_abi": 6}'
        return subprocess.CompletedProcess(cmd, 0, out, "")
    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr("glove.enforcers.base.srt_suffix", lambda: "-srt-x")
    monkeypatch.setattr(srt.shutil, "which", lambda c: "/bin/" + c)

    session.probe_http("docker", plan, "http://x/")
    verify.probe("docker", plan, "egress", "true", {"U": "u"})
    assert DockerRuntime()._landlock_check().status == "ok"
    assert srt.SrtEnforcer()._bwrap_smoke(DockerRuntime()).status == "ok"
    runs = [c for c in calls if c[1] == "run"]
    assert len(runs) == 4 and all(_hardened(c) for c in runs)
    assert [_flag(c, "--network") for c in runs] == ["glove-s-net", "glove-s-egress", "none", "none"]
    assert [_flag(c, "--user") for c in runs] == ["501:20", "501:20", "65534:65534", "1000:1000"]
    assert _flag(runs[3], "--entrypoint") == "bwrap" and any("nested-userns" in a for a in runs[3])
