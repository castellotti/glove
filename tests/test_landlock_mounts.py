"""The bind mode a Landlock-wrapped container needs (Docker Desktop's fakeowner layer)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from helpers import make_session
from typer.testing import CliRunner

from glove.cli import app
from glove.doctor import run_doctor
from glove.runtimes import landlock_mounts as lm
from glove.runtimes import podman
from glove.runtimes.docker import DockerRuntime
from glove.runtimes.podman import PodmanRuntime

OK = dict.fromkeys(("create", "write", "read", "list", "mmap", "lock", "rename", "link", "unlink"), "ok")
DENIED = {**OK, "create": "PermissionError: Permission denied", "read": "PermissionError: Permission denied"}


def report(native=None, virtiofs=None, *, abi=8, vfs_type="virtiofs.virtiofs0", control=OK):
    mounts = {}
    if native is not None:
        mounts["/glove-probe/native"] = {"fstype": "fakeowner", "control": control, "steps": native}
    if virtiofs is not None:
        mounts["/glove-probe/virtiofs"] = {"fstype": vfs_type, "control": OK, "steps": virtiofs}
    return {"abi": abi, "mounts": mounts}


@pytest.mark.parametrize(("rep", "mode"), [
    (report(OK), "native"),                       # Linux Docker, Podman
    (report(OK, DENIED), "native"),               # a fixed Docker Desktop: the normal path wins
    (report(DENIED, OK), "virtiofs"),             # Docker Desktop 4.96
    (report(DENIED, DENIED), "broken"),
    (report(DENIED), "broken"),                   # no virtiofs layer to fall back to
    (report(DENIED, OK, vfs_type="ext4"), "broken"),  # a made-up source is the VM's disk, not the share
    (report(OK, abi=0), "broken"),                # no Landlock at all
    (report(OK, abi=3), "broken"),                # below nono's floor (doctor's ABI check agrees)
    (report(DENIED, OK, control=DENIED), "unknown"),  # denied without Landlock too: not Landlock's failure
    ({"abi": 8, "mounts": {"/glove-probe/native": {"fstype": "x", "control": OK, "steps": {}}}}, "broken"),
])
def test_classify(rep, mode):
    assert lm.classify(rep).mode == mode


def test_classify_names_the_first_failing_step():
    assert lm.classify(report(DENIED, OK)).detail == (
        "normal path fakeowner: create PermissionError: Permission denied; virtiofs layer virtiofs.virtiofs0: ok")
    assert "fails without Landlock: create" in lm.classify(report(DENIED, control=DENIED)).detail


def test_enforcers_that_run_landlock():
    assert [e for e in ("none", "nono", "srt", "nono+srt") if lm.landlock_enforced(e)] == ["nono", "nono+srt"]


@pytest.fixture
def engine(monkeypatch, tmp_path):
    """A fake engine: `version` answers state["version"]; probes are counted."""
    state = {"version": "Docker Desktop 4.96.0 (1) 29.9.1 7.0", "mode": "virtiofs", "probes": 0}
    settings = tmp_path / "settings-store.json"
    settings.write_text("{}")
    monkeypatch.setattr(lm, "DESKTOP_SETTINGS", settings)
    monkeypatch.setattr(lm.shutil, "which", lambda c: f"/bin/{c}")
    monkeypatch.setattr(lm.subprocess, "run", lambda argv, **k: SimpleNamespace(
        returncode=0 if state["version"] else 1, stdout=state["version"] + "\n"))

    def probe(rt, desktop):
        state["probes"] += 1
        state["desktop"] = desktop
        return lm.MountMode(state["mode"], "d")

    monkeypatch.setattr(lm, "probe", probe)
    state["settings"] = settings
    return state


def test_mode_is_cached_per_engine_version_and_settings(engine, home):
    rt = DockerRuntime()
    assert lm.mount_mode(rt) == lm.MountMode("virtiofs", "d") and engine["desktop"]
    assert lm.mount_mode(rt).mode == "virtiofs" and engine["probes"] == 1
    cached = json.loads((home / "runtime-cache.json").read_text())["docker"]
    assert cached["key"].startswith("Docker Desktop 4.96.0") and "settings@" in cached["key"]
    engine["version"] = "Docker Desktop 4.97.0 (2) 29.9.2 7.0"  # an update re-probes
    lm.mount_mode(rt)
    assert engine["probes"] == 2
    os.utime(engine["settings"], ns=(1, 1))  # a settings change (restart) re-probes
    lm.mount_mode(rt)
    assert engine["probes"] == 3
    lm.mount_mode(rt, refresh=True)
    assert engine["probes"] == 4


@pytest.mark.parametrize("damaged", ["[1]", "{", '{"docker": "x"}', '{"docker": {"key": 1}}'])
def test_a_damaged_cache_is_a_miss(engine, home, damaged):
    home.mkdir()
    (home / "runtime-cache.json").write_text(damaged)
    assert lm.mount_mode(DockerRuntime()).mode == "virtiofs" and engine["probes"] == 1
    assert json.loads((home / "runtime-cache.json").read_text())["docker"]["mode"] == "virtiofs"


def test_a_failure_is_never_cached(engine, home):
    engine["mode"] = "broken"
    for _ in range(2):
        assert lm.mount_mode(DockerRuntime()).mode == "broken"
    assert engine["probes"] == 2 and not (home / "runtime-cache.json").exists()


def test_no_engine_is_unknown_and_not_probed(engine):
    engine["version"] = ""
    assert lm.mount_mode(DockerRuntime()).mode == "unknown" and engine["probes"] == 0


def test_probe_binds_both_layers_as_the_host_user_and_falls_back(monkeypatch, home):
    runs = []

    def run(argv, **k):
        runs.append(argv)
        if len(runs) == 1:  # the virtiofs layer moved: --mount refuses the source
            return SimpleNamespace(returncode=125, stdout="", stderr="bind source path does not exist")
        targets = argv[argv.index("/glove-probe.py") + 1:]
        assert targets == ["/glove-probe/native"]
        return SimpleNamespace(returncode=0, stdout=json.dumps(report(OK)), stderr="")

    monkeypatch.setattr(lm.subprocess, "run", run)
    assert lm.probe(DockerRuntime(), desktop=True).mode == "native"
    first = runs[0]
    mounts = [first[i + 1] for i, a in enumerate(first) if a == "--mount"]
    tmp = mounts[0].split(",")[1].removeprefix("source=")
    assert Path(tmp).parent == home and not Path(tmp).exists()  # removed afterwards
    assert mounts == [f"type=bind,source={tmp},target=/glove-probe/native",
                      f"type=bind,source=/run/host_virtiofs{os.path.realpath(tmp)},target=/glove-probe/virtiofs"]
    assert first[first.index("--user") + 1] == f"{os.getuid()}:{os.getgid()}"
    assert first[first.index("--cap-drop") + 1] == "ALL" and first[first.index("--network") + 1] == "none"
    assert f"{lm.PROBE_SCRIPT}:/glove-probe.py:ro" in first


def test_probe_failure_is_unknown(monkeypatch, home):
    monkeypatch.setattr(lm.subprocess, "run", lambda argv, **k: SimpleNamespace(returncode=1, stdout="", stderr="no"))
    assert lm.probe(DockerRuntime(), desktop=False) == lm.MountMode("unknown", "probe failed: no")


def test_podman_probes_in_keep_id(monkeypatch):
    monkeypatch.setattr(podman, "_host_info", lambda cli: {"rootless": "true"})
    argv = PodmanRuntime().throwaway_argv("img", [], as_host=True)
    assert argv[argv.index("--userns") + 1] == "keep-id"


def _mode(monkeypatch, mode):
    monkeypatch.setattr(DockerRuntime, "landlock_mounts",
                        lambda self, *, refresh=False: lm.MountMode(mode, "normal path fakeowner: read EACCES"))


@pytest.mark.parametrize(("enforcer", "refused"), [("nono", True), ("nono+srt", True), ("none", False)])
def test_a_broken_mode_refuses_a_nono_session(monkeypatch, home, tmp_path, enforcer, refused):
    _mode(monkeypatch, "broken")
    d = make_session(tmp_path / "s", f"enforcer: {enforcer}\n")
    result = CliRunner().invoke(app, ["plan", str(d)])
    assert (result.exit_code != 0) == refused, result.output
    if refused:
        assert "Landlock can't open files on a docker bind mount" in result.output
        assert "read EACCES" in result.output and not (d / ".glove" / "enforcer").exists()  # nothing written


def test_doctor_reports_the_mode_for_a_nono_enforcer(monkeypatch):
    monkeypatch.setattr(DockerRuntime, "doctor", lambda self: [])
    _mode(monkeypatch, "broken")
    by = {c.name: c for c in run_doctor(enforcer="nono")}
    assert by["landlock on a bind mount"].status == "fail"
    assert "refused" in by["landlock on a bind mount"].detail
    _mode(monkeypatch, "virtiofs")
    check = {c.name: c for c in run_doctor(enforcer="nono+srt")}["landlock on a bind mount"]
    assert check.status == "ok" and check.detail.startswith("virtiofs: ") and "fakeowner layer" in check.detail
    assert "landlock on a bind mount" not in {c.name for c in run_doctor(enforcer="none")}
    assert "landlock on a bind mount" not in {c.name for c in run_doctor(include_container_probes=False)}
