"""`glove clean`: glove's stacks on a runtime, found by compose's project label."""

import os
import subprocess
from datetime import UTC, datetime, timedelta

import pytest
import typer
from typer.testing import CliRunner

from glove import registry as reg
from glove.cli import COMMANDS_DIR
from glove.extensions import load_module

cli = load_module(COMMANDS_DIR / "clean" / "cli.py", "clean", ns="glove_cmd")
app = typer.Typer()
app.command()(cli.command)
runner = CliRunner()
LABEL = cli.PROJECT_LABEL


def _fake_runtime(monkeypatch, listing: dict[str, list[str]], *, fail: str = ""):
    """`_out` answering `<kind> inspect` from `listing` (kind → inspect lines)."""
    calls = []

    def out(rt, *args, partial=False):
        calls.append(args)
        if fail and fail in args:
            return None
        if "inspect" in args:
            return listing[args[0]]
        kind = "container" if args[0] == "ps" else args[0]
        return [f"{kind}-id"] if listing[kind] else []

    monkeypatch.setattr(cli, "_out", out)
    return calls


def test_stacks_groups_glove_v3_projects_and_skips_the_rest(monkeypatch):
    calls = _fake_runtime(monkeypatch, {
        "container": ["glove-a-0a0b0c|c1|created|0001-01-01T00:00:00Z|0001-01-01T00:00:00Z",
                      "glove-a-0a0b0c|c2|exited|2026-10-01 06:00:00.1 +0000 UTC|2026-10-02 06:00:00.1 +0000 UTC",
                      "open-webui|c3|running|2026-10-19T00:00:00Z|0001-01-01T00:00:00Z",
                      "glove-pi-search|x|running||"],  # not a v3 id: never glove v3's
        "network": ["glove-a-0a0b0c|glove-a-0a0b0c-net"],
        "volume": ["glove-b-0d0e0f|glove-b-0d0e0f-data", "open-webui_data|x"]})
    a, b = cli.stacks("podman")
    assert (a.sid, a.containers, a.networks, a.active) == ("a-0a0b0c", {"c1": "created", "c2": "exited"},
                                                           ["glove-a-0a0b0c-net"], True)
    assert a.ran == datetime(2026, 10, 2, 6, tzinfo=UTC) and b.ran is None
    assert (b.sid, b.volumes, b.active, b.describe()) == ("b-0d0e0f", ["glove-b-0d0e0f-data"], False, "1 volume(s)")
    assert ("ps", "-aq", "--filter", f"label={LABEL}") in calls
    assert ("container", "inspect", "-f", f'{{{{index .Config.Labels "{LABEL}"}}}}|{{{{.Id}}}}|{{{{.State.Status}}}}'
            "|{{.State.StartedAt}}|{{.State.FinishedAt}}", "container-id") in calls


def test_stacks_is_none_when_the_runtime_does_not_answer(monkeypatch):
    _fake_runtime(monkeypatch, {"container": [], "network": [], "volume": []}, fail="volume")
    assert cli.stacks("docker") is None


def test_stacks_keeps_what_an_inspect_printed_when_one_id_went_meanwhile(monkeypatch):
    monkeypatch.setattr(cli.subprocess, "run", lambda cmd, **k: subprocess.CompletedProcess(
        cmd, 1, stdout="glove-a-0a0b0c|n1\n", stderr="No such network: n-gone") if "inspect" in cmd
        else subprocess.CompletedProcess(cmd, 0 if "ls" in cmd else 1, stdout="n1\nn-gone\n"))
    assert cli._labelled("docker", "network", ".Labels", ".Name") == [["glove-a-0a0b0c", "n1"]]
    assert cli._out("docker", "network", "rm", "n1") is None  # a plain failure is still one


def test_stacks_with_nothing_labelled_inspects_nothing(monkeypatch):
    calls = _fake_runtime(monkeypatch, {"container": [], "network": [], "volume": []})
    assert cli.stacks("docker") == []
    assert not [c for c in calls if "inspect" in c]


@pytest.mark.parametrize("volumes", [True, False])
def test_remove_takes_containers_then_networks_and_volumes_only_when_asked(monkeypatch, volumes):
    cmds = []
    def run(cmd, **k):
        cmds.append(cmd)
        assert k["timeout"] == cli.TIMEOUT
        if cmd[-1] == "v1":
            raise subprocess.TimeoutExpired(cmd, k["timeout"])
        return subprocess.CompletedProcess(cmd, 1 if cmd[-1] == "n2" else 0)

    monkeypatch.setattr(cli.subprocess, "run", run)
    s = cli.Stack("docker", "a-0a0b0c", {"c1": "exited"}, ["n1", "n2"], ["v1"])
    assert cli.remove(s, volumes=volumes) == ["docker network n2", *(["docker volume v1"] if volumes else [])]
    assert cmds == [["docker", "rm", "-v", "c1"], ["docker", "network", "rm", "n1"], ["docker", "network", "rm", "n2"],
                    *([["docker", "volume", "rm", "v1"]] if volumes else [])]


def test_runtimes_are_the_named_one_or_those_on_path(monkeypatch):
    monkeypatch.setattr(cli.shutil, "which", lambda c: c == "podman")
    assert cli.runtimes() == ["podman"]
    assert cli.runtimes("docker") == ["docker"]


def _session(tmp_path, name: str, sid: str, *, holds: str | None = None) -> None:
    """A registry row for `sid`; its directory holds `holds` (None: no directory)."""
    d = tmp_path / name
    if holds:
        (d / ".glove").mkdir(parents=True)
        (d / ".glove" / "id").write_text(holds)
    reg.upsert(reg.SessionEntry(id=sid, dir=str(d), harness="pi"))


@pytest.mark.parametrize("flag", [False, True])
def test_clean_removes_volumes_only_of_provably_gone_sessions(home, tmp_path, monkeypatch, flag):
    _session(tmp_path, "live", "live-0a0a0a", holds="live-0a0a0a")
    _session(tmp_path, "moved", "moved-0b0b0b")  # its directory is missing: maybe moved
    _session(tmp_path, "reused", "reused-0c0c0c", holds="reused-0d0d0d")  # re-launched under a new id
    found = [cli.Stack("docker", "live-0a0a0a", {"c1": "exited"}, ["n1"], ["v1"]),
             cli.Stack("docker", "moved-0b0b0b", {"c2": "exited"}, ["n2"], ["v2"]),
             cli.Stack("docker", "reused-0c0c0c", volumes=["v3"]),
             cli.Stack("docker", "other-home-0e0e0e", volumes=["v4"]),
             cli.Stack("docker", "starting-0f0f0f", {"c5": "created"}, volumes=["v5"])]
    removed = []
    monkeypatch.setattr(cli, "runtimes", lambda only=None: ["docker"])
    monkeypatch.setattr(cli, "stacks", lambda rt: found)
    monkeypatch.setattr(cli, "remove", lambda s, volumes: removed.append((s.sid, volumes)) or [])
    monkeypatch.setattr(cli, "disk", lambda rt: None)  # not the host's `docker system df`
    args = ["--volumes"] if flag else []
    result = runner.invoke(app, ["--dry-run", *args])
    assert result.exit_code == 0 and not removed
    out = result.output
    assert "glove-starting-0f0f0f is active: left alone" in out and "glove-live-0a0a0a" not in out
    if flag:
        assert "docker stack glove-moved-0b0b0b: 1 container(s), 1 network(s), 1 volume(s)" in out
        assert "keeping" not in out
    else:
        assert "docker stack glove-moved-0b0b0b: 1 container(s), 1 network(s)\n" in out
        assert "keeping docker glove-moved-0b0b0b's 1 volume(s): its directory is missing (moved?)" in out
        assert "keeping docker glove-other-home-0e0e0e's 1 volume(s): not in this registry" in out
    result = runner.invoke(app, ["-y", *args])
    assert result.exit_code == 0, result.output
    assert removed == [("moved-0b0b0b", flag), ("reused-0c0c0c", True),
                       *([("other-home-0e0e0e", True)] if flag else [])]


def test_clean_asks_first(home, monkeypatch):
    monkeypatch.setattr(cli, "runtimes", lambda only=None: ["docker"])
    monkeypatch.setattr(cli, "stacks", lambda rt: [cli.Stack("docker", "gone-0b0b0b", {"c": "exited"})])
    monkeypatch.setattr(cli, "remove", lambda s, volumes: pytest.fail("removed without asking"))
    assert runner.invoke(app, [], input="n\n").exit_code == 1


def test_clean_warns_when_a_runtime_does_not_answer_and_refuses_unknown_ones(home, monkeypatch):
    monkeypatch.setattr(cli, "stacks", lambda rt: None)
    result = runner.invoke(app, ["--runtime", "podman"])
    assert result.exit_code == 0 and "podman did not answer" in result.output and "nothing to clean" in result.output
    assert runner.invoke(app, ["--runtime", "lxc"]).exit_code == 1


def test_clean_refuses_an_unreadable_registry(home, tmp_path):
    (tmp_path / "ghome").mkdir()
    (tmp_path / "ghome" / "registry.json").write_text("[]")  # not a v3 registry
    result = runner.invoke(app, ["--runtime", "docker"])
    assert result.exit_code == 1 and "unsupported registry version" in result.output


def test_glove_mounts_it():
    from glove.cli import app as glove

    assert "--dry-run" in runner.invoke(glove, ["clean", "--help"]).output


# --- <age> ----------------------------------------------------------------------------

def test_age_is_hours_days_or_weeks_and_build_cache_needs_one(home):
    assert [cli.parse_age(a) for a in ("12h", "3d", "2w", "1h")] == [12, 72, 336, 1]
    for bad in ("3", "3 d", "-1d", "1y", "d", "0h", "0d", "99999999999999w"):
        assert runner.invoke(app, ["--", bad]).exit_code == 1
    result = runner.invoke(app, ["--build-cache"])
    assert result.exit_code == 1 and "needs an AGE" in result.output


def test_when_reads_docker_podman_and_registry_times():
    want = datetime(2026, 10, 19, 6, 44, 54, tzinfo=UTC)
    assert cli._when("2026-10-19T06:44:54.558174589Z") == want
    assert cli._when("2026-10-19 06:44:54.805380182 +0000 UTC") == want
    assert cli._when("2026-10-19T08:44:54+02:00") == want
    assert cli._when("2026-10-19T06:44:54") == want  # naive: UTC
    assert cli._when("") is None and cli._when("yesterday") is None and cli._when(None) is None


def _entry(tmp_path, sid: str, *, images: list[str] | None = (), mtime: datetime | None = None,
           created: str | None = None):
    d = tmp_path / sid
    if mtime is not None:
        f = d / ".glove" / "compose.yml"
        f.parent.mkdir(parents=True)
        f.write_text("services:\n" + "".join(f"  s{i}:\n    image: {t}\n" for i, t in enumerate(images))
                     if images is not None else "{not yaml")
        os.utime(f, (mtime.timestamp(), mtime.timestamp()))
    return reg.SessionEntry(id=sid, dir=str(d), harness="pi", created=created)


def test_last_uses_are_the_compose_files_mtime_else_the_rows_created(tmp_path):
    old, new = datetime(2026, 10, 1, tzinfo=UTC), datetime(2026, 10, 15, tzinfo=UTC)
    images, sessions = cli.last_uses([
        _entry(tmp_path, "a-0a0a0a", images=["glove/pi:1-x", "docker.io/valkey:9", "'glove/gate:g'"], mtime=old),
        _entry(tmp_path, "b-0b0b0b", images=["glove/gate:g"], mtime=new),
        _entry(tmp_path, "c-0c0c0c", created="2026-09-01T00:00:00Z"),
        _entry(tmp_path, "d-0d0d0d"),
        _entry(tmp_path, "e-0e0e0e", images=None, mtime=new, created="2026-09-02T00:00:00Z")])  # unreadable
    assert images == {"glove/pi:1-x": old, "glove/gate:g": new}
    assert sessions == {"a-0a0a0a": old, "b-0b0b0b": new, "c-0c0c0c": datetime(2026, 9, 1, tzinfo=UTC),
                        "e-0e0e0e": datetime(2026, 9, 2, tzinfo=UTC)}


def test_the_compose_file_it_reads_is_the_sessions(tmp_path):
    from glove.sessiondir import SessionDir

    assert SessionDir(tmp_path).compose == tmp_path / ".glove" / "compose.yml"


def _fake_images(monkeypatch, images: list[str], containers: list[str]):
    def out(rt, *args, partial=False):
        if args[:2] == ("image", "ls"):
            assert args[-1] == "reference=glove/*"
            return [r.split("|")[0] for r in images]
        if args[0] == "ps":
            return [c.split("|")[0] for c in containers]
        return images if args[0] == "image" else containers
    monkeypatch.setattr(cli, "_out", out)


def test_unused_images_spare_the_used_the_recent_and_what_kept_ones_were_built_from(monkeypatch):
    cutoff = datetime(2026, 10, 10, tzinfo=UTC)
    long_ago = "2026-10-01T00:00:00Z"
    _fake_images(monkeypatch, [
        f"i0|{long_ago}|glove/pi:1|L0",  # under both i1 and i3: i1 is kept
        f"i1|{long_ago}|glove/pi:1-srt-s other/pi:latest|L0 L1",  # i2 was built from it
        f"i2|{long_ago}|glove/pi:1-aa-srt-s glove/pi:1-aa|L0 L1 L2",  # one tag recently used
        f"i3|{long_ago}|glove/pi:1-bb|L0 L9",  # old: goes
        f"i4|{long_ago}|glove/pi:1-cc|L4",  # a container uses it
        f"i5|{long_ago}|glove/pi:1-dd|L5",  # only a container that goes uses it
        f"i6|{long_ago}|glove/pi:1-ee|L6",  # a container that goes ran it recently
        "i7|2026-10-12 00:00:00 +0000 UTC|localhost/glove/vibe:2|V1",  # recent (Podman)
        "i8|2026-10-01 00:00:00 +0000 UTC|localhost/glove/vibe:1|V0",  # old (Podman)
        "i9|garbled|glove/vibe:0|V9",  # unreadable: kept
    ], ["c1|i4|2026-09-01T00:00:00Z|2026-09-02T00:00:00Z",
        "c2|i5|0001-01-01T00:00:00Z|0001-01-01T00:00:00Z",
        "c3|i6|2026-09-01 00:00:00 +0000 UTC|2026-10-11 00:00:00.5 +0000 UTC"])
    used = {"glove/pi:1-aa-srt-s": datetime(2026, 10, 15, tzinfo=UTC),
            "glove/pi:1-bb": datetime(2026, 10, 2, tzinfo=UTC)}
    old = cli.unused_images("podman", cutoff, used, leaving={"c2", "c3"})
    assert [(i.ref, i.tag) for i in old] == [("glove/pi:1-bb", "glove/pi:1-bb"), ("glove/pi:1-dd", "glove/pi:1-dd"),
                                             ("localhost/glove/vibe:1", "glove/vibe:1")]
    assert old[0].last == used["glove/pi:1-bb"]


def test_unused_images_is_none_when_the_runtime_does_not_answer(monkeypatch):
    monkeypatch.setattr(cli, "_out", lambda rt, *a, partial=False: None if a[0] == "ps" else [])
    assert cli.unused_images("docker", datetime.now(UTC), {}, set()) is None


def test_disk_sums_system_df(monkeypatch):
    monkeypatch.setattr(cli, "_out", lambda rt, *a, partial=False: ["100.7GB", "491.5kB", "0B", "1.5 MB", "?"])
    assert cli.disk("docker") == pytest.approx(100.7e9 + 491.5e3 + 1.5e6)
    monkeypatch.setattr(cli, "_out", lambda rt, *a, partial=False: None)
    assert cli.disk("docker") is None


def test_clean_with_an_age_takes_idle_stacks_old_images_and_the_build_cache(home, tmp_path, monkeypatch):
    long_ago = datetime.now(UTC) - timedelta(days=30)
    for sid in ("idle-0a0a0a", "busy-0b0b0b", "fresh-0c0c0c"):
        _session(tmp_path, sid, sid, holds=sid)
        f = tmp_path / sid / ".glove" / "compose.yml"
        f.write_text("services:\n  h:\n    image: glove/pi:1\n")
        if sid != "fresh-0c0c0c":
            os.utime(f, (long_ago.timestamp(), long_ago.timestamp()))
    found = {"docker": [cli.Stack("docker", "idle-0a0a0a", {"c1": "exited"}, ["n1"], ["v1"]),
                        cli.Stack("docker", "busy-0b0b0b", {"c2": "running"}),
                        cli.Stack("docker", "fresh-0c0c0c", {"c3": "exited"})],
             "podman": []}
    images = {rt: [cli.Image(rt, f"glove/{rt}:1", long_ago)] for rt in found}
    monkeypatch.setattr(cli, "runtimes", lambda only=None: ["docker", "podman"])
    monkeypatch.setattr(cli, "stacks", lambda rt: found[rt])
    monkeypatch.setattr(cli, "unused_images", lambda rt, cutoff, used, leaving: (
        leaving == ({"c1"} if rt == "docker" else set()) or pytest.fail(leaving)) and images[rt])
    sizes = iter([10e9, 6e9, 1e9, 1e9])  # before: docker, podman; after: docker, podman
    monkeypatch.setattr(cli, "disk", lambda rt: next(sizes))
    removed, cmds = [], []
    monkeypatch.setattr(cli, "remove", lambda s, volumes: removed.append((s.sid, volumes)) or [])
    monkeypatch.setattr(cli, "_ok", lambda cmd, timeout=cli.TIMEOUT: cmds.append((cmd, timeout)) or "podman" not in cmd)

    result = runner.invoke(app, ["7d", "--dry-run", "--build-cache"])
    out = result.output
    assert result.exit_code == 0 and not removed and not cmds
    assert "docker stack glove-idle-0a0a0a: 1 container(s), 1 network(s) (idle: its volumes stay)" in out
    assert "busy" not in out and "fresh" not in out
    assert "docker image glove/docker:1" in out and "podman image glove/podman:1" in out
    assert "docker build cache unused for 7d (machine-wide" in out and "podman build cache" not in out

    result = runner.invoke(app, ["7d", "-y", "--build-cache"])
    assert result.exit_code == 0, result.output
    assert removed == [("idle-0a0a0a", False)]
    assert cmds == [(["docker", "rmi", "glove/docker:1"], cli.TIMEOUT),
                    (["podman", "rmi", "glove/podman:1"], cli.TIMEOUT),
                    (["docker", "builder", "prune", "-f", "--filter", "until=168h"], cli.PRUNE_TIMEOUT)]
    assert "could not remove podman image glove/podman:1" in result.output
    assert "removed 1 stack(s), 1 image(s); reclaimed 9.0 GB on docker, 5.0 GB on podman" in result.output


def test_clean_without_an_age_leaves_idle_sessions_and_images(home, tmp_path, monkeypatch):
    _session(tmp_path, "idle", "idle-0a0a0a", holds="idle-0a0a0a")
    monkeypatch.setattr(cli, "runtimes", lambda only=None: ["docker"])
    monkeypatch.setattr(cli, "stacks", lambda rt: [cli.Stack("docker", "idle-0a0a0a", {"c1": "exited"})])
    monkeypatch.setattr(cli, "unused_images", lambda *a: pytest.fail("images looked at without an AGE"))
    assert "nothing to clean" in runner.invoke(app, ["--dry-run"]).output


def test_clean_counts_what_it_removed_and_measures_only_where_it_removed(home, monkeypatch):
    monkeypatch.setattr(cli, "runtimes", lambda only=None: ["docker", "podman"])
    monkeypatch.setattr(cli, "stacks", lambda rt: [cli.Stack(rt, "gone-0b0b0b", {"c": "exited"})] * (rt == "docker"))
    monkeypatch.setattr(cli, "remove", lambda s, volumes: ["docker container c"])
    measured = []
    monkeypatch.setattr(cli, "disk", lambda rt: measured.append(rt) or 1e9)
    result = runner.invoke(app, ["-y"])
    assert "could not remove docker container c" in result.output and "removed 0 stack(s), 0 image(s)" in result.output
    assert measured == ["docker", "docker"]


def test_build_cache_warns_when_docker_was_not_looked_at(home, monkeypatch):
    monkeypatch.setattr(cli, "stacks", lambda rt: [])
    monkeypatch.setattr(cli, "unused_images", lambda *a: [])
    result = runner.invoke(app, ["7d", "--build-cache", "--runtime", "podman"])
    assert result.exit_code == 0 and "docker was not looked at" in result.output
