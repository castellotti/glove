"""Mount-dedup tests."""

from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

from glove.mounts import (
    HOST_TRUSTED,
    Mount,
    MountError,
    compute_mounts,
    make_bind_sources,
    protected_home,
    protected_paths,
    write_placeholders,
)


def _by_container(plan):
    return {m.container_path: m for m in plan.mounts}


def test_workdir_becomes_work(tmp_path):
    plan = compute_mounts(str(tmp_path))
    m = _by_container(plan)
    assert "/work" in m
    assert m["/work"].mode == "rw"
    assert plan.working_dir == "/work"


def test_parent_absorbs_child(tmp_path):
    parent = tmp_path / "parent"
    child = parent / "child"
    child.mkdir(parents=True)
    plan = compute_mounts(str(parent), [(str(child), "ro")])
    # Only the parent survives; the child is absorbed.
    assert [m.container_path for m in plan.mounts] == ["/work"]


def test_child_needing_rw_widens_parent(tmp_path):
    # workdir is a sibling so it doesn't absorb parent/child itself.
    work = tmp_path / "work"
    work.mkdir()
    parent = tmp_path / "tree" / "parent"
    child = parent / "child"
    child.mkdir(parents=True)
    # Parent added ro, child needs rw → parent widened to rw.
    plan = compute_mounts(
        str(work), [(str(parent), "ro"), (str(child), "rw")]
    )
    parent_mount = next(x for x in plan.mounts if x.host_path == str(parent))
    assert parent_mount.mode == "rw"
    # child is absorbed into the (now rw) parent
    assert [m.container_path for m in plan.mounts] == ["/work", "/mnt/parent"]


def test_sibling_paths_both_mounted(tmp_path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    work = tmp_path / "work"
    work.mkdir()
    plan = compute_mounts(str(work), [(str(a), "ro"), (str(b), "rw")])
    containers = sorted(m.container_path for m in plan.mounts)
    assert containers == ["/mnt/a", "/mnt/b", "/work"]


def test_prefix_not_component_ancestor(tmp_path):
    # /x/b must NOT be treated as ancestor of /x/bc.
    b = tmp_path / "b"
    bc = tmp_path / "bc"
    b.mkdir()
    bc.mkdir()
    plan = compute_mounts(str(b), [(str(bc), "ro")])
    assert len(plan.mounts) == 2


def test_cwd_inside_added_parent_sets_working_dir(tmp_path):
    parent = tmp_path / "proj"
    sub = parent / "pkg" / "mod"
    sub.mkdir(parents=True)
    other = tmp_path / "other"
    other.mkdir()
    # workdir is `other`; cwd is deep inside an added parent → working_dir maps
    # onto that mount, no second mount added for cwd.
    plan = compute_mounts(
        str(other), [(str(parent), "rw")], cwd=str(sub)
    )
    m = _by_container(plan)
    assert plan.working_dir == "/mnt/proj/pkg/mod"
    assert m["/mnt/proj"].mode == "rw"


def test_basename_collision_disambiguated(tmp_path):
    a = tmp_path / "one" / "data"
    b = tmp_path / "two" / "data"
    a.mkdir(parents=True)
    b.mkdir(parents=True)
    work = tmp_path / "w"
    work.mkdir()
    plan = compute_mounts(str(work), [(str(a), "ro"), (str(b), "ro")])
    containers = sorted(m.container_path for m in plan.mounts if not m.is_workdir)
    assert containers == ["/mnt/data", "/mnt/data-2"]


def test_refuses_root_without_optin():
    with pytest.raises(MountError):
        compute_mounts("/")


def test_refuses_home_without_optin():
    home = os.path.expanduser("~")
    with pytest.raises(MountError):
        compute_mounts(home)


def test_allow_sensitive_permits_home():
    home = os.path.expanduser("~")
    plan = compute_mounts(home, allow_sensitive=True)
    assert plan.mounts[0].container_path == "/work"


# --- ring-0 protected paths (v3 §6.3) ---------------------------------------


def _repo(tmp_path, name="proj"):
    work = tmp_path / name
    (work / ".git" / "hooks").mkdir(parents=True)
    (work / ".git" / "config").write_text("[core]\n\tbare = false\n")
    return work


def test_git_hooks_and_config_protected(tmp_path):
    work = _repo(tmp_path)
    plan = compute_mounts(str(work))
    got = [(p.container_path, p.kind, p.read_only) for p in protected_paths(plan.mounts)]
    # .git itself first (rw, only to pin it as a mount point), then the ro binds inside it
    assert got == [
        ("/work/.git", "dir", False),
        ("/work/.git/hooks", "dir", True),
        ("/work/.git/config", "file", True),
    ]
    assert all(p.host_path for p in protected_paths(plan.mounts))


def test_nothing_protected_without_git(tmp_path):
    work = tmp_path / "plain"
    work.mkdir()
    assert protected_paths(compute_mounts(str(work)).mounts) == ()


def test_rw_add_dir_repo_protected_ro_not(tmp_path):
    work = tmp_path / "w"
    work.mkdir()
    rw = _repo(tmp_path, "rwlib")
    ro = _repo(tmp_path, "rolib")
    plan = compute_mounts(str(work), [(str(rw), "rw"), (str(ro), "ro")])
    paths = {p.container_path for p in protected_paths(plan.mounts)}
    assert paths == {"/mnt/rwlib/.git", "/mnt/rwlib/.git/hooks", "/mnt/rwlib/.git/config"}


def test_symlink_escaping_the_mount_is_not_bound(tmp_path):
    work = tmp_path / "w"
    (work / ".git").mkdir(parents=True)
    outside = tmp_path / "outside-hooks"
    outside.mkdir()
    (work / ".git" / "hooks").symlink_to(outside)
    paths = {p.container_path for p in protected_paths(compute_mounts(str(work)).mounts)}
    assert "/work/.git/hooks" not in paths
    assert all(str(outside) != p.host_path for p in protected_paths(compute_mounts(str(work)).mounts))


def test_in_tree_hooks_path_protected(tmp_path):
    work = _repo(tmp_path)
    (work / ".githooks").mkdir()
    (work / ".git" / "config").write_text("[core]\n\thooksPath = .githooks\n")
    paths = {p.container_path for p in protected_paths(compute_mounts(str(work)).mounts)}
    assert "/work/.githooks" in paths


def test_ide_file_placeholders_are_opt_in(tmp_path):
    work = _repo(tmp_path)
    (work / ".envrc").write_text("export X=1\n")
    mounts = compute_mounts(str(work)).mounts
    # present: always protected (as srt denies it), no host file created for the missing ones
    got = {p.container_path: p for p in protected_paths(mounts)}
    assert got["/work/.envrc"].host_path == os.path.realpath(work / ".envrc")
    assert not any(p.host_path is None for p in got.values())
    got = {p.container_path: p for p in protected_paths(mounts, protect_ide_files=True)}
    assert got["/work/.envrc"].host_path == os.path.realpath(work / ".envrc")  # exists → real file
    for rel, kind in ((".vscode", "dir"), (".idea", "dir"), (".mcp.json", "file")):
        assert got[f"/work/{rel}"].host_path is None and got[f"/work/{rel}"].kind == kind


def test_every_host_trusted_path_present_is_protected_with_its_dir_pinned(tmp_path):
    work = _repo(tmp_path)
    (work / ".gitmodules").write_text("")
    for d in ("commands", "agents", "hooks", "skills"):
        (work / ".claude" / d).mkdir(parents=True)
    (work / ".claude" / "settings.json").write_text("{}")
    (work / ".idea").mkdir()
    got = {p.container_path: p.read_only for p in protected_paths(compute_mounts(str(work)).mounts)}
    real = os.path.realpath(work)
    assert got == {"/work/.git": False, "/work/.claude": False,  # pinned: `mv .claude x` fails
                   **{f"/work/{rel}": True for rel, *_ in HOST_TRUSTED if os.path.lexists(f"{real}/{rel}")}}
    assert "/work/.claude/settings.local.json" not in got  # missing, no placeholder: nothing created on the host


def test_a_host_trusted_path_inside_a_masked_dir_is_covered(tmp_path):
    # a harness masks .claude/ with its placeholder: the repo's own commands are never bound over it
    work = tmp_path / "w"
    (work / ".claude" / "commands").mkdir(parents=True)
    got = [(p.container_path, p.host_path) for p in protected_paths(compute_mounts(str(work)).mounts,
                                                                     files=[("/work/.claude/", "empty")])]
    assert got == [("/work/.claude", None)]


def test_srt_denies_ring0s_own_binds_never_inside_a_mask(tmp_path):
    from glove.enforcers.nono_srt import protected_paths as srt_denied

    work = _repo(tmp_path)
    (work / ".claude" / "commands").mkdir(parents=True)
    (work / ".envrc").write_text("")
    mounts = compute_mounts(str(work)).mounts
    plan = SimpleNamespace(mounts=mounts, protect=protected_paths(mounts, protect_ide_files=True))
    assert srt_denied(plan) == ["/work/.envrc", "/work/.git/hooks", "/work/.git/config", "/work/.claude/commands"]
    # a harness masks .claude/: the repo's commands are not there to deny (bwrap would create them)
    plan.protect = protected_paths(mounts, files=[("/work/.claude/", "empty")])
    assert "/work/.claude/commands" not in srt_denied(plan)


@pytest.mark.parametrize("hooks", [".claude", ".git"])
def test_a_hooks_path_on_a_pinned_dir_is_read_only(tmp_path, hooks):
    # git runs <hooksPath>/pre-commit on the host: the pin over .claude/.git must not leave it writable
    work = _repo(tmp_path)
    (work / ".claude" / "commands").mkdir(parents=True)
    (work / ".git" / "config").write_text(f"[core]\n\thooksPath = {hooks}\n")
    mounts = compute_mounts(str(work)).mounts
    protect = protected_paths(mounts, files=TRUSTED)
    got = {p.container_path: p for p in protect}
    assert got[f"/work/{hooks}"].read_only and got[f"/work/{hooks}"].host_path
    ro = [c for c, p in got.items() if p.read_only]
    assert all(p.read_only for c, p in got.items() if any(c.startswith(r + "/") for r in ro))  # no pin reopens it
    if hooks == ".claude":  # CC's placeholder for a missing settings.local.json needs its mount point on the host
        make_bind_sources(protect, str(tmp_path / "home"))
        assert (work / ".claude" / "settings.local.json").is_file()


TRUSTED = [("/work/.claude/settings.json", "auto"), ("/work/.claude/settings.local.json", "auto")]


def test_trusted_files_always_protected_with_their_dir_pinned(tmp_path):
    work = tmp_path / "w"
    (work / ".claude").mkdir(parents=True)
    (work / ".claude" / "settings.json").write_text("{}")
    got = [(p.container_path, p.host_path, p.kind, p.read_only)
           for p in protected_paths(compute_mounts(str(work)).mounts, files=TRUSTED)]
    real = os.path.realpath(work)
    assert got == [
        ("/work/.claude", f"{real}/.claude", "dir", False),  # pinned: `mv .claude x` fails
        ("/work/.claude/settings.json", f"{real}/.claude/settings.json", "file", True),
        ("/work/.claude/settings.local.json", None, "file", True),  # missing: a placeholder
    ]


def test_trusted_dir_missing_is_still_pinned(tmp_path):
    work = tmp_path / "w"
    work.mkdir()
    got = {p.container_path: p.host_path for p in protected_paths(compute_mounts(str(work)).mounts, files=TRUSTED)}
    assert got["/work/.claude"] == f"{os.path.realpath(work)}/.claude"  # created at launch
    assert got["/work/.claude/settings.json"] is None


@pytest.mark.parametrize("plant", ["dir-link", "file-link", "file-is-dir"])
def test_trusted_path_that_cannot_be_protected_is_refused(tmp_path, plant):
    work = tmp_path / "w"
    work.mkdir()
    (tmp_path / "elsewhere").mkdir()
    if plant == "dir-link":
        (work / ".claude").symlink_to(tmp_path / "elsewhere")
    else:
        (work / ".claude").mkdir()
        target = work / ".claude" / "settings.json"
        target.symlink_to(tmp_path / "elsewhere") if plant == "file-link" else target.mkdir()
    with pytest.raises(MountError, match="glove protects it"):
        protected_paths(compute_mounts(str(work)).mounts, files=TRUSTED)


def test_masked_paths_always_get_the_placeholder(tmp_path):
    work = tmp_path / "w"
    (work / ".vibe").mkdir(parents=True)
    (work / ".vibe" / "hooks.toml").write_text("[[hooks]]\n")
    got = [(p.container_path, p.host_path, p.kind, p.read_only)
           for p in protected_paths(compute_mounts(str(work)).mounts, files=[
               ("/work/.claude/", "auto"), ("/work/.vibe/", "empty"), ("/work/.agents/", "empty")])]
    real = os.path.realpath(work)
    assert got == [
        ("/work/.claude", None, "dir", True),  # a trusted dir: the placeholder only while missing
        ("/work/.vibe", None, "dir", True),  # masked: the repo's own .vibe/ is never seen
        ("/work/.agents", None, "dir", True),
    ]
    (work / ".claude").mkdir()
    got = {p.container_path: p.host_path for p in protected_paths(compute_mounts(str(work)).mounts,
                                                                   files=[("/work/.claude/", "auto")])}
    assert got == {"/work/.claude": f"{real}/.claude"}


def test_trusted_files_outside_a_rw_mount_are_skipped(tmp_path):
    work = tmp_path / "w"
    work.mkdir()
    assert protected_paths(compute_mounts(str(work)).mounts, files=[("/opt/x/settings.json", "auto")]) == ()


def test_a_path_inside_a_masked_dir_binds_inside_its_placeholder(tmp_path):
    # Vibe's project_skills: the repo's .vibe/skills/ through the masked .vibe/,
    # whatever the order; the placeholder gets its mount point.
    work = tmp_path / "w"
    (work / ".vibe" / "skills").mkdir(parents=True)
    protect = protected_paths(compute_mounts(str(work)).mounts, files=[
        ("/work/.vibe/skills/", "auto"), ("/work/.agents/skills/", "auto"),
        ("/work/.vibe/", "empty"), ("/work/.agents/", "empty")])
    real = os.path.realpath(work)
    assert [(p.container_path, p.host_path, p.read_only) for p in protect] == [
        ("/work/.vibe", None, True),  # no pin over the placeholder
        ("/work/.agents", None, True),
        ("/work/.vibe/skills", f"{real}/.vibe/skills", True),  # the repo's own, read-only
        ("/work/.agents/skills", None, True),  # missing: a placeholder
    ]
    holders = write_placeholders(tmp_path / "ph", protect)
    assert sorted(str(p.relative_to(holders)) for p in holders.rglob("*")) == [
        "work", "work/.agents", "work/.agents/skills", "work/.vibe", "work/.vibe/skills"]


HOME_PROTECTED = [".vibe/hooks.toml", ".vibe/tools/", ".agents/"]
CONFIG_HOME = "/home/agent/.vibe"


def _home(tmp_path):
    return Mount(host_path=str(tmp_path / "home"), container_path="/home/agent", mode="ro")


def test_protected_home_rebinds_the_config_home_rw_and_binds_its_own_copies_ro(tmp_path):
    got = [(p.container_path, p.host_path, p.kind, p.read_only)
           for p in protected_home(_home(tmp_path), CONFIG_HOME, HOME_PROTECTED)]
    home = tmp_path / "home"
    assert got == [
        ("/home/agent/.vibe", f"{home}/.vibe", "dir", False),  # writable, and pinned: `mv .vibe x` fails
        # never a placeholder: glove renders the file there (or creates it empty)
        ("/home/agent/.vibe/hooks.toml", f"{home}/.vibe/hooks.toml", "file", True),
        ("/home/agent/.vibe/tools", f"{home}/.vibe/tools", "dir", True),
        # .agents/ is outside the config home: read-only with the home, no bind
    ]


def test_protected_home_pins_nothing_above_the_config_home(tmp_path):
    got = [p.container_path for p in protected_home(_home(tmp_path), "/home/agent/.pi/agent",
                                                    [".pi/agent/settings.json"])]
    assert got == ["/home/agent/.pi/agent", "/home/agent/.pi/agent/settings.json"]  # not .pi: the home is ro


@pytest.mark.parametrize("config_home", ["/home/agent", "/home/other/.vibe", "/home/agent/../x"])
def test_config_home_outside_the_home_is_refused(tmp_path, config_home):
    with pytest.raises(MountError, match="must be inside /home/agent"):
        protected_home(_home(tmp_path), config_home, [])


def test_bind_sources_are_created_empty_and_existing_ones_kept(tmp_path):
    (tmp_path / "home" / ".vibe").mkdir(parents=True)
    (tmp_path / "home" / ".vibe" / "hooks.toml").write_text("kept")
    make_bind_sources(protected_home(_home(tmp_path), CONFIG_HOME, HOME_PROTECTED), str(tmp_path / "home"),
                      ["/tmp", "/home/agent/.local/state/nono"])
    assert (tmp_path / "home" / ".vibe" / "hooks.toml").read_text() == "kept"
    assert (tmp_path / "home" / ".vibe" / "tools").is_dir()
    assert not (tmp_path / "home" / ".agents").exists()  # no bind: nothing to create
    # a mount point under the read-only home, which the runtime cannot create
    assert (tmp_path / "home" / ".local" / "state" / "nono").is_dir()
    assert sorted(p.name for p in (tmp_path / "home").iterdir()) == [".local", ".vibe"]


def test_mount_point_through_a_symlink_is_refused(tmp_path):
    (tmp_path / "home").mkdir()
    (tmp_path / "home" / ".local").symlink_to(tmp_path)
    with pytest.raises(MountError, match="not a symlink"):
        make_bind_sources((), str(tmp_path / "home"), ["/home/agent/.local/state/nono"])
    assert not (tmp_path / "state").exists()


@pytest.mark.parametrize("plant", ["file-link", "file-is-dir", "dir-is-file", "config-home-link", "outside-link"])
def test_protected_home_path_of_the_wrong_kind_is_refused(tmp_path, plant):
    vibe = tmp_path / "home" / ".vibe"
    vibe.parent.mkdir(parents=True)
    if plant == "config-home-link":
        vibe.symlink_to(tmp_path)
    else:
        vibe.mkdir()
    if plant == "file-link":
        (vibe / "hooks.toml").symlink_to(tmp_path)
    elif plant == "file-is-dir":
        (vibe / "hooks.toml").mkdir()
    elif plant == "dir-is-file":
        (vibe / "tools").write_text("")
    elif plant == "outside-link":  # outside the config home: no bind, but still checked
        (tmp_path / "home" / ".agents").symlink_to(tmp_path)
    with pytest.raises(MountError, match="glove protects it"):
        protected_home(_home(tmp_path), CONFIG_HOME, HOME_PROTECTED)


def test_remove_empty_removes_only_empty_files_and_dirs_never_a_symlink_or_content(tmp_path):
    from glove.mounts import remove_empty

    (tmp_path / "pin" / "hole").mkdir(parents=True)
    (tmp_path / "pin" / "f").touch()  # pin/ is empty once its children go: deepest first
    (tmp_path / "kept").write_text("mine")
    (tmp_path / "full").mkdir()
    (tmp_path / "full" / "x").write_text("x")
    (tmp_path / "target").touch()
    (tmp_path / "link").symlink_to(tmp_path / "target")
    (tmp_path / "elsewhere" / "empty").mkdir(parents=True)
    (tmp_path / "swapped").symlink_to(tmp_path / "elsewhere")  # a pinned dir swapped for a link
    paths = [str(tmp_path / n) for n in ("pin", "pin/hole", "pin/f", "kept", "full", "link", "gone", "swapped/empty")]
    removed, failed = remove_empty(paths)
    assert sorted(os.path.relpath(p, tmp_path) for p in removed) == ["pin", "pin/f", "pin/hole"]
    assert failed == [f"{tmp_path}/swapped/empty: a symlink on the way"]
    assert sorted(p.name for p in tmp_path.iterdir()) == ["elsewhere", "full", "kept", "link", "swapped", "target"]
    assert (tmp_path / "elsewhere" / "empty").is_dir()
