"""Mount-dedup tests."""

from __future__ import annotations

import os

import pytest

from glove.mounts import MountError, compute_mounts, protected_paths


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


def test_ide_files_opt_in_with_placeholders(tmp_path):
    work = _repo(tmp_path)
    (work / ".envrc").write_text("export X=1\n")
    mounts = compute_mounts(str(work)).mounts
    assert not any(p.container_path.endswith(".envrc") for p in protected_paths(mounts))
    got = {p.container_path: p for p in protected_paths(mounts, protect_ide_files=True)}
    assert got["/work/.envrc"].host_path == os.path.realpath(work / ".envrc")  # exists → real file
    assert got["/work/.vscode"].host_path is None and got["/work/.vscode"].kind == "dir"
    assert got["/work/.mcp.json"].host_path is None and got["/work/.mcp.json"].kind == "file"


TRUSTED = ["/work/.claude/settings.json", "/work/.claude/settings.local.json"]


def test_trusted_files_always_protected_with_their_dir_pinned(tmp_path):
    work = tmp_path / "w"
    (work / ".claude").mkdir(parents=True)
    (work / ".claude" / "settings.json").write_text("{}")
    got = [(p.container_path, p.host_path, p.kind, p.read_only)
           for p in protected_paths(compute_mounts(str(work)).mounts, trusted=TRUSTED)]
    real = os.path.realpath(work)
    assert got == [
        ("/work/.claude", f"{real}/.claude", "dir", False),  # pinned: `mv .claude x` fails
        ("/work/.claude/settings.json", f"{real}/.claude/settings.json", "file", True),
        ("/work/.claude/settings.local.json", None, "file", True),  # missing: a placeholder
    ]


def test_trusted_dir_missing_is_still_pinned(tmp_path):
    work = tmp_path / "w"
    work.mkdir()
    got = {p.container_path: p.host_path for p in protected_paths(compute_mounts(str(work)).mounts, trusted=TRUSTED)}
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
        protected_paths(compute_mounts(str(work)).mounts, trusted=TRUSTED)


def test_trusted_files_outside_a_rw_mount_are_skipped(tmp_path):
    work = tmp_path / "w"
    work.mkdir()
    assert protected_paths(compute_mounts(str(work)).mounts, trusted=["/opt/x/settings.json"]) == ()
