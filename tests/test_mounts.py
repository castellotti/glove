"""Mount-dedup tests."""

from __future__ import annotations

import os

import pytest

from glove.mounts import MountError, compute_mounts


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
