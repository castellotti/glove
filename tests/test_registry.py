"""Environment identity + registry tests."""

from __future__ import annotations

import os

import pytest

from glove import registry


@pytest.fixture
def glove_home(tmp_path, monkeypatch):
    monkeypatch.setenv("GLOVE_HOME", str(tmp_path))
    return tmp_path


def _mkdir(tmp_path, name):
    d = tmp_path / name
    d.mkdir(parents=True, exist_ok=True)
    return str(d)


def test_env_id_unused_base(glove_home, tmp_path):
    d = _mkdir(tmp_path, "pi-local")
    assert registry.derive_env_id([], os.path.realpath(d), "pi") == "pi-local"


def test_env_id_same_dir_second_harness(glove_home, tmp_path):
    d = _mkdir(tmp_path, "pi-local")
    first = registry.create_env(d, "pi")
    assert first == "pi-local"
    second = registry.create_env(d, "vibe")
    assert second == "pi-local-vibe"


def test_env_id_path_collision(glove_home, tmp_path):
    a = _mkdir(tmp_path / "dev", "pi-local")
    b = _mkdir(tmp_path / "other", "pi-local")
    id_a = registry.create_env(a, "pi")
    id_b = registry.create_env(b, "pi")
    assert id_a == "pi-local"
    assert id_b.startswith("pi-local-")
    assert id_b != "pi-local"
    assert len(id_b.rsplit("-", 1)[1]) == 6  # short(dir) hex


def test_resolution_is_stable(glove_home, tmp_path):
    d = _mkdir(tmp_path, "wd")
    first = registry.create_env(d, "pi")
    # Re-resolving the same (dir, harness) returns the same id, no duplicate.
    assert registry.find_env_id(d, "pi") == first
    assert registry.resolve_env_id(d, "pi") == first
    assert len(registry.load_registry()) == 1


def test_registry_round_trip(glove_home, tmp_path):
    d = _mkdir(tmp_path, "wd")
    registry.create_env(d, "pi")
    registry.create_env(d, "vibe")
    entries = registry.load_registry()
    assert {e.env_id for e in entries} == {"wd", "wd-vibe"}
    assert all(e.dir == os.path.realpath(d) for e in entries)


def test_resolve_env_id_no_create(glove_home, tmp_path):
    d = _mkdir(tmp_path, "wd")
    assert registry.resolve_env_id(d, "pi", create=False) is None
    assert registry.load_registry() == []


def test_explicit_name(glove_home, tmp_path):
    d = _mkdir(tmp_path, "wd")
    env_id = registry.create_env(d, "pi", name="custom")
    assert env_id == "custom"
    assert registry.find_env_id(d, "pi") == "custom"


def test_explicit_name_clash_across_dirs_is_refused(glove_home, tmp_path):
    a = _mkdir(tmp_path / "one", "wd")
    b = _mkdir(tmp_path / "two", "wd")
    registry.create_env(a, "pi", name="shared")
    with pytest.raises(registry.RegistryError):
        registry.create_env(b, "vibe", name="shared")
    # The clash must not have created a second entry.
    assert {e.env_id for e in registry.load_registry()} == {"shared"}


def test_explicit_name_rebinds_same_dir_harness(glove_home, tmp_path):
    d = _mkdir(tmp_path, "wd")
    registry.create_env(d, "pi", name="shared")
    # Re-forcing the SAME (dir, harness) to the same name is a no-op rebind.
    assert registry.create_env(d, "pi", name="shared") == "shared"
    assert len(registry.load_registry()) == 1
    # A different harness in the same dir cannot reuse the name (it would clobber
    # the shared env tree); it must be refused just like a cross-dir clash.
    with pytest.raises(registry.RegistryError):
        registry.create_env(d, "vibe", name="shared")
