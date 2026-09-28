"""Registry v2 (``~/.glove/registry.json``): rows, locking, subnets, v1 refusal."""

from __future__ import annotations

import json

import pytest

from glove import registry as reg


@pytest.fixture(autouse=True)
def glove_home(tmp_path, monkeypatch):
    home = tmp_path / "ghome"
    monkeypatch.setenv("GLOVE_HOME", str(home))
    return home


def test_empty_when_absent():
    assert reg.load_registry() == []


def test_upsert_update_remove_round_trip(tmp_path):
    reg.upsert(reg.SessionEntry(id="a-000001", dir="/x/a", harness="pi", template="minimal"))
    reg.upsert(reg.SessionEntry(id="b-000002", dir="/x/b", harness="vibe"))
    reg.upsert(reg.SessionEntry(id="a-000001", dir="/x/a2", harness="pi"))  # replaces by id
    assert [(e.id, e.dir) for e in reg.load_registry()] == [("b-000002", "/x/b"), ("a-000001", "/x/a2")]
    assert reg.update("b-000002", grants={"observe": {"net": True}, "filter": None}).grants["observe"]
    assert reg.update("nope-000000", dir="/y") is None
    assert reg.remove({"a-000001", "zzz"}) == 1
    doc = json.loads(reg.registry_path().read_text())
    assert doc["v"] == 2 and [s["id"] for s in doc["sessions"]] == ["b-000002"]
    assert set(doc["sessions"][0]) == {"id", "dir", "harness", "template", "created", "grants", "subnet"}


def test_a_v1_registry_is_refused_not_migrated(glove_home):
    glove_home.mkdir()
    (glove_home / "registry.json").write_text('[{"dir": "/d", "harness": "pi", "env_id": "d"}]')
    with pytest.raises(reg.RegistryError, match="glove v2 registry"):
        reg.load_registry()
    with pytest.raises(reg.RegistryError):
        reg.upsert(reg.SessionEntry(id="a-000001", dir="/x", harness="pi"))
    assert json.loads((glove_home / "registry.json").read_text())[0]["env_id"] == "d"


def test_load_drops_unknown_keys_and_bad_rows(glove_home):
    glove_home.mkdir()
    (glove_home / "registry.json").write_text(json.dumps({"v": 2, "sessions": [
        {"id": "a-000001", "dir": "/a", "harness": "pi", "future": 1}, {"dir": "/b"}, "junk"]}))
    assert [e.id for e in reg.load_registry()] == ["a-000001"]


def test_unreadable_or_future_registries_are_errors(glove_home):
    glove_home.mkdir()
    (glove_home / "registry.json").write_text("{nope")
    with pytest.raises(reg.RegistryError, match="unreadable"):
        reg.load_registry()
    (glove_home / "registry.json").write_text('{"v": 3, "sessions": []}')
    with pytest.raises(reg.RegistryError, match="unsupported"):
        reg.load_registry()


def test_allocate_subnet_skips_taken_and_overlapping():
    assert reg.allocate_subnet("172.31.0.0/16", set()) == "172.31.0.0/24"
    assert reg.allocate_subnet("172.31.0.0/16", {"172.31.0.0/24", "172.31.1.0/24"}) == "172.31.2.0/24"
    assert reg.allocate_subnet("10.9.0.0/23", {"10.9.0.0/24"}) == "10.9.1.0/24"
    with pytest.raises(reg.RegistryError, match="exhausted"):
        reg.allocate_subnet("10.9.0.0/24", {"10.9.0.0/24"})
    with pytest.raises(reg.RegistryError):
        reg.allocate_subnet("10.9.0.0/25", set())
    with pytest.raises(reg.RegistryError):
        reg.allocate_subnet("nonsense", set())
