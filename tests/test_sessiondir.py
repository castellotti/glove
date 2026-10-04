"""The session directory model (glove/sessiondir.py)."""

from __future__ import annotations

import json
import re

import pytest
from helpers import make_session

from glove import sessiondir as sdm
from glove.network import slice_subnet

SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")  # Layman's, handoff §3
COMPOSE_PROJECT = re.compile(r"^[a-z0-9][a-z0-9_-]*$")


@pytest.mark.parametrize(("name", "prefix"), [
    ("research-1", "research-1"), ("tmp.XyZ12", "tmp-xyz12"), ("My Project!", "my-project"),
    ("...", "session"), ("_x_", "x"), ("a" * 60, "a" * 40), ("ünïcode", "n-code")])
def test_ids_are_sanitised_dirnames_plus_six_hex(name, prefix):
    sid = sdm.new_id(name)
    assert sid.rsplit("-", 1)[0] == prefix
    assert sdm.ID_RE.match(sid) and SAFE_NAME.match(sid) and COMPOSE_PROJECT.match(f"glove-{sid}")


def test_ensure_state_is_idempotent_and_private(tmp_path):
    sd = sdm.SessionDir(make_session(tmp_path / "s"))
    sid, created = sdm.ensure_state(sd)
    assert created and sdm.ensure_state(sd) == (sid, False)
    assert (sd.state / ".gitignore").read_text().endswith("*\n")  # never committed with a repo
    (sd.state / "id").write_text("../../etc\n")  # a tampered id is not trusted
    assert sd.read_id() is None


def test_find_walks_up_from_a_subdirectory(tmp_path, monkeypatch):
    d = make_session(tmp_path / "s")
    (d / "work" / "deep").mkdir()
    monkeypatch.chdir(d / "work" / "deep")
    assert sdm.find().root == d.resolve()
    with pytest.raises(sdm.SessionError, match="not a glove session"):
        sdm.find(tmp_path)


def test_the_schema_version_is_required(tmp_path):
    d = make_session(tmp_path / "s")
    (d / "glove-session.yml").write_text("harness: pi\n")
    with pytest.raises(sdm.SessionError, match="glove: 3"):
        sdm.load_file(sdm.SessionDir(d))


@pytest.mark.parametrize(("extra", "runtime", "enforcer"), [
    ("", "docker", "nono+srt"), ("runtime: podman\n", "podman", "nono"),
    ("enforcer: nono\n", "docker", "nono"), ("runtime: podman\nenforcer: none\n", "podman", "none")])
def test_the_default_enforcer_follows_the_runtime(tmp_path, extra, runtime, enforcer):
    sd = sdm.SessionDir(make_session(tmp_path / "s", extra))
    cfg = sdm.to_config(sd, sdm.load_file(sd), "s-000000")
    assert (cfg.runtime, cfg.enforcer) == (runtime, enforcer)


def test_placeholders_left_names_every_path():
    raw = {"a": "<set-me>", "b": {"c": "keychain:<set-me>", "d": "ok"}, "e": ["x", "<set-me>"]}
    assert sdm.placeholders_left(raw) == ["a", "b.c", "e[1]"]


def test_every_bundled_template_is_a_valid_v3_file(tmp_path):
    assert "minimal" in sdm.list_templates()
    for name in sdm.list_templates():
        sd, sid = sdm.materialize(name, tmp_path / name)
        raw = sdm.load_file(sd)
        assert raw["template"] == name
        sdm.to_config(sd, raw, sid)


def test_git_url_detection():
    assert sdm._is_git_url("https://github.com/x/y") and sdm._is_git_url("git@github.com:x/y.git")
    assert not sdm._is_git_url("minimal") and not sdm._is_git_url("./tpl")


def test_subnet_slices_are_deterministic_27s():
    assert slice_subnet("172.31.4.0/24", ["n", "h", "x"]) == {
        "n": "172.31.4.0/27", "h": "172.31.4.32/27", "x": "172.31.4.64/27"}
    with pytest.raises(ValueError, match="room for 8"):
        slice_subnet("172.31.4.0/24", [str(i) for i in range(9)])


def test_pi_search_template_plans_once_filled(tmp_path, monkeypatch):
    monkeypatch.setenv("GLOVE_HOME", str(tmp_path / "gh"))
    assert "pi-search" in sdm.list_templates()
    sd, sid = sdm.materialize("pi-search", tmp_path / "ps")
    text = sd.file.read_text()
    assert "keychain:<set-me>" in text  # secrets are references, never values
    filled = (text.replace("provider: <set-me>         # openai", "provider: llama.cpp  # openai")
              .replace("location: <set-me>", "location: host").replace("endpoint: <set-me>", 'endpoint: "127.0.0.1:1"')
              .replace("provider: <set-me>", "provider: mullvad").replace("keychain:<set-me>", "keychain:wg"))
    sd.file.write_text(filled)
    raw = sdm.load_file(sd)
    assert sdm.placeholders_left(raw) == []
    from glove.plan import build_session_plan

    cfg = sdm.to_config(sd, raw, sid, subnet="172.31.9.0/24")
    plan = build_session_plan(cfg, home_dir=str(sd.home), cwd=str(sd.work), state_dir=str(sd.ext),
                              session_dir=str(sd.root))
    comp = plan.composition
    assert [a.name for a in comp.active] == ["llm", "media", "ocr", "vpn", "search", "webfetch"]
    assert comp.slot_exports("egress")["route"] == "vpn"


def test_pi_rag_template_plans_once_filled(tmp_path, monkeypatch):
    monkeypatch.setenv("GLOVE_HOME", str(tmp_path / "gh"))
    assert "pi-rag" in sdm.list_templates()
    sd, sid = sdm.materialize("pi-rag", tmp_path / "pr")
    (tmp_path / "models").mkdir()
    filled = (sd.file.read_text().replace("provider: <set-me>", "provider: llama.cpp")
              .replace("location: <set-me>", "location: host").replace("endpoint: <set-me>", 'endpoint: "127.0.0.1:1"')
              .replace("models_dir: <set-me>", f"models_dir: {tmp_path / 'models'}"))
    sd.file.write_text(filled)
    raw = sdm.load_file(sd)
    assert sdm.placeholders_left(raw) == []
    from glove.plan import build_session_plan

    cfg = sdm.to_config(sd, raw, sid, subnet="172.31.9.0/24")
    plan = build_session_plan(cfg, home_dir=str(sd.home), cwd=str(sd.work), state_dir=str(sd.ext),
                              session_dir=str(sd.root))
    comp = plan.composition
    assert [a.name for a in comp.active] == ["llm", "media", "ocr", "rag"]
    assert "egress" not in comp.slots and [e.name for e in comp.endpoints] == ["llm"]  # offline
    assert any(m.container_path == "/mnt/rag-models" and m.mode == "ro" for m in plan.mounts)


def test_browse_watch_template_plans_once_filled(tmp_path, monkeypatch):
    monkeypatch.setenv("GLOVE_HOME", str(tmp_path / "gh"))
    assert "browse-watch" in sdm.list_templates()
    sd, sid = sdm.materialize("browse-watch", tmp_path / "bw")
    filled = (sd.file.read_text().replace("provider: <set-me>", "provider: llama.cpp")
              .replace("location: <set-me>", "location: host").replace("endpoint: <set-me>", 'endpoint: "127.0.0.1:1"'))
    sd.file.write_text(filled)
    raw = sdm.load_file(sd)
    assert sdm.placeholders_left(raw) == []
    from glove.plan import build_session_plan

    cfg = sdm.to_config(sd, raw, sid, subnet="172.31.9.0/24")
    plan = build_session_plan(cfg, home_dir=str(sd.home), cwd=str(sd.work), state_dir=str(sd.ext),
                              session_dir=str(sd.root))
    comp = plan.composition
    assert comp.slots["browser"].name == "playwright" and comp.slots["egress"].name == "direct"
    assert comp.by_name("playwright").settings["mode"] == "novnc"
    assert [e.name for e in comp.endpoints] == ["llm", "browser", "browser-egress"]


def test_corporate_template_plans_once_filled(tmp_path, monkeypatch):
    monkeypatch.setenv("GLOVE_HOME", str(tmp_path / "gh"))
    assert "corporate" in sdm.list_templates()
    sd, sid = sdm.materialize("corporate", tmp_path / "corp")
    text = sd.file.read_text()
    filled = (text.replace("provider: <set-me>", "provider: llama.cpp").replace("location: <set-me>", "location: host")
              .replace("endpoint: <set-me>", 'endpoint: "127.0.0.1:1"')
              .replace("allow_domains: [<set-me>]", 'allow_domains: ["*.corp.example"]'))
    sd.file.write_text(filled)
    raw = sdm.load_file(sd)
    assert sdm.placeholders_left(raw) == []
    from glove.plan import build_session_plan

    cfg = sdm.to_config(sd, raw, sid, subnet="172.31.9.0/24")
    plan = build_session_plan(cfg, home_dir=str(sd.home), cwd=str(sd.work), state_dir=str(sd.ext),
                              session_dir=str(sd.root))
    comp = plan.composition
    assert {a.name for a in comp.active} == {"llm", "gate", "corporate", "webfetch", "observe"}
    assert comp.slot_exports("egress")["route"] == "corporate"
    assert comp.slots["forwarder"].name == "observe"


def test_vibe_search_template_plans_once_filled(tmp_path, monkeypatch):
    monkeypatch.setenv("GLOVE_HOME", str(tmp_path / "gh"))
    assert "vibe-search" in sdm.list_templates()
    sd, sid = sdm.materialize("vibe-search", tmp_path / "vs")
    text = sd.file.read_text()
    filled = (text.replace("provider: <set-me>         # openai", "provider: llama.cpp  # openai")
              .replace("location: <set-me>", "location: host").replace("endpoint: <set-me>", 'endpoint: "127.0.0.1:1"')
              .replace("provider: <set-me>", "provider: mullvad").replace("keychain:<set-me>", "keychain:wg"))
    sd.file.write_text(filled)
    raw = sdm.load_file(sd)
    assert sdm.placeholders_left(raw) == []
    from glove.plan import build_session_plan

    cfg = sdm.to_config(sd, raw, sid, subnet="172.31.9.0/24")
    plan = build_session_plan(cfg, home_dir=str(sd.home), cwd=str(sd.work), state_dir=str(sd.ext),
                              session_dir=str(sd.root))
    comp = plan.composition
    assert cfg.harness == "vibe"
    assert [a.name for a in comp.active] == ["llm", "media", "ocr", "vpn", "search", "webfetch"]
    assert {"search-mcp", "webfetch-mcp"} <= {e.name for e in comp.endpoints}


def test_claude_code_template_plans_once_filled(tmp_path, monkeypatch):
    monkeypatch.setenv("GLOVE_HOME", str(tmp_path / "gh"))
    assert "claude-code" in sdm.list_templates()
    sd, sid = sdm.materialize("claude-code", tmp_path / "cc")
    text = sd.file.read_text()
    assert text.count("keychain:<set-me>") >= 2  # the token and the GitHub token are references
    sd.file.write_text(text.replace("keychain:<set-me>", "keychain:svc"))
    raw = sdm.load_file(sd)
    assert sdm.placeholders_left(raw) == []
    from glove.plan import build_session_plan

    cfg = sdm.to_config(sd, raw, sid, subnet="172.31.9.0/24")
    plan = build_session_plan(cfg, home_dir=str(sd.home), cwd=str(sd.work), state_dir=str(sd.ext),
                              session_dir=str(sd.root))
    comp = plan.composition
    assert cfg.harness == "claude-code" and plan.enforcer == "nono+srt"
    assert {"direct", "webfetch", "playwright", "github", "relay", "observe", "filter"} <= {a.name for a in comp.active}
    assert comp.by_name("ssh") is None
    assert "/proc" in json.loads(plan.policies["tool.json"])["filesystem"]["read"]  # browsers in shell commands
    assert [tc["lang"] for tc in cfg.toolchains] == ["python", "node"]
