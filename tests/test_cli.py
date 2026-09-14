"""CLI-level tests for the env workflow."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from glove.cli import app
from glove.registry import session_dir

runner = CliRunner()


@pytest.fixture
def home(tmp_path, monkeypatch):
    ghome = tmp_path / "ghome"
    monkeypatch.setenv("GLOVE_HOME", str(ghome))
    return ghome


def _chdir(monkeypatch, d):
    d.mkdir(parents=True, exist_ok=True)
    monkeypatch.chdir(d)
    return d


def _write_llm_cfg(tmp_path):
    """A minimal overlay declaring one `llm` service the harness dials."""
    cfg = tmp_path / "over.yaml"
    cfg.write_text(
        "net: [service]\n"
        "model: m\n"
        "services:\n"
        "  - { name: llm, to: example.test:8080, port: 8080 }\n"
    )
    return cfg


def _pi_llm_base(env_id, session):
    """The Pi `glove` provider baseUrl from a session's rendered models.json."""
    models_json = session_dir(env_id, session) / "home" / ".pi" / "agent" / "models.json"
    return json.loads(models_json.read_text())["providers"]["glove"]["baseUrl"]


def test_init_writes_only_under_glove_home(home, tmp_path, monkeypatch):
    wd = _chdir(monkeypatch, tmp_path / "pi-local")
    result = runner.invoke(app, ["init", "pi"])
    assert result.exit_code == 0, result.output
    # cwd untouched
    assert list(wd.iterdir()) == []
    # env config written under GLOVE_HOME/envs/<id>/
    assert (home / "envs" / "pi-local" / "glove.yaml").is_file()
    assert (home / "registry.json").is_file()


def test_two_harnesses_one_dir_distinct_envs(home, tmp_path, monkeypatch):
    _chdir(monkeypatch, tmp_path / "pi-local")
    assert runner.invoke(app, ["init", "pi"]).exit_code == 0
    assert runner.invoke(app, ["init", "vibe"]).exit_code == 0
    ids = {d.name for d in (home / "envs").iterdir()}
    assert ids == {"pi-local", "pi-local-vibe"}


def test_run_without_env_errors_with_hint(home, tmp_path, monkeypatch):
    _chdir(monkeypatch, tmp_path / "wd")
    result = runner.invoke(app, ["run", "pi"])
    assert result.exit_code == 1
    assert "glove init pi" in result.output


def test_run_dry_run_renders_under_env(home, tmp_path, monkeypatch):
    work = tmp_path / "work"
    work.mkdir()
    _chdir(monkeypatch, tmp_path / "vibe-local")
    assert runner.invoke(app, ["init", "vibe"]).exit_code == 0
    result = runner.invoke(
        app, ["run", "vibe", "--workdir", str(work), "--dry-run"]
    )
    assert result.exit_code == 0, result.output
    assert "name: glove-vibe-local" in result.output
    # compose renders under sessions/<session>/ (default session == env-id)
    sdir = home / "envs" / "vibe-local" / "sessions" / "vibe-local"
    assert (sdir / "docker-compose.yml").is_file()
    # harness home seeded per-session, under the session dir (not the env root)
    assert (sdir / "home" / ".vibe" / "config.toml").is_file()


def test_named_session_llm_base_matches_sidecar(home, tmp_path, monkeypatch):
    # Regression: a `--name`d session's llm sidecar is glove-<env>-<name>-llm,
    # so the Pi baseUrl must be built from the resolved session token, not the
    # bare env-id — otherwise Pi dials a host that doesn't exist ("Connection
    # error"). Default (unnamed) sessions happened to match and hid this.
    _chdir(monkeypatch, tmp_path / "pi-local")
    assert runner.invoke(app, ["init", "pi"]).exit_code == 0
    cfg = _write_llm_cfg(tmp_path)
    result = runner.invoke(
        app, ["run", "pi", "--name", "feature", "--config", str(cfg), "--dry-run"]
    )
    assert result.exit_code == 0, result.output
    host = "glove-pi-local-feature-llm"
    # The sidecar is named with the full token in the rendered compose...
    assert host in result.output
    # ...and the Pi provider baseUrl must point at that same host. The home is
    # per-session, so the named session's config lives under sessions/feature/.
    assert _pi_llm_base("pi-local", "feature") == f"http://{host}:8080/v1"


def test_coexisting_sessions_get_isolated_homes(home, tmp_path, monkeypatch):
    # Regression: the harness home is per-session. Two sessions of one env
    # coexisting must not share one home/, or the second render clobbers the
    # first's models.json and repoints it at a sidecar that isn't on its
    # network (the "Connection error" the baseUrl fix set out to eliminate).
    _chdir(monkeypatch, tmp_path / "pi-local")
    assert runner.invoke(app, ["init", "pi"]).exit_code == 0
    cfg = _write_llm_cfg(tmp_path)
    # Default (unnamed) session, then a --name'd one from the same env.
    assert runner.invoke(
        app, ["run", "pi", "--config", str(cfg), "--dry-run"]
    ).exit_code == 0
    assert runner.invoke(
        app, ["run", "pi", "--name", "feature", "--config", str(cfg), "--dry-run"]
    ).exit_code == 0

    # Each session's config survived the other's render, pointing at its own llm.
    assert _pi_llm_base("pi-local", "pi-local") == "http://glove-pi-local-llm:8080/v1"
    assert _pi_llm_base("pi-local", "feature") == "http://glove-pi-local-feature-llm:8080/v1"


def test_down_tears_down_named_sessions_too(home, tmp_path, monkeypatch):
    # Regression: `glove down <env>` must tear down every session, including
    # --name'd ones whose compose project is glove-<env>-<name>, not just the
    # default unnamed session.
    _chdir(monkeypatch, tmp_path / "pi-local")
    assert runner.invoke(app, ["init", "pi"]).exit_code == 0

    sessions = home / "envs" / "pi-local" / "sessions"
    for sname, token in (("pi-local", "pi-local"), ("feat", "pi-local-feat")):
        sdir = sessions / sname
        sdir.mkdir(parents=True)
        (sdir / "glove.effective.yaml").write_text(f"harness: pi\nname: {token}\n")

    torn: list[str] = []
    import glove.session as session_mod

    monkeypatch.setattr(session_mod, "teardown", lambda s, **kw: torn.append(s))

    result = runner.invoke(app, ["down", "pi-local"])
    assert result.exit_code == 0, result.output
    assert set(torn) == {"pi-local", "pi-local-feat"}


def test_down_name_narrows_to_one_session(home, tmp_path, monkeypatch):
    _chdir(monkeypatch, tmp_path / "pi-local")
    assert runner.invoke(app, ["init", "pi"]).exit_code == 0
    sdir = home / "envs" / "pi-local" / "sessions" / "feat"
    sdir.mkdir(parents=True)
    (sdir / "glove.effective.yaml").write_text("harness: pi\nname: pi-local-feat\n")

    torn: list[str] = []
    import glove.session as session_mod

    monkeypatch.setattr(session_mod, "teardown", lambda s, **kw: torn.append(s))

    result = runner.invoke(app, ["down", "pi-local", "--name", "feat"])
    assert result.exit_code == 0, result.output
    assert torn == ["pi-local-feat"]


def _seed_transcript(home, env_id, session, uuid="01a09d62"):
    """Seed a fake Pi transcript under a session's persistent home."""
    tdir = (
        session_dir(env_id, session)
        / "home" / ".pi" / "agent" / "sessions" / "--work--"
    )
    tdir.mkdir(parents=True, exist_ok=True)
    f = tdir / f"20240101_{uuid}.jsonl"
    f.write_text("{}\n")
    return uuid


def test_resume_and_session_mutually_exclusive(home, tmp_path, monkeypatch):
    _chdir(monkeypatch, tmp_path / "pi-local")
    assert runner.invoke(app, ["init", "pi"]).exit_code == 0
    result = runner.invoke(app, ["run", "pi", "--resume", "--session", "x"])
    assert result.exit_code == 1
    assert "not both" in result.output


def test_resume_no_prior_session_errors(home, tmp_path, monkeypatch):
    _chdir(monkeypatch, tmp_path / "pi-local")
    assert runner.invoke(app, ["init", "pi"]).exit_code == 0
    result = runner.invoke(app, ["run", "pi", "--resume", "--dry-run"])
    assert result.exit_code == 1
    assert "no previous session to resume" in result.output


def _compose_text(home, env_id, session):
    return (
        session_dir(env_id, session) / "docker-compose.yml"
    ).read_text()


def test_resume_dry_run_renders_continue(home, tmp_path, monkeypatch):
    _chdir(monkeypatch, tmp_path / "pi-local")
    assert runner.invoke(app, ["init", "pi"]).exit_code == 0
    _seed_transcript(home, "pi-local", "pi-local")
    result = runner.invoke(app, ["run", "pi", "--resume", "--dry-run"])
    assert result.exit_code == 0, result.output
    # flag lands inside the nono wrapper, after `pi -e …`
    compose = _compose_text(home, "pi-local", "pi-local")
    assert "--continue" in compose
    assert compose.index("--continue") > compose.index("--")


def test_session_dry_run_renders_id(home, tmp_path, monkeypatch):
    _chdir(monkeypatch, tmp_path / "pi-local")
    assert runner.invoke(app, ["init", "pi"]).exit_code == 0
    uuid = _seed_transcript(home, "pi-local", "pi-local")
    result = runner.invoke(app, ["run", "pi", "--session", uuid, "--dry-run"])
    assert result.exit_code == 0, result.output
    compose = _compose_text(home, "pi-local", "pi-local")
    assert "--session" in compose and uuid in compose


def test_session_missing_lists_available(home, tmp_path, monkeypatch):
    _chdir(monkeypatch, tmp_path / "pi-local")
    assert runner.invoke(app, ["init", "pi"]).exit_code == 0
    uuid = _seed_transcript(home, "pi-local", "pi-local")
    result = runner.invoke(app, ["run", "pi", "--session", "nope", "--dry-run"])
    assert result.exit_code == 1
    assert "no session matching" in result.output
    assert uuid in result.output  # available ids listed


def test_resume_composes_with_net_change(home, tmp_path, monkeypatch):
    # Grant change (llm sidecar via --config) composes with the resume flag:
    # both the sidecar and --session land in the rendered compose command.
    _chdir(monkeypatch, tmp_path / "pi-local")
    assert runner.invoke(app, ["init", "pi"]).exit_code == 0
    uuid = _seed_transcript(home, "pi-local", "pi-local")
    cfg = _write_llm_cfg(tmp_path)
    result = runner.invoke(
        app,
        ["run", "pi", "--config", str(cfg), "--session", uuid, "--dry-run"],
    )
    assert result.exit_code == 0, result.output
    compose = _compose_text(home, "pi-local", "pi-local")
    assert "glove-pi-local-llm" in compose  # llm sidecar rendered
    assert "--session" in compose and uuid in compose  # + resume flag


def test_resume_grant_widening_warns(home, tmp_path, monkeypatch):
    _chdir(monkeypatch, tmp_path / "pi-local")
    assert runner.invoke(app, ["init", "pi"]).exit_code == 0
    uuid = _seed_transcript(home, "pi-local", "pi-local")
    # Prior snapshot ran with no network; resume widening to net: [service].
    snapshot = session_dir("pi-local", "pi-local") / "glove.effective.yaml"
    snapshot.parent.mkdir(parents=True, exist_ok=True)
    snapshot.write_text("harness: pi\nname: pi-local\nnet: [none]\n")
    cfg = _write_llm_cfg(tmp_path)
    result = runner.invoke(
        app,
        ["run", "pi", "--config", str(cfg), "--session", uuid, "--dry-run"],
    )
    assert result.exit_code == 0, result.output
    assert "broader access" in result.output
    assert "net" in result.output


def test_ls_lists_registered_envs(home, tmp_path, monkeypatch):
    _chdir(monkeypatch, tmp_path / "wd")
    runner.invoke(app, ["init", "pi"])
    result = runner.invoke(app, ["ls"])
    assert result.exit_code == 0
    assert "wd" in result.output
    assert "pi" in result.output
