"""Shared test helpers."""

from __future__ import annotations

from glove.config import Config

# Every harness session needs the `inference` slot filled. A host llama.cpp
# with an explicit model resolves nothing at plan time and adds one forwarder
# (`glove-<id>-llm` → host.docker.internal:8080).
STUB_LLM = {"provider": "llama.cpp", "location": "host", "endpoint": "127.0.0.1:8080", "model": "test-model"}


def with_llm(extensions: dict | None = None) -> dict:
    return {"llm": dict(STUB_LLM), **(extensions or {})}


def make_cfg(**kw) -> Config:
    """A Config with the stub inference provider (plus any `extensions=`)."""
    kw["extensions"] = with_llm(kw.get("extensions"))
    return Config(**kw)


def render(cfg: Config, tmp_path, *, cwd=None, uid=501, gid=20, overrides=frozenset()):
    """Plan + docker render (what `glove run --dry-run` writes); returns (plan, yaml text)."""
    from pathlib import Path

    from glove.plan import build_session_plan
    from glove.runtimes.docker import DockerRuntime

    plan = build_session_plan(
        cfg, env_id=cfg.resolved_name(), home_dir=str(tmp_path / "home"), cwd=cwd, uid=uid, gid=gid,
        state_dir=str(tmp_path / "ext"),
    )
    return plan, DockerRuntime().render(plan, Path(tmp_path), overrides=overrides).compose_yaml

# The same stub as YAML, for CLI tests that write a glove.yaml / --config overlay.
STUB_LLM_YAML = (
    "extensions:\n"
    "  llm: {provider: llama.cpp, location: host, endpoint: \"127.0.0.1:8080\", model: test-model}\n"
)
