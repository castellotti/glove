"""Shared test helpers."""

from __future__ import annotations

from glove.config import Config

# Every harness session needs the `inference` slot filled. A host llama.cpp
# with an explicit model resolves nothing at plan time and adds one forwarder
# (`glove-<id>-llm` → host.docker.internal:8080).
STUB_LLM = {"provider": "llama.cpp", "location": "host", "endpoint": "127.0.0.1:8080", "model": "test-model"}


# Toolchain blocks: a pinned Node, and that Node baking Playwright's Chromium.
NODE = {"lang": "node", "version": "22.11.0"}
CHROMIUM = {**NODE, "packages": ["playwright@1.63.0"], "browsers": ["chromium"]}


def with_llm(extensions: dict | None = None) -> dict:
    return {"llm": dict(STUB_LLM), **(extensions or {})}


def make_cfg(**kw) -> Config:
    """A Config with the stub inference provider (plus any `extensions=`), on Pi
    unless `harness=` says otherwise (core has no default harness)."""
    kw["extensions"] = with_llm(kw.get("extensions"))
    kw.setdefault("harness", "pi")
    return Config(**kw)


def render(cfg: Config, tmp_path, *, cwd=None, uid=501, gid=20, overrides=frozenset()):
    """Plan + docker render (what `glove run --dry-run` writes); returns (plan, yaml text)."""
    from pathlib import Path

    from glove.plan import build_session_plan
    from glove.runtimes.docker import DockerRuntime

    plan = build_session_plan(
        cfg, home_dir=str(tmp_path / "home"), cwd=cwd, uid=uid, gid=gid,
        state_dir=str(tmp_path / "ext"),
    )
    return plan, DockerRuntime().render(plan, Path(tmp_path), overrides=overrides).compose_yaml

# The same stub as YAML, for CLI tests that write a glove.yaml / --config overlay.
STUB_LLM_YAML = (
    "extensions:\n"
    "  llm: {provider: llama.cpp, location: host, endpoint: \"127.0.0.1:8080\", model: test-model}\n"
)


def session_file(extra: str = "", *, harness: str = "pi", llm: str | None = None) -> str:
    """A v3 glove-session.yml with the stub inference provider (or `llm`, a
    flow mapping replacing it) plus `extra` top-level YAML."""
    llm = llm or "{provider: llama.cpp, location: host, endpoint: \"127.0.0.1:8080\", model: test-model}"
    return f"glove: 3\ntemplate: test\nharness: {harness}\nextensions:\n  llm: {llm}\n{extra}"


def make_session(root, extra: str = "", **kw):
    """Write a session directory (file + work/) without `glove new`; returns its Path."""
    from pathlib import Path

    root = Path(root)
    (root / "work").mkdir(parents=True, exist_ok=True)
    (root / "glove-session.yml").write_text(session_file(extra, **kw))
    return root


def path_rule_cases(tmp) -> tuple[str, list[tuple[str, str | None]]]:
    """harnesses/path_rule_cases.json laid out under `tmp` (resolved): the write
    root (also the cwd), and (path, checked path or None) per case."""
    import json
    from pathlib import Path

    tmp = Path(tmp).resolve()
    data = json.loads((Path(__file__).resolve().parents[1] / "harnesses" / "path_rule_cases.json").read_text())
    for d in ("work/real", "home"):
        (tmp / d).mkdir(parents=True)
    for link, target in data["symlinks"].items():
        (tmp / link).symlink_to(target.format(tmp=tmp))
    return str(tmp / "work"), [(c["path"].format(tmp=tmp), c["checked"] and c["checked"].format(tmp=tmp))
                               for c in data["cases"]]
