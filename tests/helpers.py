"""Shared test helpers."""

from __future__ import annotations

import subprocess
import sys

import pytest

from glove.config import Config

# Every harness session needs the `inference` slot filled. A host llama.cpp
# with an explicit model resolves nothing at plan time and adds one forwarder
# (`glove-<id>-llm` → host.docker.internal:8080).
# A certificate-only PEM, as `corporate_ca` and `playwright.ca` require.
PEM = "-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----\n"
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


def render(cfg: Config, tmp_path, *, cwd=None, uid=501, gid=20, overrides=frozenset(), session_dir=None):
    """Plan + docker render (what `glove run --dry-run` writes); returns (plan, yaml text)."""
    from pathlib import Path

    from glove.plan import build_session_plan
    from glove.runtimes.docker import DockerRuntime

    plan = build_session_plan(
        cfg, home_dir=str(tmp_path / "home"), cwd=cwd, uid=uid, gid=gid,
        state_dir=str(tmp_path / "ext"), session_dir=session_dir,
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


def session_id(d) -> str:
    """The id `glove new`/`plan` gave the session directory `d`."""
    from pathlib import Path

    return (Path(d) / ".glove" / "id").read_text().strip()


def command_module(name: str):
    """The `commands/<name>/cli.py` module `glove.cli` mounted: patch this one
    when invoking `glove.cli.app` (another `load_module` makes a second copy)."""
    import importlib

    import glove.cli  # noqa: F401  (mounts the commands)

    return importlib.import_module(f"glove_cmd.{name}.cli")


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


def quarantine_attr(p) -> str | None:
    """`com.apple.quarantine` on `p` itself (never a link's target), or None."""
    r = subprocess.run(["xattr", "-s", "-p", "com.apple.quarantine", str(p)], capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else None


darwin = pytest.mark.skipif(sys.platform != "darwin", reason="the quarantine attribute is macOS-only")


def plan_pw(tmp_path, **settings):
    """A pi session with `direct` and `playwright: settings`, planned."""
    from glove.plan import build_session_plan

    work = tmp_path / "work"
    work.mkdir(parents=True, exist_ok=True)
    cfg = make_cfg(harness="pi", name="s", workdir=str(work), subnet="172.31.4.0/24",
                   extensions={"direct": {}, "playwright": settings})
    return build_session_plan(cfg, home_dir=str(tmp_path / "h"), state_dir=str(tmp_path / "ext"),
                              session_dir=str(tmp_path))


def pw_service(tmp_path, plan) -> tuple[dict, str]:
    """(the rendered playwright sidecar, the whole compose text)."""
    import yaml

    from glove.runtimes.docker import DockerRuntime

    text = DockerRuntime().render(plan, tmp_path).compose_yaml
    return yaml.safe_load(text)["services"]["glove-s-pw"], text


def hook_ctx(name: str = "test", **fields):
    """A `HookContext` for calling an extension's hook directly."""
    from glove.hooks import HookContext

    return HookContext(name=name, **fields)
