"""Golden renders per harness: what a session writes before anything launches.

For each case: the harness home (render_home), the compose project, the ring-1
policies, the derived Dockerfile and the plan's command/env/image. Paths under
the test's tmp dir, GLOVE_HOME and the checkout are normalised. Regenerate with
`GLOVE_UPDATE_GOLDEN=1 uv run pytest tests/test_harness_golden.py` and review
the diff: a harness refactor must leave these byte-identical.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from helpers import make_cfg

GOLDEN = Path(__file__).parent / "golden" / "harness"
UPDATE = os.environ.get("GLOVE_UPDATE_GOLDEN") == "1"

WEB = {"direct": {}, "search": {}, "webfetch": {}, "playwright": {}, "media": {}, "ocr": {}, "observe": {},
       "filter": {}}

CASES = {
    "pi-nono-min": {"harness": "pi", "enforcer": "nono", "extensions": {}},
    "pi-srt-full": {
        "harness": "pi", "enforcer": "nono+srt",
        "extensions": {**WEB, "rag": {"models_dir": "{tmp}/models"}},
        "harness_config": {"settings": {"defaultThinkingLevel": "medium", "env": {"X": "1"}},
                           "model": {"maxTokens": 4096}},
        "brief": "# brief\n\nDo the thing.",
    },
    "vibe-nono-min": {"harness": "vibe", "enforcer": "nono", "extensions": {}},
    "claude-code-nono-min": {
        "harness": "claude-code", "enforcer": "nono",
        "extensions": {"llm": {"provider": "anthropic", "model": "claude-x", "auth": "oauth",
                               "api_key": "keychain:test-cc"}},
    },
    "claude-code-srt-full": {
        "harness": "claude-code", "enforcer": "nono+srt",
        "extensions": {**WEB, "rag": {"models_dir": "{tmp}/models"},
                       "llm": {"provider": "anthropic-compatible", "location": "host", "endpoint": "127.0.0.1:8080",
                               "model": "claude-stub", "api_key": "env:TEST_KEY"}},
        "harness_config": {"settings": {"theme": "dark"},
                           "permissions": {"defaultMode": "acceptEdits", "deny": ["Bash(rm -rf:*)"]}},
        "brief": "# brief\n\nDo the thing.",
    },
    "vibe-srt-full": {
        "harness": "vibe", "enforcer": "nono+srt", "extensions": dict(WEB),
        "harness_config": {"include_commit_signature": False, "disabled_tools": ["task"],
                           "mcp_servers": [{"name": "extra", "transport": "http", "url": "http://x:1/mcp"}]},
        "brief": "# brief\n\nDo the thing.",
    },
}


def _render(case: dict, tmp_path: Path) -> dict[str, str]:
    from glove.harnessconfig import render_home
    from glove.plan import build_session_plan
    from glove.runtimes.docker import DockerRuntime

    (tmp_path / "models").mkdir()
    work = tmp_path / "work"
    work.mkdir()
    exts = json.loads(json.dumps(case["extensions"]).replace("{tmp}", str(tmp_path)))
    kw = {k: v for k, v in case.items() if k != "extensions"}
    cfg = make_cfg(name="s", workdir=str(work), extensions=exts, **kw)
    home = tmp_path / "home"
    plan = build_session_plan(cfg, home_dir=str(home), uid=501, gid=20, state_dir=str(tmp_path / "ext"),
                              session_dir=str(tmp_path))
    out: dict[str, str] = {}
    for p in render_home(cfg, plan, home):
        out[f"home/{p.relative_to(home)}"] = f"-> {p.readlink()}\n" if p.is_symlink() else p.read_text()
    for target, files in plan.system_files.items():
        for name, text in files.items():
            out[f"system{target}/{name}"] = text
    for name, text in (plan.policies or {}).items():
        out[f"policies/{name}"] = text
    out["compose.yml"] = DockerRuntime().render(plan, tmp_path / "state").compose_yaml
    out["Dockerfile.derived"] = plan.derived_dockerfile or ""
    out["plan.json"] = json.dumps({
        "image": plan.image, "command": plan.command, "environment": plan.environment,
        "enforcer_env": plan.enforcer_env, "passthrough_env": plan.passthrough_env,
        "transcripts": [plan.transcripts_host_dir, plan.transcripts_container_dir],
    }, indent=2, sort_keys=True) + "\n"
    repo = str(Path(__file__).resolve().parent.parent)
    subs = [(str(tmp_path.resolve()), "<TMP>"), (str(tmp_path), "<TMP>"), (repo, "<REPO>"),
            (os.path.realpath(os.environ["GLOVE_HOME"]), "<GLOVE_HOME>"), (os.environ["GLOVE_HOME"], "<GLOVE_HOME>")]
    for k, v in out.items():
        for a, b in subs:
            v = v.replace(a, b)
        out[k] = v
    return out


@pytest.mark.parametrize("name", sorted(CASES))
def test_harness_render_is_unchanged(name, tmp_path):
    got = _render(CASES[name], tmp_path)
    root = GOLDEN / name
    if UPDATE:
        if root.exists():
            for f in sorted(root.rglob("*"), reverse=True):
                f.unlink() if f.is_file() else f.rmdir()
        for rel, text in got.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text)
    want = {str(f.relative_to(root)): f.read_text() for f in root.rglob("*") if f.is_file()}
    assert sorted(got) == sorted(want), "rendered file set changed"
    for rel in sorted(want):
        assert got[rel] == want[rel], f"{name}/{rel} changed"
