"""Claude Code adapter (experimental stub; replaced in the claude-code-harness phase)."""

from __future__ import annotations

import json
from pathlib import Path

from glove.harnessconfig import rel_config_home


def render_home(cfg, profile, home_dir: Path, model, comp=None) -> list[Path]:
    cfg_dir = home_dir / rel_config_home(profile)
    cfg_dir.mkdir(parents=True, exist_ok=True)
    # Claude Code speaks the Anthropic API; an OpenAI-compatible base only works
    # via a shim, so we just record settings for reference.
    settings = {
        "env": {
            "ANTHROPIC_BASE_URL": model.base_url.removesuffix("/v1"),
            "ANTHROPIC_MODEL": model.model,
        }
    }
    p = cfg_dir / "settings.json"
    p.write_text(json.dumps(settings, indent=2) + "\n")
    return [p]
