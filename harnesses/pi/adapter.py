"""Pi adapter: models.json + settings.json, and Pi's `-e` extensions.

Extensions contribute Pi code as `harness: {pi: {extensions: [<dir>, …]}}`
(Pi has no MCP): each directory is baked into the derived image under
/opt/glove/ext/<ext>/ and loaded with `pi -e <path>`. Skills come from the
neutral `harness.skills` contribution (`comp.skills`).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from glove.extensions import ExtensionError, active_items
from glove.harnessconfig import rel_config_home
from glove.image import staged_name

# What Pi sends when the endpoint needs no key (Pi refuses a provider without one).
NO_KEY_PLACEHOLDER = "glove-no-key"
SECTION_KEYS = frozenset({"extensions"})


def extensions(comp) -> list[tuple[str, Path]]:
    """(extension, source dir) of every Pi extension the session's extensions contribute."""
    out: list[tuple[str, Path]] = []
    for a, section, ctx in comp.harness_items:
        where = f"extension {a.name!r} harness"
        if not isinstance(section, dict) or set(section) - SECTION_KEYS:
            raise ExtensionError(f"{where}: `pi:` takes {sorted(SECTION_KEYS)}")
        for item in active_items(section.get("extensions"), ctx):
            src = a.manifest.path / (item["src"] if isinstance(item, dict) else item)
            if not src.is_dir():
                raise ExtensionError(f"{where}: pi extension {src} not found")
            out.append((a.name, src))
    return out


def extension_dest(ext: str, src: Path) -> str:
    return f"/opt/glove/ext/{ext}/{src.name}"


def entry_args(comp) -> list[str]:
    return [arg for ext, src in extensions(comp) for arg in ("-e", extension_dest(ext, src))]


def image_lines(comp) -> tuple[list[str], list[tuple[str, Path]]]:
    lines: list[str] = []
    staged: list[tuple[str, Path]] = []
    for ext, src in extensions(comp):
        dest = extension_dest(ext, src)
        staged.append((ext, src))
        lines.append(f"# extension: {ext} (Pi extension)")
        lines.append(f"COPY {staged_name(ext, src)} {dest}")
        if (src / "package.json").is_file():
            lines.append(f"RUN cd {dest} && npm install --no-audit --no-fund")
    return lines, staged


def describe(comp) -> list[str]:
    """Lines for `glove plan`."""
    return [f"pi extension ({ext}): {extension_dest(ext, src)}" for ext, src in extensions(comp)]


def _pi_model(entry: dict[str, Any], model) -> dict[str, Any]:
    """One Pi model entry; `entry` may override id/vision/context for extra models."""
    mid = entry.get("id", model.model)
    reasoning = bool(entry.get("reasoning", model.reasoning))
    out: dict[str, Any] = {
        "id": mid,
        "name": f"{mid} (glove)",
        "reasoning": reasoning,
        "input": ["text", "image"] if entry.get("vision", model.vision) else ["text"],
        "contextWindow": int(entry.get("context_window", model.context_window)),
        "maxTokens": int(entry.get("max_tokens", model.max_tokens)),
        "cost": {"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0},
    }
    if reasoning:
        out["thinkingLevelMap"] = {"off": "none", "low": "low", "medium": "medium", "xhigh": "xhigh"}
    return out


def render_home(cfg, profile, home_dir: Path, model, comp=None) -> list[Path]:
    cfg_dir = home_dir / rel_config_home(profile)
    cfg_dir.mkdir(parents=True, exist_ok=True)
    model_id = model.model

    glove_provider: dict[str, Any] = {"baseUrl": model.base_url, "api": model.api}
    # Pi treats a provider with no credential as unconfigured ("No models
    # available"). When the endpoint needs a key, name the env var glove passes
    # the harness (Pi resolves "$VAR" in apiKey), so the key itself is never
    # written into the home.
    # Keyless servers (e.g. llama-server without --api-key) ignore it, but Pi
    # still needs a non-empty value: it is a fixed placeholder, not a secret.
    glove_provider["apiKey"] = f"${model.api_key_env}" if model.api_key_env else NO_KEY_PLACEHOLDER
    if model.api == "openai-completions":
        glove_provider["compat"] = {
            "supportsDeveloperRole": False,
            "supportsReasoningEffort": model.reasoning,
            "thinkingFormat": "reasoning_effort",
            "maxTokensField": "max_tokens",
        }
    models = [_pi_model({}, model), *(_pi_model(dict(e), model) for e in model.extra_models)]
    models_json = {"providers": {"glove": {**glove_provider, "models": models}}}
    settings_json = {
        "defaultProvider": "glove",
        "defaultModel": model_id,
        "defaultThinkingLevel": "low",
        "theme": "dark",
    }
    # Endpoint URLs (e.g. SEARXNG_URL) reach Pi as container env from the
    # extensions' `harness.env`, which the Pi extensions read directly.

    # Let the (git-tracked) session file's `harness_config` override Pi settings
    # and model fields without a code change — e.g. `defaultThinkingLevel: xhigh`,
    # or extra per-model tuning if the endpoint supports it. `env` is deep-merged.
    extra_settings = dict(cfg.harness_config.get("settings", {}))
    extra_env = extra_settings.pop("env", None)
    # extensions' skills first, then any the session file lists itself
    skills = [dest for _, _, dest in (comp.skills if comp else [])]
    settings_json.update(extra_settings)
    if skills:
        settings_json["skills"] = [*skills, *(s for s in extra_settings.get("skills") or [] if s not in skills)]
    if extra_env:
        settings_json.setdefault("env", {}).update(extra_env)
    model_overrides = cfg.harness_config.get("model", {})
    if model_overrides:
        models[0].update(model_overrides)

    written: list[Path] = []
    for name, data in (
        ("models.json", models_json),
        ("settings.json", settings_json),
    ):
        p = cfg_dir / name
        p.write_text(json.dumps(data, indent=2) + "\n")
        written.append(p)

    # glove's always-on enforcer extension (and any selected extensions' Pi
    # extensions) are baked into the image and loaded via `pi -e`; nothing to
    # seed here. A user extensions/ dir in the config home still auto-loads and
    # is left untouched.
    (cfg_dir / "extensions").mkdir(parents=True, exist_ok=True)
    return written
