"""`toolchains`: the blocks, checked against the session dir, become image
layers, harness env and a brief (toolchains.py does the work)."""

from __future__ import annotations

from typing import Any

from glove.api import ConfigError, HookContext, hook

from . import toolchains as tcs  # its `resolve` would read as the hook of that name


@hook
def contribute(ctx: HookContext) -> dict[str, Any]:
    blocks = tcs.resolve(ctx.settings["blocks"], ctx.session_dir)
    # the grant widens ring 1 for Chromium only: never without a browser to start
    if ctx.enforcer_options["nono"]["browsers"] and not any(tc.browsers for tc in blocks):
        raise ConfigError("enforcer_options.nono.browsers grants shell commands /proc for Chromium, but no "
                          "block bakes `browsers:`; drop the option or add the browsers")
    if not blocks:
        return {}
    return {"harness": {"image": tcs.image_layers(blocks), "env": tcs.harness_env(blocks),
                        "brief": tcs.brief(blocks, ctx.enforcer, ctx.enforcer_options)}}
