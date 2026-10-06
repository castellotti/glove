"""github hooks.

`launch_env()` runs on the host at `glove up`: it resolves the token reference
(`keychain:`/`env:`) in memory and hands it to the relay sidecar's environment
for this `compose up` only (RELAY_GITHUB_TOKEN, declared without a value in the
fragment, like llm-auth's LLM_AUTH_KEY). Not a compose secret: Docker cannot put
an environment-sourced secret file into a read-only container, and the sidecar
keeps its read-only rootfs. relayd hands it only to gh and git.
"""

from __future__ import annotations

from typing import Any


def launch_env(ctx: dict[str, Any], resolve_secret) -> dict[str, Any]:
    token = resolve_secret(ctx["settings"]["token"]).strip()
    if not token:
        raise ValueError("github.token resolves to an empty value")
    return {"env": {"RELAY_GITHUB_TOKEN": token}}
