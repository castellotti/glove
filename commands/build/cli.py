"""`glove build` — the forwarder and harness base images."""

from __future__ import annotations

import typer

from glove.api.commands import autodetect_provider, build_forwarder, build_harness, get_profile, known_harnesses


def command(
    harness: str | None = typer.Argument(
        None, help=f"harness image to build ({', '.join(known_harnesses())}); "
                   "omit to build the forwarder only"
    ),
    provider: str | None = typer.Option(None),
    enforcer: str | None = typer.Option(None, "--enforcer", help="enforcer variant (srt, nono+srt → -srt image)"),
    rebuild: bool = typer.Option(False, "--rebuild", help="force rebuild"),
) -> None:
    """Build the forwarder and (optionally) a harness base image. Extension
    images and layers are built per session by `glove up`."""
    prov = provider or autodetect_provider()
    build_forwarder(prov, force=rebuild)
    if harness:
        build_harness(prov, get_profile(harness), enforcer=enforcer or "nono", force=rebuild)
