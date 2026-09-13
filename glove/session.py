"""Session lifecycle: bring up sidecars, run the harness on a
PTY, tear the project down.

The heavy validation (mounts, network, compose render) happens in the render
path; this module only shells out to the provider's compose CLI.
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from rich.console import Console

from .compose import FORWARDER_IMAGE, TEMPLATES_DIR
from .config import Config
from .harness import HarnessProfile, effective_image, get_profile
from .network import build_network_plan

console = Console()


def _image_exists(provider: str, tag: str) -> bool:
    return (
        subprocess.run(
            [provider, "image", "inspect", tag],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode
        == 0
    )


def build_forwarder(provider: str, *, force: bool = False) -> None:
    if not force and _image_exists(provider, FORWARDER_IMAGE):
        return
    console.print(f"[bold]building forwarder image[/bold] {FORWARDER_IMAGE}")
    subprocess.run(
        [
            provider, "build", "-t", FORWARDER_IMAGE,
            "-f", str(TEMPLATES_DIR / "forwarder.Dockerfile"),
            str(TEMPLATES_DIR),
        ],
        check=True,
    )


def _build_base(
    provider: str,
    profile: HarnessProfile,
    apt_packages: list[str],
    pip_packages: list[str],
    srt: bool,
    tag: str,
    *,
    force: bool,
) -> None:
    """Build (or reuse) the harness's base image from its own Dockerfile."""
    if not force and _image_exists(provider, tag):
        return
    if not profile.dockerfile.exists():
        raise FileNotFoundError(f"no Dockerfile for harness {profile.name}: {profile.dockerfile}")
    context = profile.dockerfile.parent
    console.print(f"[bold]building base image[/bold] {tag}  (context: {context})")
    cmd = [provider, "build", "-t", tag]
    if apt_packages:
        cmd += ["--build-arg", f"GLOVE_APT={' '.join(apt_packages)}"]
    if pip_packages:
        cmd += ["--build-arg", f"GLOVE_PIP={' '.join(pip_packages)}"]
    if srt:
        cmd += ["--build-arg", "GLOVE_ENFORCER=srt"]
    cmd.append(str(context))
    subprocess.run(cmd, check=True)


def build_harness(
    provider: str,
    profile: HarnessProfile,
    *,
    apt_packages: list[str] | None = None,
    pip_packages: list[str] | None = None,
    plugins: list[str] | None = None,
    enforcer: str = "nono",
    force: bool = False,
) -> str:
    """Build the session image: the minimal base, plus a derived layer per
    enabled plugin. Returns the tag the session should run.

    With no plugins the base *is* the session image (byte-identical to a bare
    base build). With plugins, the base stays cached and the plugin layers are
    composed on top as a distinct, hash-tagged derived image."""
    apt_packages = apt_packages or []
    pip_packages = pip_packages or []
    plugin_names = plugins or []
    srt = enforcer == "srt"

    base_tag = effective_image(profile, apt_packages, pip_packages)
    final_tag = effective_image(profile, apt_packages, pip_packages, plugin_names)
    if srt:
        base_tag = f"{base_tag}-srt"
        final_tag = f"{final_tag}-srt"

    if not force and _image_exists(provider, final_tag):
        return final_tag

    _build_base(provider, profile, apt_packages, pip_packages, srt, base_tag, force=force)
    if not plugin_names:
        return base_tag  # == final_tag: no derived layer to compose

    from .plugins import resolve_plugins
    from .plugins.image import render_dockerfile, stage_context

    resolved = resolve_plugins(plugin_names)
    with tempfile.TemporaryDirectory(prefix="glove-build-") as ctx:
        ctx_dir = Path(ctx)
        stage_context(ctx_dir, profile, resolved)
        dockerfile = ctx_dir / "Dockerfile"
        dockerfile.write_text(render_dockerfile(base_tag, profile, resolved))
        console.print(
            f"[bold]composing plugin image[/bold] {final_tag}  "
            f"(plugins: {', '.join(plugin_names)})"
        )
        subprocess.run(
            [provider, "build", "-t", final_tag, "-f", str(dockerfile), str(ctx_dir)],
            check=True,
        )
    return final_tag


def ensure_images(cfg: Config, provider: str, *, rebuild: bool = False) -> None:
    profile = get_profile(cfg.harness)
    if build_network_plan(cfg, cfg.resolved_name()).sidecars:
        build_forwarder(provider, force=rebuild)
    build_harness(
        provider,
        profile,
        apt_packages=cfg.apt_packages,
        pip_packages=cfg.pip_packages,
        plugins=cfg.plugins,
        enforcer=cfg.enforcer,
        force=rebuild,
    )


def _compose_base(provider: str, project: str, compose_file: Path) -> list[str]:
    # Both docker and podman expose a `compose` subcommand in this environment.
    return [provider, "compose", "-p", project, "-f", str(compose_file)]


def launch(cfg: Config, session_dir: Path, *, provider: str, rebuild: bool) -> None:
    session = cfg.resolved_name()
    project = f"glove-{session}"
    compose_file = session_dir / "docker-compose.yml"
    base = _compose_base(provider, project, compose_file)

    plan = build_network_plan(cfg, session)
    forwarder_services = [f"glove-{session}-{s.role}" for s in plan.sidecars]

    ensure_images(cfg, provider, rebuild=rebuild)

    if forwarder_services:
        console.print("[bold]starting forwarders…[/bold] " + ", ".join(forwarder_services))
        subprocess.run([*base, "up", "-d", *forwarder_services], check=True)

    console.print("[bold]launching harness (Ctrl-D to exit)…[/bold]")
    try:
        subprocess.run(
            [*base, "run", "--rm", "-it", f"glove-{session}-harness"], check=False
        )
    finally:
        console.print(
            f"[dim]harness exited; forwarders still up. "
            f"Run `glove down {session}` to tear down.[/dim]"
        )


def teardown(session: str, *, provider: str, wipe: bool) -> None:
    project = f"glove-{session}"
    cmd = [provider, "compose", "-p", project, "down"]
    if wipe:
        cmd.append("--volumes")
    console.print(f"[bold]tearing down[/bold] {project}")
    subprocess.run(cmd, check=False)
