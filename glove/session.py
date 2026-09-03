"""Session lifecycle (DESIGN.md A.7): bring up sidecars, run the harness on a
PTY, tear the project down.

The heavy validation (mounts, network, compose render) happens in the render
path; this module only shells out to the provider's compose CLI.
"""

from __future__ import annotations

import subprocess
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


def build_harness(
    provider: str,
    profile: HarnessProfile,
    *,
    apt_packages: list[str] | None = None,
    pip_packages: list[str] | None = None,
    enforcer: str = "nono",
    force: bool = False,
) -> str:
    apt_packages = apt_packages or []
    pip_packages = pip_packages or []
    tag = effective_image(profile, apt_packages, pip_packages)
    # srt needs bwrap/socat/srt baked in; build a distinct `-srt` image (§4.3).
    if enforcer == "srt":
        tag = f"{tag}-srt"
    if not force and _image_exists(provider, tag):
        return tag
    context = profile.dockerfile.parent
    if not profile.dockerfile.exists():
        raise FileNotFoundError(f"no Dockerfile for harness {profile.name}: {profile.dockerfile}")
    console.print(f"[bold]building harness image[/bold] {tag}  (context: {context})")
    cmd = [provider, "build", "-t", tag]
    if apt_packages:
        cmd += ["--build-arg", f"GLOVE_APT={' '.join(apt_packages)}"]
    if pip_packages:
        cmd += ["--build-arg", f"GLOVE_PIP={' '.join(pip_packages)}"]
    if enforcer == "srt":
        cmd += ["--build-arg", "GLOVE_ENFORCER=srt"]
    cmd.append(str(context))
    subprocess.run(cmd, check=True)
    return tag


def ensure_images(cfg: Config, provider: str, *, rebuild: bool = False) -> None:
    profile = get_profile(cfg.harness)
    if build_network_plan(cfg, cfg.resolved_name()).sidecars:
        build_forwarder(provider, force=rebuild)
    build_harness(
        provider,
        profile,
        apt_packages=cfg.apt_packages,
        pip_packages=cfg.pip_packages,
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
