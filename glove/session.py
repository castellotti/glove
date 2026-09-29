"""Session lifecycle: bring up sidecars, run the harness on a
PTY, tear the project down.

The heavy validation (mounts, network, compose render) happens in the render
path; this module only shells out to the provider's compose CLI.
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

import yaml
from rich.console import Console

from .config import Config
from .harness import HarnessProfile, effective_image
from .plan import FORWARDER_IMAGE
from .runtimes.docker import TEMPLATES_DIR

if TYPE_CHECKING:
    from .plan import SessionPlan

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
    enforcer: str = "nono",
    plan: SessionPlan | None = None,
    force: bool = False,
) -> str:
    """Build the session image: the minimal base, plus — when the plan's
    extensions contribute image layers or Pi extensions — a derived image on
    top (content-addressed tag, see glove/image.py). Returns the tag to run."""
    apt_packages = apt_packages or []
    pip_packages = pip_packages or []
    srt = enforcer == "srt"
    base_tag = effective_image(profile, apt_packages, pip_packages)
    if srt:
        base_tag = f"{base_tag}-srt"
    final_tag = plan.image if plan is not None else base_tag
    if not force and _image_exists(provider, final_tag):
        return final_tag
    _build_base(provider, profile, apt_packages, pip_packages, srt, base_tag, force=force)
    if final_tag == base_tag or plan is None or plan.composition is None:
        return base_tag

    from .image import render_dockerfile, stage_context

    dockerfile, staged = render_dockerfile(base_tag, profile, plan.composition)
    with tempfile.TemporaryDirectory(prefix="glove-build-") as ctx:
        ctx_dir = Path(ctx)
        stage_context(ctx_dir, staged)
        (ctx_dir / "Dockerfile").write_text(dockerfile)
        names = ", ".join(sorted({e for e, _ in plan.composition.image_layers} | {e for e, _ in staged}))
        console.print(f"[bold]composing extension image[/bold] {final_tag}  (extensions: {names})")
        subprocess.run(
            [provider, "build", "-t", final_tag, "-f", str(ctx_dir / "Dockerfile"), str(ctx_dir)],
            check=True,
        )
    return final_tag


def build_extension_images(provider: str, plan: SessionPlan, *, force: bool = False) -> None:
    """Build every image an active extension declares (`images:` in its manifest)."""
    from .extensions import image_tag

    if plan.composition is None:
        return
    for a in plan.composition.active:
        for name, spec in (a.manifest.raw.get("images") or {}).items():
            tag = image_tag(a, name)
            if not force and _image_exists(provider, tag):
                continue
            ctx = a.manifest.path / str((spec or {}).get("build", name))
            console.print(f"[bold]building extension image[/bold] {tag}")
            subprocess.run([provider, "build", "-t", tag, str(ctx)], check=True)


def ensure_images(cfg: Config, plan: SessionPlan, provider: str, *, rebuild: bool = False) -> None:
    from .observe import build_netgate

    if len(plan.network.gated) < len(plan.network.sidecars):
        build_forwarder(provider, force=rebuild)
    if plan.network.gated:
        build_netgate(provider, force=rebuild, console=console)
    build_extension_images(provider, plan, force=rebuild)
    build_harness(
        provider,
        plan.profile,
        apt_packages=cfg.apt_packages,
        pip_packages=cfg.pip_packages,
        enforcer=cfg.enforcer,
        plan=plan,
        force=rebuild,
    )


def _compose_base(provider: str, project: str, compose_file: Path) -> list[str]:
    # Both docker and podman expose a `compose` subcommand in this environment.
    return [provider, "compose", "-p", project, "-f", str(compose_file)]


_SENSITIVE = re.compile(r"private.?key|password|passwd|secret|token", re.I)


def redact_log(text: str) -> str:
    """A sidecar's log without lines that may carry credentials (gluetun, for
    one, prints a truncated WireGuard private key in its settings summary)."""
    return "\n".join(line for line in text.strip().splitlines() if not _SENSITIVE.search(line))


def start_sidecars(plan: SessionPlan, compose_file: Path, *, provider: str, env: dict[str, str]) -> None:
    """`compose up -d` every sidecar, then run the extensions' verify checks.

    Sidecars that mount a compose secret are always recreated: compose does not
    notice a changed secret value (a rotated Keychain entry, a freshly
    registered VPN key). A failed check stops the project (fail closed) after
    showing the failing sidecar's last log lines."""
    from .verify import VerifyError, run_verify

    base = _compose_base(provider, plan.project, compose_file)
    doc = yaml.safe_load(compose_file.read_text()) or {}
    services = doc.get("services") or {}
    sidecars = [n for n in services if n != plan.harness_service]
    if not sidecars:
        return
    with_secrets = [n for n in sidecars if services[n].get("secrets")]
    console.print("[bold]starting sidecars…[/bold] " + ", ".join(sidecars))
    if with_secrets:
        subprocess.run([*base, "up", "-d", "--force-recreate", *with_secrets], check=True, env=env)
    subprocess.run([*base, "up", "-d", *sidecars], check=True, env=env)
    if plan.composition is None or not plan.composition.verify:
        return
    console.print("[bold]verifying…[/bold]")
    try:
        run_verify(provider, plan, lambda m: console.print(f"[dim]{m}[/dim]" if "retry" in m else m))
    except VerifyError as e:
        if e.service:
            name = f"glove-{plan.session}-{e.service}"
            logs = subprocess.run([provider, "logs", "--tail", "25", name], capture_output=True, text=True)
            console.print(f"[dim]--- last log lines of {name} (key/password lines withheld):[/dim]")
            console.print(redact_log(logs.stdout + logs.stderr)[-3000:], markup=False)
        console.print("[bold red]verify failed — stopping the session's sidecars (fail closed).[/bold red]")
        subprocess.run([*base, "down"], env=env, capture_output=True)
        raise


def launch(
    cfg: Config,
    plan: SessionPlan,
    compose_file: Path,
    *,
    provider: str,
    rebuild: bool,
    secrets: dict[str, str],
    prepare: Callable[[], None] | None = None,
) -> None:
    """Build, start and verify every sidecar, run `prepare()` (launch-time
    resolution and the harness home), then run the harness on a PTY.

    `secrets` is the already-resolved secret_env(plan): it is passed to compose
    only in this process environment, never written to a file."""
    base = _compose_base(provider, plan.project, compose_file)
    ensure_images(cfg, plan, provider, rebuild=rebuild)
    env = {**os.environ, **secrets}
    start_sidecars(plan, compose_file, provider=provider, env=env)
    if prepare is not None:
        prepare()

    console.print("[bold]launching harness (Ctrl-D to exit)…[/bold]")
    try:
        subprocess.run([*base, "run", "--rm", "-it", plan.harness_service], check=False, env=env)
    finally:
        console.print(
            "[dim]harness exited; sidecars still up. Run `glove down` in the session "
            "directory to tear down.[/dim]"
        )


def probe_http(
    provider: str, plan: SessionPlan, url: str, *, method: str = "GET", body: dict | None = None,
    auth_env: dict[str, str] | None = None, auth_header: str = "Authorization", auth_scheme: str = "Bearer",
) -> tuple[int, str]:
    """HTTP request from a throwaway, hardened container on the harness network,
    so the host never resolves or contacts the endpoint itself. A key travels
    only as an env var of that container (never in any argv)."""
    import json as _json

    script = 'curl -sS -m 20 -o /tmp/b -w "%{http_code}" -X "$M" "$U"'
    if body is not None:
        script += ' -H "content-type: application/json" --data "$B"'
    if auth_env:
        prefix = f"{auth_scheme} " if auth_scheme else ""
        script += f' -H "{auth_header}: {prefix}$GLOVE_LLM_API_KEY"'
    script += "; echo; cat /tmp/b"
    cmd = [
        provider, "run", "--rm", "--network", plan.network.internal_network,
        "--user", f"{plan.uid}:{plan.gid}", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
        "--read-only", "--tmpfs", "/tmp", "-e", "M", "-e", "U", "-e", "B",
        *(["-e", "GLOVE_LLM_API_KEY"] if auth_env else []),
        "--entrypoint", "sh", plan.image, "-c", script,
    ]
    env = {**os.environ, "M": method, "U": url, "B": _json.dumps(body or {}), **(auth_env or {})}
    r = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=90, check=False)
    head, _, rest = r.stdout.partition("\n")
    try:
        return int(head.strip() or 0), rest
    except ValueError:
        return 0, (r.stdout + r.stderr)[-400:]


def teardown(session: str, *, provider: str, wipe: bool) -> None:
    project = f"glove-{session}"
    cmd = [provider, "compose", "-p", project, "down"]
    if wipe:
        cmd.append("--volumes")
    console.print(f"[bold]tearing down[/bold] {project}")
    subprocess.run(cmd, check=False)
