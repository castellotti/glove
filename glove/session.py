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

from rich.console import Console

from .cafile import TRUST_DIR, trust_script
from .config import Config, ConfigError, load_yaml
from .enforcers.base import SRT_IMAGE_DIR, srt_suffix, uses_srt
from .harness import HarnessProfile, base_contexts, effective_image
from .mounts import missing_bind_targets
from .naming import project_name, scoped
from .plan import FORWARDER_DIR, forwarder_image
from .runtimes import get_runtime

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


def _build(provider: str, *args: str) -> None:
    """`<provider> build` without BuildKit's default provenance attestation (a new digest each build:
    a forced rebuild of the base made every image FROM it miss Docker's cache, `up --rebuild`)."""
    subprocess.run([provider, "build", *args], check=True, env={**os.environ, "BUILDX_NO_DEFAULT_ATTESTATIONS": "1"})


def build_forwarder(provider: str, *, force: bool = False) -> None:
    tag = forwarder_image()
    if not force and _image_exists(provider, tag):
        return
    console.print(f"[bold]building forwarder image[/bold] {tag}")
    _build(provider, "-t", tag, str(FORWARDER_DIR))


def _build_base(
    provider: str,
    profile: HarnessProfile,
    apt_packages: list[str],
    pip_packages: list[str],
    tag: str,
    *,
    force: bool,
) -> None:
    """Build (or reuse) the harness's base image from its own Dockerfile."""
    if not force and _image_exists(provider, tag):
        return
    if not profile.dockerfile.exists():
        raise FileNotFoundError(f"no Dockerfile for harness {profile.name}: {profile.dockerfile}")
    (_, context), *named = base_contexts(profile)
    console.print(f"[bold]building base image[/bold] {tag}  (context: {context})")
    args = ["-t", tag, "--build-arg", f"HARNESS_VERSION={profile.version}"]
    for name, path in named:
        args += ["--build-context", f"{name}={path}"]
    if apt_packages:
        args += ["--build-arg", f"GLOVE_APT={' '.join(apt_packages)}"]
    if pip_packages:
        args += ["--build-arg", f"GLOVE_PIP={' '.join(pip_packages)}"]
    _build(provider, *args, str(context))


def _build_srt_layer(provider: str, base: str, tag: str, *, force: bool) -> None:
    """`<base>-srt`: the srt overlay (srt, bubblewrap, glove's apply-seccomp and
    glove-pty) on a harness base image."""
    if not force and _image_exists(provider, tag):
        return
    console.print(f"[bold]building srt layer[/bold] {tag}  (on {base})")
    _build(provider, "-t", tag, "--build-arg", f"BASE={base}", str(SRT_IMAGE_DIR))


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
    plain_tag = effective_image(profile, apt_packages, pip_packages)
    base_tag = f"{plain_tag}{srt_suffix()}" if uses_srt(enforcer) else plain_tag
    final_tag = plan.image if plan is not None else base_tag
    if not force and _image_exists(provider, final_tag):
        return final_tag
    _build_base(provider, profile, apt_packages, pip_packages, plain_tag, force=force)
    if base_tag != plain_tag:
        _build_srt_layer(provider, plain_tag, base_tag, force=force)
    if final_tag == base_tag or plan is None:
        return base_tag

    from .image import stage_context

    dockerfile, staged = plan.derived_dockerfile, plan.derived_staged
    with tempfile.TemporaryDirectory(prefix="glove-build-") as ctx:
        ctx_dir = Path(ctx)
        stage_context(ctx_dir, staged)
        (ctx_dir / "Dockerfile").write_text(dockerfile)
        names = ", ".join(sorted({e for e, _ in plan.composition.image_layers} | {e for e, _ in staged}))
        console.print(f"[bold]composing extension image[/bold] {final_tag}  (extensions: {names})")
        _build(provider, "-t", final_tag, "-f", str(ctx_dir / "Dockerfile"), str(ctx_dir))
    return final_tag


def build_extension_images(provider: str, plan: SessionPlan, *, force: bool = False) -> None:
    """Build every image an active extension declares (`images:` in its manifest)."""
    from .extensions import image_tag, when_context, when_matches

    for a in plan.composition.active:
        for name, spec in (a.manifest.raw.get("images") or {}).items():
            ctx = when_context(a.settings, plan.composition.harness)
            if not when_matches((spec or {}).get("when"), ctx):
                continue  # e.g. the browser sidecar's image in host mode
            tag = image_tag(a, name)
            if not force and _image_exists(provider, tag):
                continue
            ctx = a.manifest.path / str((spec or {}).get("build", name))
            console.print(f"[bold]building extension image[/bold] {tag}")
            _build(provider, "-t", tag, str(ctx))


def ensure_images(cfg: Config, plan: SessionPlan, provider: str, *, rebuild: bool = False) -> None:
    if plan.network.socat:
        build_forwarder(provider, force=rebuild)
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


def compose_process_env(provider: str, secrets: dict[str, str] | None = None) -> dict[str, str]:
    """The environment of a `compose` process: glove's, the runtime's own
    (Podman's banner off) and the session's secrets (never in a file)."""
    return {**os.environ, **get_runtime(provider).compose_cli_env, **(secrets or {})}


def _compose_base(provider: str, project: str, compose_file: Path) -> list[str]:
    # Both docker and podman expose a `compose` subcommand in this environment.
    return [provider, "compose", "-p", project, "-f", str(compose_file)]




_SENSITIVE = re.compile(r"private.?key|password|passwd|secret|token", re.I)


def redact_log(text: str) -> str:
    """A sidecar's log without lines that may carry credentials (gluetun, for
    one, prints a truncated WireGuard private key in its settings summary)."""
    return "\n".join(line for line in text.strip().splitlines() if not _SENSITIVE.search(line))


class SubnetTaken(Exception):
    """Another session's network took this session's subnet between glove's
    check and compose creating the networks (two `glove up`s racing, each
    with its own registry): re-allocate and retry."""


def foreign_networks(provider: str, session: str) -> dict[str, list[str]]:
    """The runtime's existing networks that are not this session's, with their
    IPv4 subnets (none when the runtime can't be asked)."""
    try:
        nets = get_runtime(provider).network_subnets()
    except (ValueError, AttributeError, OSError):
        return {}
    own = scoped(session, "")
    return {name: subnets for name, subnets in nets.items() if not name.startswith(own)}


def _subnet_taken(provider: str, plan: SessionPlan) -> str | None:
    """The foreign network that now overlaps one of this session's subnets."""
    from .registry import overlapping

    for name, subnets in foreign_networks(provider, plan.session).items():
        hit = overlapping(subnets, plan.network.subnets.values())
        if hit:
            return f"{hit} ({name})"
    return None


def start_sidecars(plan: SessionPlan, compose_file: Path, *, provider: str, env: dict[str, str]) -> None:
    """`compose up -d` every sidecar, then run the extensions' verify checks.

    Sidecars that mount a compose secret are always recreated: compose does not
    notice a changed secret value (a rotated Keychain entry, a freshly
    registered VPN key). A failed check stops the project (fail closed) after
    showing the failing sidecar's last log lines."""
    from .verify import VerifyError, run_verify, sidecar_exec

    base = _compose_base(provider, plan.project, compose_file)
    doc = load_yaml(compose_file.read_text()) or {}
    services = doc.get("services") or {}
    sidecars = [n for n in services if n != plan.harness_service]
    if not sidecars:
        return
    with_secrets = [n for n in sidecars if services[n].get("secrets")]
    console.print("[bold]starting sidecars…[/bold] " + ", ".join(sidecars))
    # podman: one container at a time (see PodmanRuntime.serial_start)
    batches = [[n] for n in sidecars] if get_runtime(provider).serial_start else [sidecars]
    try:
        if with_secrets:
            subprocess.run([*base, "up", "-d", "--force-recreate", *with_secrets], check=True, env=env)
        for batch in batches:
            subprocess.run([*base, "up", "-d", "--remove-orphans", *batch], check=True, env=env)
        if scoped(plan.session, "mount-watch") in services:  # what changed while nothing watched (compose.yml.j2)
            walk = ["sh", "-c", "find /watch >/dev/null 2>&1 || true"]  # an unreadable entry: as unreadable there
            if sidecar_exec(provider, plan.session, "mount-watch", walk, 300)[0]:
                raise subprocess.CalledProcessError(1, walk, "mount-watch: walking the harness's binds failed")
    except subprocess.CalledProcessError:
        # never leave a half-started egress stack behind (fail closed)
        console.print("[bold red]starting the sidecars failed — stopping the session's sidecars.[/bold red]")
        teardown(plan.session, provider=provider, wipe=False)  # its anonymous volumes too
        taken = _subnet_taken(provider, plan)
        if taken:
            raise SubnetTaken(f"another network took this session's subnet meanwhile: {taken}") from None
        raise
    if not plan.composition.verify:
        return
    console.print("[bold]verifying…[/bold]")
    try:
        run_verify(provider, plan, lambda m: console.print(f"[dim]{m}[/dim]" if "retry" in m else m))
    except VerifyError as e:
        if e.service:
            name = scoped(plan.session, e.service)
            logs = subprocess.run([provider, "logs", "--tail", "25", name], capture_output=True, text=True)
            console.print(f"[dim]--- last log lines of {name} (key/password lines withheld):[/dim]")
            console.print(redact_log(logs.stdout + logs.stderr)[-3000:], markup=False)
        console.print("[bold red]verify failed — stopping the session's sidecars (fail closed).[/bold red]")
        teardown(plan.session, provider=provider, wipe=False)  # its anonymous volumes too
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
    env = compose_process_env(provider, secrets)
    start_sidecars(plan, compose_file, provider=provider, env=env)
    if prepare is not None:
        prepare()
    missing_bind_targets(plan.mounts, plan.protect, create=True)  # recorded at plan: `glove down` removes them

    console.print("[bold]launching harness (Ctrl-D to exit)…[/bold]")
    try:
        subprocess.run([*base, "run", "--rm", "-it", "--name", plan.harness_service, plan.harness_service],
                       check=False, env=env)
    finally:
        console.print(
            "[dim]harness exited; sidecars still up. Run `glove down` in the session "
            "directory to tear down.[/dim]"
        )


def clear_stale_harness(provider: str, name: str) -> None:
    """The harness runs under one name per session, so a second `glove up`
    can't start beside it. A running one is refused (`glove up` checks before
    it starts a host service or recreates a sidecar under it); a stopped one,
    left when its client was killed, is removed."""
    state = subprocess.run([provider, "container", "inspect", "-f", "{{.State.Running}}", name],
                           capture_output=True, text=True, check=False)
    if state.returncode != 0:
        return
    if state.stdout.strip() == "true":
        raise ConfigError(f"this session's harness is already running ({name}); "
                          "use that terminal, or `glove down` first")
    subprocess.run([provider, "rm", "-fv", name], stdout=subprocess.DEVNULL, check=False)


# curl exit codes that mean "nothing answers yet", and fail fast: 6 (the name
# does not resolve: a sidecar not yet on the network), 7 (refused), 52 (empty
# reply) and 56 (reset: a forwarder accepted but cannot relay yet).
FAST_FAILURES = frozenset({6, 7, 52, 56})
CONNECT_RETRIES = (1, 2, 3, 4)  # seconds between attempts


def probe_http(
    provider: str, plan: SessionPlan, url: str, *, method: str = "GET", body: dict | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, str]:
    """HTTP request from a throwaway, hardened container on the harness network,
    so the host never resolves or contacts the endpoint itself. It holds no
    key (llm-auth adds the provider's on the way); `headers` are public
    request headers (e.g. an API version). A fast failure (a sidecar or
    forwarder still starting) is retried after each of `CONNECT_RETRIES`
    seconds; see `_curl`."""
    # Trust what the harness trusts (`plan.trusted_cas`: a read-only channel's
    # file, corporate_ca's copy), bound read-only here too, in the same bundle.
    prelude = trust_script(plan.trusted_cas, dest="/tmp") if plan.trusted_cas else ""
    trust = [(c.volume(plan.session), c.path) for c in plan.composition.channels if c.trust]
    # glove's own copies, relabelled where the runtime labels binds (SELinux)
    own = [(plan.trust_host_dir, TRUST_DIR)] if plan.trusts_copies else []
    # in the session's user namespace, as the harness it stands in for (rootless
    # Podman's keep-id: what it mounts is owned by the session uid as seen there)
    return _curl(provider, plan.image, url, method=method, body=body, headers=headers, plan=plan,
                 network=plan.network.internal_network, mounts=trust, own=own, prelude=prelude,
                 retries=CONNECT_RETRIES)


def with_headers(probe, exports: dict) -> Callable[..., tuple[int, str]]:
    """`probe` as an extension hook calls it, `(url, method=, body=)`, sending
    the extension's public `probe_headers` export (e.g. an API version)."""
    def ask(url: str, method: str = "GET", body: dict | None = None) -> tuple[int, str]:
        return probe(url, method=method, body=body, headers=exports.get("probe_headers") or {})
    return ask


LOOPBACK = frozenset({"127.0.0.1", "localhost", "::1"})


def probe_direct(provider: str, url: str, *, method: str = "GET", body: dict | None = None,
                 headers: dict[str, str] | None = None) -> tuple[int, str]:
    """`glove check`'s request to a server the session reaches, before anything
    is up: from a throwaway, hardened container on the runtime's default
    bridge, dialled as a forwarder dials it (direct, IPv4, never through a
    proxy), so the host never resolves or contacts it either. A loopback host
    is this machine, reached as a host-gateway forwarder reaches it. See `_curl`."""
    from urllib.parse import urlsplit

    from .verify import PROBE_IMAGE

    add_hosts: tuple[str, ...] = ()
    u = urlsplit(url)
    if u.hostname in LOOPBACK:
        gateway = get_runtime(provider).caps.host_gateway_name
        url = u._replace(netloc=gateway + (f":{u.port}" if u.port else "")).geturl()
        add_hosts = (f"{gateway}:host-gateway",)
    return _curl(provider, PROBE_IMAGE, url, method=method, body=body, headers=headers, network="bridge",
                 ipv4=True, add_hosts=add_hosts)


def _curl(
    provider: str, image: str, url: str, *, network: str, method: str = "GET", body: dict | None = None,
    headers: dict[str, str] | None = None, plan: SessionPlan | None = None, mounts=(), own=(), prelude: str = "",
    ipv4: bool = False, retries: tuple[int, ...] = (), add_hosts=(),
) -> tuple[int, str]:
    """curl `url` in a throwaway, hardened container: (status, body). Status 0:
    no HTTP answer (the text is then curl's own message, or the container's).
    A fast failure (`FAST_FAILURES`) is retried inside the one container after
    each of `retries` seconds; a timeout is not. Values travel as env vars; a
    `prelude` that builds /tmp/bundle.pem (cafile.trust_script) makes curl trust it."""
    import json as _json
    import shlex

    flags = ("--cacert /tmp/bundle.pem " if prelude else "") + ("-4 " if ipv4 else "")
    curl = f'curl {flags}-sS -m 20 -o /tmp/b -w "%{{http_code}}" -X "$M" "$U"'
    for k, v in (headers or {}).items():
        curl += " -H " + shlex.quote(f"{k}: {v}")
    if body is not None:
        curl += ' -H "content-type: application/json" --data "$B"'
    waits = " ".join(str(w) for w in (*retries, 0))
    fast = "|".join(str(c) for c in sorted(FAST_FAILURES))
    # "<http code> <curl exit code>", then the body
    script = (f'{prelude}for w in {waits}; do code=$({curl}); rc=$?; '
              f'case $rc in {fast}) [ "$w" -gt 0 ] && sleep "$w" && continue;; esac; break; done; '
              'echo "$code $rc"; cat /tmp/b 2>/dev/null')
    cmd = get_runtime(provider).throwaway_argv(
        image, ["-c", script], plan=plan, network=network, env=("M", "U", "B"), mounts=mounts, own=own,
        entrypoint="sh", add_hosts=add_hosts)
    env = {**os.environ, "M": method, "U": url, "B": _json.dumps(body or {})}
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=90, check=False)
    except subprocess.TimeoutExpired:
        return 0, "the probe container timed out"
    except FileNotFoundError:  # the runtime's CLI is not installed
        return 0, f"{provider} is not installed"
    head, _, rest = r.stdout.partition("\n")
    try:
        status, curl_rc = (int(x) for x in head.split())
    except ValueError:  # the probe container itself failed
        return 0, (r.stdout + r.stderr)[-400:]
    return status, rest if curl_rc == 0 else r.stderr[-400:]


def teardown(session: str, *, provider: str, wipe: bool) -> None:
    project = project_name(session)
    console.print(f"[bold]tearing down[/bold] {project}")
    # a `compose run` (the harness) whose client was killed leaves its container,
    # which `down` keeps, and with it the networks (Podman's compose keeps it even
    # with --remove-orphans): remove the project's runs first
    runs = subprocess.run([provider, "ps", "-aq", "--filter", f"label=com.docker.compose.project={project}",
                           "--filter", "label=com.docker.compose.oneoff=True"],
                          capture_output=True, text=True, check=False).stdout.split()
    if runs:
        subprocess.run([provider, "rm", "-fv", *runs], stdout=subprocess.DEVNULL, check=False)
    # `down` keeps anonymous volumes (each `up` adds more): `rm -fsv` stops the services and removes
    # them first, named volumes stay; --remove-orphans: services since removed
    for args in (["rm", "-fsv"], ["down", "--remove-orphans", *(["--volumes"] if wipe else [])]):
        subprocess.run([provider, "compose", "-p", project, *args], check=False, env=compose_process_env(provider))
