"""The ``docker`` runtime — full implementation for v2.

Renders the per-session compose project from a ``SessionPlan`` (evolving v1's
``compose.py`` + template), enforces the hardening set before writing
anything, and exposes the container/landlock probes ``glove doctor`` needs.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

import yaml
from jinja2 import Environment, FileSystemLoader, StrictUndefined

from ..exports import validate_export_isolation
from ..hardening import HardeningError, validate_hardening
from .base import Check, RenderedProject, RunningSession, RuntimeCaps

if TYPE_CHECKING:
    from ..plan import SessionPlan

TEMPLATES_DIR = Path(__file__).parent.parent / "templates"

# Fully-qualified so podman's short-name resolution never prompts; docker
# resolves it identically.
PROBE_IMAGE = "docker.io/library/python:3.12-slim"

# Compact probe run inside a hardened container: reports Landlock ABI, whether
# an unprivileged user namespace is creatable, /dev/kvm, and the effective caps.
_ENV_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

_PROBE = r"""
import ctypes, json, os
libc = ctypes.CDLL(None, use_errno=True)
def landlock_abi():
    try:
        # landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION=1)
        r = libc.syscall(444, 0, 0, 1)
        return r if r >= 0 else -ctypes.get_errno()
    except Exception:
        return None
def userns_ok():
    try:
        with open('/proc/sys/user/max_user_namespaces') as f:
            return int(f.read().strip()) > 0
    except Exception:
        return None
info = {
    'landlock_abi': landlock_abi(),
    'userns_ok': userns_ok(),
    'kvm': os.path.exists('/dev/kvm'),
    'uid': os.getuid(),
}
try:
    for line in open('/proc/self/status'):
        if line.startswith(('CapEff','NoNewPrivs','Seccomp:')):
            k, v = line.split(':', 1)
            info[k.strip()] = v.strip()
except Exception:
    pass
print(json.dumps(info))
"""


def tmpfs_volume_opts(uid: int, gid: int, context: str | None = None) -> str:
    """Mount options for an extension's tmpfs volume (e.g. the netgate events
    socket dir): owned by ``uid``/``gid`` as the mount sees ids, mode 0700, with
    an optional SELinux ``context=`` label."""
    opts = f"size=1m,mode=0700,uid={uid},gid={gid}"
    return f'{opts},context="{context}"' if context else opts


def _indent(block: dict) -> str:
    if not block:
        return ""
    text = yaml.safe_dump(block, sort_keys=False, default_flow_style=False)
    return "".join(f"  {line}\n" if line else "\n" for line in text.splitlines())


def _extension_blocks(plan: SessionPlan, extra: dict) -> dict[str, str]:
    """Extension sidecars/volumes/secrets as YAML text for the template."""
    from ..compose import harden_fragments

    blocks = harden_fragments(plan.composition, plan, extra)
    return {f"extension_{k}": _indent(v) for k, v in blocks.items()}


class DockerRuntime:
    name = "docker"
    caps = RuntimeCaps(
        supports_internal_networks=True,
        supports_sidecars=True,
        supports_seccomp_profile=True,
        supports_userns=True,
        supports_kvm=False,
        host_gateway_name="host.docker.internal",
        compose_cmd=("docker", "compose"),
        implemented=True,
        tested=True,
    )
    # The CLI binary this runtime shells out to (podman overrides).
    cli = "docker"

    # --- compatibility -----------------------------------------------------

    def unsupported_enforcer_reason(self, enforcer: str) -> str | None:
        """Why ``enforcer`` can't run on this runtime, or None if it can.

        A single source of truth for runtime/enforcer compatibility: both the
        render path (which refuses) and ``glove doctor`` (which surfaces the
        incompatibility up front) consult it, so a bad combo is reported before
        launch rather than aborting mid-render. Docker supports every enforcer.
        """
        return None

    # --- rendering ---------------------------------------------------------

    def compose_extra(self, plan: SessionPlan) -> dict:
        """Runtime-specific compose knobs folded into the render context.

        Docker needs none of these; podman overrides to add rootless
        ``userns_mode: keep-id`` and to skip the inline seccomp profile (the
        compose provider inlines the file's JSON, which podman's compat API
        rejects — podman applies its built-in default profile instead).
        """
        return {
            "userns_mode": None,
            "emit_seccomp": True,
            "host_gateway_name": self.caps.host_gateway_name or "host.docker.internal",
            # mount options of extension tmpfs volumes, owned by the plan's
            # uid/gid (rootful ids are the container's ids)
            "tmpfs_volume_opts": tmpfs_volume_opts(plan.uid, plan.gid),
            # SELinux relabel for extension sidecars' binds (None: none)
            "bind_selinux": None,
        }

    # Start sidecars one `compose up` at a time (podman); docker starts them together.
    serial_start = False

    def _jinja(self) -> Environment:
        return Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            undefined=StrictUndefined,
            trim_blocks=True,
            lstrip_blocks=True,
            keep_trailing_newline=True,
        )

    def render(
        self,
        plan: SessionPlan,
        project_dir: Path,
        *,
        overrides: frozenset[str] = frozenset(),
    ) -> RenderedProject:
        validate_hardening(plan, overrides=overrides)
        # Not waivable: the agent must never see (or forge) its own flow record
        # or rules (the export roots).
        validate_export_isolation(plan)
        # Env keys render into compose unquoted: a newline would add keys.
        for k in (*plan.environment, *plan.enforcer_env, *plan.passthrough_env):
            if not _ENV_KEY.match(k):
                raise HardeningError(f"harness env key {k!r} is not a plain variable name")
        extra = self.compose_extra(plan)
        # Couple the seccomp hardening row to what actually renders. validate_hardening
        # only checks that the *plan* names a profile; on a runtime that omits the
        # `seccomp=` line (podman) that plan value is discarded, so the invariant
        # would pass while the container runs unpinned. Refuse unless the runtime is
        # known to apply a validated built-in default — or the operator explicitly
        # waived the seccomp row, which validate_hardening already honoured above
        # (kept symmetric so an accepted override isn't silently re-refused here).
        if (
            not extra.get("emit_seccomp", True)
            and not self.caps.applies_builtin_seccomp
            and "seccomp" not in overrides
        ):
            raise HardeningError(
                f"runtime {self.name!r} omits glove's seccomp profile but does not "
                "apply a validated built-in default — the container would run "
                "unpinned. Refusing to render."
            )
        from ..plan import CORPORATE_CA_PATH

        ctx = {
            "session": plan.session,
            "harness": plan.profile,
            "harness_image": plan.image,
            "command": plan.harness_command,
            "home_dir": plan.home_dir,
            "working_dir": plan.working_dir,
            "mounts": plan.mounts,
            "protect": plan.protect,
            "placeholder_host_dir": plan.placeholder_host_dir,
            "environment": plan.environment,
            "enforcer_env": plan.enforcer_env,
            "passthrough_env": plan.passthrough_env,
            "policies_host_dir": plan.policies_host_dir,
            "policies_container_dir": plan.policies_container_dir,
            "system_mounts": plan.system_mounts,
            "sidecars": plan.network.socat,
            "transcripts_host_dir": plan.transcripts_host_dir,
            "transcripts_container_dir": plan.transcripts_container_dir,
            "corporate_ca_host_path": plan.corporate_ca_host_path,
            "corporate_ca_container_path": CORPORATE_CA_PATH,
            "hostgw_network": plan.network.hostgw_network,
            "session_networks": plan.network.session_networks,
            "subnets": plan.network.subnets,
            "forwarder_image": plan.forwarder_image,
            "uid": plan.uid,
            "gid": plan.gid,
            "hardening": plan.hardening,
            "allow_root": plan.allow_root,
            **extra,
            **_extension_blocks(plan, extra),
        }
        compose_yaml = self._jinja().get_template("compose.yml.j2").render(**ctx)
        # Not waivable: re-check §3.4 on the merged project (extension sidecars
        # included), so a merge bug cannot ship a weaker project.
        from ..compose import validate_project

        validate_project(yaml.safe_load(compose_yaml), plan, plan.composition)
        return RenderedProject(
            session=plan.session,
            project=plan.project,
            compose_yaml=compose_yaml,
            project_dir=project_dir,
            plan=plan,
        )

    # --- lifecycle inspection ---------------------------------------------

    def network_subnets(self) -> dict[str, list[str]]:
        """Every existing network's IPv4 subnets, by name (empty when the
        runtime is unavailable) — for subnet allocation that avoids them."""
        if not shutil.which(self.cli):
            return {}
        ids = subprocess.run([self.cli, "network", "ls", "-q"], capture_output=True, text=True, check=False)
        if ids.returncode != 0 or not ids.stdout.split():
            return {}
        out = subprocess.run(
            [self.cli, "network", "inspect", "-f", "{{.Name}}{{range .IPAM.Config}} {{.Subnet}}{{end}}",
             *ids.stdout.split()], capture_output=True, text=True, check=False)
        nets: dict[str, list[str]] = {}
        for line in out.stdout.splitlines():
            name, *subnets = line.split()
            nets[name] = [x for x in subnets if "." in x]
        return nets

    def ps(self) -> list[RunningSession]:
        if not shutil.which(self.cli):
            return []
        # Group by compose's own project label rather than parsing the container
        # name: `compose run` appends `-run-<hash>` and a service role may itself
        # contain dashes (e.g. `my-llm`), so name surgery mis-attributes both.
        proc = subprocess.run(
            [
                self.cli, "ps", "--filter", "name=glove-", "--format",
                '{{.Names}}\t{{.Label "com.docker.compose.project"}}\t{{.Status}}',
            ],
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            return []
        by_project: dict[str, RunningSession] = {}
        for line in proc.stdout.splitlines():
            if not line.strip():
                continue
            name, _, rest = line.partition("\t")
            project, _, _status = rest.partition("\t")
            # Fall back to the name prefix when the label is absent (a container
            # not started by compose); the compose project is always glove-<session>.
            if not project:
                project = name.rsplit("-", 1)[0]
            session = project.removeprefix("glove-")
            sess = by_project.setdefault(
                project, RunningSession(project=project, session=session)
            )
            sess.services.append(name)
        return list(by_project.values())

    # --- doctor ------------------------------------------------------------

    def doctor(self) -> list[Check]:
        checks: list[Check] = []
        if not shutil.which(self.cli):
            checks.append(Check(f"{self.name} cli", "fail", f"{self.cli} not on PATH"))
            return checks

        engine = self._engine_check()
        checks.append(engine)
        if engine.status == "fail":
            return checks

        checks.extend(self._security_checks())
        checks.append(self._landlock_check())
        return checks

    def _engine_check(self) -> Check:
        ver = subprocess.run(
            [self.cli, "version", "--format",
             "{{.Server.Version}} {{.Server.Os}}/{{.Server.Arch}} kernel={{.Server.KernelVersion}}"],
            capture_output=True, text=True,
        )
        if ver.returncode != 0:
            return Check(f"{self.name} engine", "fail", ver.stderr.strip() or "daemon not responding")
        return Check(f"{self.name} engine", "ok", ver.stdout.strip())

    def _security_checks(self) -> list[Check]:
        info = subprocess.run(
            [self.cli, "info", "--format", "{{.SecurityOptions}}"],
            capture_output=True, text=True,
        )
        sec = info.stdout.strip()
        eci = "on" if "userns" in sec and "rootless" not in sec else "off/unknown"
        return [
            Check("security options", "ok" if "seccomp" in sec else "warn", sec),
            Check("enhanced container isolation (ECI)", "info", eci),
        ]

    def _landlock_check(self) -> Check:
        """Run the hardened-container Landlock/userns/kvm probe.

        Applies glove's vendored default seccomp profile so the probe
        runs under the same syscall filter as the real harness — a bare
        ``docker run`` would use Docker's built-in default and could report a
        different Landlock/userns result than the hardened container gets.
        """
        proc = subprocess.run(
            [
                self.cli, "run", "--rm",
                "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges:true",
                *self._probe_seccomp_args(),
                PROBE_IMAGE, "python", "-c", _PROBE,
            ],
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            return Check("landlock (hardened container)", "fail", proc.stderr.strip()[-300:])
        try:
            data = json.loads(proc.stdout.strip().splitlines()[-1])
        except (json.JSONDecodeError, IndexError):
            return Check("landlock (hardened container)", "warn", proc.stdout.strip()[-200:])
        abi = data.get("landlock_abi")
        status = "ok" if isinstance(abi, int) and abi >= 4 else "fail"
        detail = (
            f"ABI {abi}; userns={data.get('userns_ok')}; kvm={data.get('kvm')}; "
            f"CapEff={data.get('CapEff')}; NoNewPrivs={data.get('NoNewPrivs')}"
        )
        return Check("landlock (hardened container)", status, detail)

    def _probe_seccomp_args(self) -> list[str]:
        """CLI args applying glove's vendored default seccomp to the probe.

        Docker's CLI reads the file and sends the profile inline; podman's
        compat path can't, so podman overrides this to rely on its built-in
        default profile (same moby-derived filter) instead.
        """
        from .seccomp import default_profile_path

        return ["--security-opt", f"seccomp={default_profile_path()}"]
