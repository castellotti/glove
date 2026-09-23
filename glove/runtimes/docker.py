"""The ``docker`` runtime — full implementation for v2.

Renders the per-session compose project from a ``SessionPlan`` (evolving v1's
``compose.py`` + template), enforces the hardening set before writing
anything, and exposes the container/landlock probes ``glove doctor`` needs.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from ..hardening import HardeningError, validate_hardening
from ..observe import render_context as observe_context
from ..observe import validate_net_isolation
from .base import Check, RenderedProject, RunningSession, RuntimeCaps

if TYPE_CHECKING:
    from ..plan import SessionPlan

TEMPLATES_DIR = Path(__file__).parent.parent / "templates"

# Fully-qualified so podman's short-name resolution never prompts; docker
# resolves it identically.
PROBE_IMAGE = "docker.io/library/python:3.12-slim"

# Compact probe run inside a hardened container: reports Landlock ABI, whether
# an unprivileged user namespace is creatable, /dev/kvm, and the effective caps.
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
        }

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
        # Not waivable: the agent must never see (or forge) its own flow record.
        validate_net_isolation(plan)
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
        ctx = {
            "session": plan.session,
            "harness": plan.profile,
            "harness_image": plan.image,
            "command": plan.harness_command,
            "home_dir": plan.home_dir,
            "working_dir": plan.working_dir,
            "mounts": plan.mounts,
            "environment": plan.environment,
            "enforcer_env": plan.enforcer_env,
            "policies_host_dir": plan.policies_host_dir,
            "policies_container_dir": plan.policies_container_dir,
            "sidecars": plan.network.sidecars,
            "external_networks": plan.network.external_networks,
            "harness_extra_networks": plan.network.harness_extra_networks,
            "harness_host_gateway": plan.network.harness_host_gateway,
            "egress_network": plan.network.egress_network,
            "forwarder_image": plan.forwarder_image,
            "uid": plan.uid,
            "gid": plan.gid,
            "hardening": plan.hardening,
            "allow_root": plan.allow_root,
            **observe_context(plan),
            **extra,
        }
        compose_yaml = self._jinja().get_template("compose.yml.j2").render(**ctx)
        return RenderedProject(
            session=plan.session,
            project=plan.project,
            compose_yaml=compose_yaml,
            project_dir=project_dir,
            plan=plan,
        )

    # --- lifecycle inspection ---------------------------------------------

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
