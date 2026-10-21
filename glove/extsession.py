"""What an extension's CLI needs of a session (`glove.api`): `ext_session`
finds it, with the extension's validated settings and hooks; `reload_sidecar`
recreates one of its sidecars with an env the caller resolved."""

from __future__ import annotations

import subprocess
import time
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from types import ModuleType
from typing import Any

from . import sessiondir as sdm
from .config import ConfigError, load_yaml
from .extensions import EXPORT_ROOTS, Manifest, declares_host_paths, discover, load_module, validate_settings
from .hooks import HookContext, hooks_of, validate_result
from .manifest import ExtensionError
from .naming import project_name, scoped


@dataclass(frozen=True)
class ExtSession:
    name: str  # the extension
    root: Path
    file: Path
    work: Path
    id: str | None  # .glove/id: None only with `ext_session(..., launched=False)`
    runtime: str  # docker | podman
    compose_file: Path  # what the last `glove up` rendered
    settings: Mapping[str, Any]  # validated, defaults applied
    manifest: Manifest

    @cached_property
    def hooks(self) -> ModuleType | None:
        """Its hooks.py, helpers included: loaded only by a CLI that calls them."""
        m = self.manifest
        return load_module(m.hooks_path, self.name) if m.hooks_path else None

    def container(self, service: str) -> str:
        return scoped(self.id or "", service)

    def running(self, service: str) -> bool:
        r = subprocess.run([self.runtime, "inspect", "-f", "{{.State.Running}}", self.container(service)],
                           capture_output=True, text=True, check=False)
        return r.returncode == 0 and r.stdout.strip() == "true"

    def rendered(self, service: str) -> dict[str, Any]:
        """The service as the last `glove up` rendered it ({} if it didn't)."""
        if not self.compose_file.is_file():
            return {}
        doc = load_yaml(self.compose_file.read_text()) or {}
        return dict((doc.get("services") or {}).get(self.container(service)) or {})

    def export_dir(self, root: str) -> Path:
        """This session's dir of an export root the extension owns."""
        from .exports import export_dirs

        if EXPORT_ROOTS.get(root) != self.name or self.manifest.out_of_tree or self.id is None:
            raise ExtensionError(f"extension {self.name!r} does not own the {root!r} export root")
        return export_dirs(self.id)[root]

    def state_dir(self) -> Path:
        """Its own state dir (`.glove/ext/<name>`), created 0700 in a private `.glove/`."""
        sdm.ensure_private(sdm.SessionDir(self.root))
        return sdm.ensure_dir(self.context().state_dir)

    def context(self) -> HookContext:
        """A hook context outside a launch: its settings and the host paths its
        manifest declares."""
        m = self.manifest
        return HookContext(name=self.name, settings=dict(self.settings), trusted=m.trusted,
                           session={"id": self.id}, assets=m.path, state_dir=sdm.SessionDir(self.root).ext / self.name,
                           session_dir=self.root if declares_host_paths(m) else None,
                           work_dir=self.work if declares_host_paths(m, work=True) else None)


def ext_session(name: str, directory: Path | None = None, *, launched: bool = True) -> ExtSession:
    """The session at (or above) `directory` that enables extension `name`."""
    try:
        sd = sdm.find(directory)
        raw = sdm.load_file(sd)
    except sdm.SessionError as e:
        raise ExtensionError(str(e)) from e
    sid = sd.read_id()
    if sid is None and launched:
        raise ExtensionError(f"{sd.root} has never been launched (no .glove/id)")
    given = raw.get("extensions") or {}
    m = discover().get(name)
    if name not in given or m is None:
        raise ExtensionError(f"{sd.file}: the {name} extension is not enabled")
    return _session(sd, sid, sdm.session_provider(sd), m, given[name])


def _session(sd: sdm.SessionDir, sid: str | None, runtime: str, m: Manifest, raw: Any) -> ExtSession:
    return ExtSession(name=m.name, root=sd.root, file=sd.file, work=sd.work, id=sid, runtime=runtime,
                      compose_file=sd.compose, settings=validate_settings(m, raw), manifest=m)


def run_teardown(sd: sdm.SessionDir, sid: str, runtime: str, given: Mapping[str, Any], *,
                 only: Collection[str] | None = None) -> list[str]:
    """Run the `teardown` hook of each extension the last launch enabled (`given`:
    its settings then), so what it started on the host stops; a warning per failure.
    `only`: the ones that define it (as the launch recorded): no other's code loads."""
    todo = {n: raw for n, raw in given.items() if only is None or n in only}
    if not todo:
        return []
    try:
        found = discover()
    except ConfigError as e:  # a manifest or config.yml: `glove down` goes on, its containers still stop
        return [f"teardown hooks skipped: {e}"]
    warnings = []
    for name, raw in todo.items():
        if (m := found.get(name)) is None:  # gone, or skipped as writable by others: what it started stays
            warnings.append(f"extension {name!r}: not found, so its teardown hook did not run")
            continue
        if m.hooks_path is None:
            continue
        try:
            s = _session(sd, sid, runtime, m, raw)
            fn = hooks_of(s.hooks, name).get("teardown")
            if fn is not None:
                validate_result("teardown", name, fn(s.context()))
        except Exception as e:  # likewise
            warnings.append(f"extension {name!r}: teardown: {e}")
    return warnings


def reload_sidecar(s: ExtSession, service: str, env: Mapping[str, str], *, wait: int = 30) -> None:
    """Recreate one running sidecar with `env` (resolved by the caller, held in memory) and
    nothing else, so the agent's conversation keeps going; wait until it is healthy."""
    from .session import _compose_base, compose_process_env
    from .verify import _health

    container = s.container(service)
    if not s.running(service):
        raise ExtensionError(f"{container} is not running; `glove up` starts it")
    r = subprocess.run([*_compose_base(s.runtime, project_name(s.id or ""), s.compose_file), "up", "-d",
                        "--no-deps", "--force-recreate", container],
                       env=compose_process_env(s.runtime, dict(env)), check=False)
    if r.returncode != 0:
        raise ExtensionError(f"recreating {container} failed (exit {r.returncode})")
    for _ in range(wait):
        if _health(s.runtime, container) == "healthy":
            return
        time.sleep(1)
    raise ExtensionError(f"{container} did not become healthy; `{s.runtime} logs {container}`")
