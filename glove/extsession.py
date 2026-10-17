"""What an extension's CLI needs of a session (`glove.api`): `ext_session`
finds it, with the extension's validated settings and hooks; `reload_sidecar`
recreates one of its sidecars with an env the caller resolved."""

from __future__ import annotations

import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

import yaml

from . import sessiondir as sdm
from .extensions import EXPORT_ROOTS, Manifest, declares_host_paths, discover, load_module, validate_settings
from .hooks import HookContext
from .manifest import ExtensionError
from .naming import scoped


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
    hooks: ModuleType | None  # its hooks.py, helpers included
    manifest: Manifest

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
        doc = yaml.safe_load(self.compose_file.read_text()) or {}
        return dict((doc.get("services") or {}).get(self.container(service)) or {})

    def export_dir(self, root: str) -> Path:
        """This session's dir of an export root the extension owns."""
        from .exports import export_dirs

        if EXPORT_ROOTS.get(root) != self.name or self.manifest.out_of_tree or self.id is None:
            raise ExtensionError(f"extension {self.name!r} does not own the {root!r} export root")
        return export_dirs(self.id)[root]

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
    return ExtSession(
        name=name, root=sd.root, file=sd.file, work=sd.work, id=sid, runtime=sdm.session_provider(sd),
        compose_file=sd.compose, settings=validate_settings(m, given[name]), manifest=m,
        hooks=load_module(m.hooks_path, name) if m.hooks_path else None,
    )


def reload_sidecar(s: ExtSession, service: str, env: Mapping[str, str], *, wait: int = 30) -> None:
    """Recreate one running sidecar with `env` (resolved by the caller, held in
    memory) and nothing else; wait until it is healthy."""
    from .session import recreate_sidecar

    container = s.container(service)
    if not s.running(service):
        raise ExtensionError(f"{container} is not running; `glove up` starts it")
    if (why := recreate_sidecar(s.runtime, s.id or "", s.compose_file, container, dict(env), wait=wait)) is not None:
        raise ExtensionError(why)
