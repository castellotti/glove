"""Plugin model — the manifest for one opt-in capability.

A plugin is a single, capability-centric unit that declares everything enabling
it composes into a session: its image contribution (extra packages/files, added
as *derived layers* on top of the minimal base — see `glove/plugins/image.py`),
and, in later phases, its network/host-service/mount/ring-1 grants and the
per-harness wiring adapters. Off by default; absent from the base image and
unloaded unless the operator names it in `plugins:`/`--with`.

Phase 2 wires the image contribution + registry + config/CLI surface only; the
network/host-service/mount/ring-1/adapter fields are added as their phases land
so there is no unused machinery.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Sentinel harness key for image layers shared by every harness.
ALL_HARNESSES = "*"


@dataclass(frozen=True)
class ImageLayer:
    """One harness's image contribution for a plugin, rendered to Dockerfile
    layers on top of the minimal base.

    - ``apt`` — Debian packages (both base images are Debian-derived).
    - ``pip`` — Python packages, installed with the harness profile's
      ``pip_install`` command (only harnesses that ship a Python installer, e.g.
      Vibe's ``uv``, support this).
    - ``npm`` — global npm packages (Node-based harnesses).
    - ``copy`` — ``(host_src, container_dst)`` files staged into the build
      context and ``COPY``'d in. ``host_src`` is an absolute path on the host
      (typically inside the plugin's own directory).
    - ``run`` — raw ``RUN`` command bodies for anything the above can't express.
    """

    apt: tuple[str, ...] = ()
    pip: tuple[str, ...] = ()
    npm: tuple[str, ...] = ()
    copy: tuple[tuple[str, str], ...] = ()
    run: tuple[str, ...] = ()


@dataclass(frozen=True)
class Plugin:
    """An opt-in capability. ``image`` maps a harness name (or ``ALL_HARNESSES``)
    to that harness's image contribution."""

    name: str
    summary: str
    image: dict[str, ImageLayer] = field(default_factory=dict)

    def layers_for(self, harness: str) -> list[ImageLayer]:
        """Image layers this plugin contributes to ``harness`` (shared first)."""
        layers: list[ImageLayer] = []
        shared = self.image.get(ALL_HARNESSES)
        if shared is not None:
            layers.append(shared)
        specific = self.image.get(harness)
        if specific is not None:
            layers.append(specific)
        return layers
