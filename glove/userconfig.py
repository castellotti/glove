"""User-global settings: ``~/.glove/config.yml`` (or ``$GLOVE_HOME/config.yml``).

Holds what applies to every session of this user, never to one session:
where out-of-tree extensions load from, which of them are trusted with
privilege exceptions, the default runtime, and where a Landlock harness's binds
come from on Docker Desktop (``docker_desktop_mounts``). Absent file ⇒ defaults.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import yaml

from .config import ConfigError, load_yaml
from .registry import glove_home

KEYS = frozenset({"extension_paths", "trusted_extensions", "runtime", "subnet_pool", "docker_desktop_mounts"})
DESKTOP_MOUNTS = ("auto", "native", "virtiofs")


@dataclass(frozen=True)
class UserConfig:
    extension_paths: list[str] = field(default_factory=list)
    trusted_extensions: list[str] = field(default_factory=list)
    runtime: str = "docker"
    subnet_pool: str = "172.31.0.0/16"
    docker_desktop_mounts: str = "auto"  # auto | native | virtiofs (glove/runtimes/landlock_mounts.py)


def load_user_config() -> UserConfig:
    path = glove_home() / "config.yml"
    if not path.is_file():
        return UserConfig()
    try:
        data = load_yaml(path.read_text()) or {}
    except (OSError, yaml.YAMLError) as e:
        raise ConfigError(f"{path}: {e}") from e
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: must be a mapping")
    unknown = set(data) - KEYS
    if unknown:
        raise ConfigError(f"{path}: unknown keys {sorted(unknown)} (known: {sorted(KEYS)})")
    for k in ("extension_paths", "trusted_extensions"):
        if not isinstance(data.get(k, []), list):
            raise ConfigError(f"{path}: `{k}` must be a list")
    if data.get("docker_desktop_mounts", "auto") not in DESKTOP_MOUNTS:
        raise ConfigError(f"{path}: `docker_desktop_mounts` must be one of {', '.join(DESKTOP_MOUNTS)}")
    return UserConfig(**data)
