"""Session configuration: schema + defaults < env file < --config < flags.

Resolution precedence is built-in defaults, then the environment's own
`glove.yaml` (under `~/.glove/envs/<env-id>/`),
then an explicit `--config` overlay, then CLI flags. There is no in-workdir
auto-discovery — nothing is read from (or written to) the invocation dir. The
fully resolved ("effective") config round-trips to YAML so a session is
reproducible.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any

import yaml

from .hardening import Limits


class ConfigError(ValueError):
    """Raised for malformed or contradictory configuration."""


@dataclass
class AddDir:
    path: str
    mode: str = "ro"  # "ro" | "rw"

    def __post_init__(self) -> None:
        if self.mode not in ("ro", "rw"):
            raise ConfigError(f"add_dir mode must be ro|rw, got {self.mode!r}")


@dataclass
class HostService:
    """A host-side helper glove starts in a detached tmux session.

    These run on the host (outside the sandbox) using host trust the container
    deliberately lacks — the SSH model tunnel, the headed Chrome, the Playwright
    MCP. `command` may use placeholders glove expands: {session}, {workdir},
    {media_dir}, {chrome_profile}, {home}.
    """

    name: str
    command: str
    ready_port: int | None = None  # glove waits for / dedupes on this port
    ready_timeout: float = 60.0  # seconds to wait for ready_port
    keep: bool = False  # leave running after `glove down` (e.g. Chrome)


@dataclass
class Service:
    """A forwarder sidecar / network allow-list entry."""

    name: str
    to: str  # target host:port the sidecar forwards to
    port: int = 0  # listen port inside the internal net (default: target port)
    join_network: str | None = None  # external docker network to also join
    host_gateway: bool = False  # add extra_hosts host.docker.internal:host-gateway

    def __post_init__(self) -> None:
        if self.port == 0:
            _, _, tport = self.to.rpartition(":")
            try:
                self.port = int(tport)
            except ValueError as e:  # pragma: no cover - defensive
                raise ConfigError(
                    f"service {self.name!r}: cannot infer port from {self.to!r}"
                ) from e
        # host.docker.internal targets imply the host-gateway extra_hosts entry.
        if "host.docker.internal" in self.to:
            self.host_gateway = True


@dataclass
class Config:
    harness: str = "vibe"
    provider: str = "docker"  # docker | podman (autodetect handled in cli)
    # NEW in v2. `runtime` is the ring-0 layer (docker | podman |
    # apple-container | gondolin | utm); for docker/podman it also drives which
    # compose CLI `provider` shells out to. `enforcer` is the ring-1 in-container
    # sandbox (nono | srt | none).
    runtime: str = "docker"
    enforcer: str = "nono"
    workdir: str = "."
    name: str | None = None
    add_dirs: list[AddDir] = field(default_factory=list)
    net: list[str] = field(default_factory=lambda: ["none"])
    allow_root: bool = False
    allow_sensitive: bool = False  # permit mounting / or $HOME
    rebuild: bool = False
    services: list[Service] = field(default_factory=list)
    harness_config: dict[str, Any] = field(default_factory=dict)
    env: dict[str, Any] = field(default_factory=dict)
    # The model id the harness sends to its LLM endpoint (OpenAI `model` field).
    model: str | None = None
    # Which service fronts the LLM; its `<host>:<port>` becomes the
    # harness's api_base. glove synthesises the provider config from this so the
    # LLM host/port live entirely inside the container.
    llm_service: str = "llm"
    # API key for the LLM endpoint, if it requires one. glove injects it into the
    # container env as GLOVE_LLM_API_KEY and points the harness provider's
    # api_key_env_var at it — so the secret lives in this (git-ignorable) file,
    # never hand-edited into the generated harness config.
    llm_api_key: str | None = None
    # Host dir bind-mounted as the harness config home (/home/agent). Defaults
    # to the environment's own `home/` under ~/.glove/envs/<env-id>/ (persistent,
    # per-instance, user-inspectable — and exactly where external monitors look).
    # Optional power-user override: point at another persistent path to keep a
    # harness's config + your own extensions there. glove only writes the files
    # it owns; anything else you add is preserved.
    config_home_source: str | None = None
    # Free-text session brief appended to the harness context file, e.g.
    # what the agent should work on in /work.
    brief: str | None = None
    # Host-side helpers glove auto-starts in detached tmux sessions:
    # SSH model tunnel, headed Chrome, Playwright MCP. Managed lifecycle:
    # port-deduped, health-checked, torn down on `glove down` (unless keep).
    host_services: list[HostService] = field(default_factory=list)
    # Legacy: commands glove only PRINTS for the operator to run by hand. Prefer
    # host_services (auto-managed). Kept for anything you want to run manually.
    host_setup: list[str] = field(default_factory=list)
    # Extra packages baked into the harness image on top of its defaults, so the
    # sandboxed agent has the tools a session needs (the box has no egress to
    # install them at runtime). Changing these yields a distinct image tag.
    apt_packages: list[str] = field(default_factory=list)
    pip_packages: list[str] = field(default_factory=list)
    # NEW in v2. Resource bounds (ring 0) and per-backend options.
    # `tools`/`browser` are consumed by later phases (ring 1 tool policy / ring 2
    # browser wiring); modeled as free dicts here so these configs load today.
    limits: Limits = field(default_factory=Limits)
    tools: dict[str, Any] = field(default_factory=dict)
    browser: dict[str, Any] = field(default_factory=dict)
    enforcer_options: dict[str, Any] = field(default_factory=dict)

    def resolved_name(self) -> str:
        # The name IS the env-id; the CLI always
        # binds it from the registry before rendering. Resolution no longer
        # falls back to the workdir basename.
        return self.name or "env"

    def to_dict(self, *, redact_secrets: bool = False) -> dict[str, Any]:
        d = asdict(self)
        # The effective config is persisted to ~/.glove as a reproducibility
        # artifact; don't leave the LLM key in cleartext there. The real key
        # stays in the (git-ignorable) env glove.yaml source and is injected
        # into the harness config/env at render time.
        if redact_secrets and d.get("llm_api_key"):
            d["llm_api_key"] = None
        return d

    def to_yaml(self, *, redact_secrets: bool = False) -> str:
        return yaml.safe_dump(
            self.to_dict(redact_secrets=redact_secrets), sort_keys=False
        )


def _load_mapping(path: Path) -> dict[str, Any]:
    text = path.read_text()
    data = json.loads(text) if path.suffix == ".json" else yaml.safe_load(text)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: top-level config must be a mapping")
    return data


def _coerce(data: dict[str, Any]) -> Config:
    """Build a Config from a plain mapping, coercing nested structures."""
    data = dict(data)  # shallow copy; we pop as we go
    add_dirs_raw = data.pop("add_dirs", []) or []
    services_raw = data.pop("services", []) or []
    host_services_raw = data.pop("host_services", []) or []

    add_dirs = [_coerce_add_dir(x) for x in add_dirs_raw]
    services = [Service(**x) if isinstance(x, dict) else _coerce_service(x) for x in services_raw]
    host_services = [
        x if isinstance(x, HostService) else HostService(**x)
        for x in host_services_raw
    ]

    net = data.pop("net", None)
    if isinstance(net, str):
        net = [p.strip() for p in net.split(",") if p.strip()]

    limits_raw = data.pop("limits", None)

    known = set(Config.__dataclass_fields__)
    unknown = set(data) - known
    if unknown:
        raise ConfigError(f"unknown config keys: {sorted(unknown)}")

    cfg = Config(**data)
    cfg.add_dirs = add_dirs
    cfg.services = services
    cfg.host_services = host_services
    if net is not None:
        cfg.net = net
    if limits_raw is not None:
        cfg.limits = _coerce_limits(limits_raw)
    return cfg


def _coerce_limits(x: Any) -> Limits:
    if isinstance(x, Limits):
        return x
    if isinstance(x, dict):
        allowed = set(Limits.__dataclass_fields__)
        unknown = set(x) - allowed
        if unknown:
            raise ConfigError(f"unknown limits keys: {sorted(unknown)}")
        return Limits(**x)
    raise ConfigError(f"invalid limits (expected mapping): {x!r}")


def _coerce_add_dir(x: Any) -> AddDir:
    if isinstance(x, AddDir):
        return x
    if isinstance(x, str):
        path, _, mode = x.partition(":")
        return AddDir(path=path, mode=mode or "ro")
    if isinstance(x, dict):
        return AddDir(**x)
    raise ConfigError(f"invalid add_dir entry: {x!r}")


def _coerce_service(x: Any) -> Service:
    raise ConfigError(f"invalid service entry (expected mapping): {x!r}")


def load_config(path: Path | None) -> Config:
    """Load a Config from a file, or return defaults when path is None."""
    if path is None:
        return Config()
    return _coerce(_load_mapping(path))


def parse_add_dir_flag(value: str) -> AddDir:
    """Parse a --add-dir value of the form PATH[:ro|:rw]."""
    path, sep, mode = value.rpartition(":")
    if sep and mode in ("ro", "rw"):
        return AddDir(path=path, mode=mode)
    return AddDir(path=value, mode="ro")


def merge_overrides(cfg: Config, overrides: dict[str, Any]) -> Config:
    """Apply non-None CLI overrides on top of a file/default config."""
    clean = {k: v for k, v in overrides.items() if v is not None}
    # add_dirs from flags are appended, not replaced.
    extra_add_dirs = clean.pop("add_dirs", None)
    merged = replace(cfg, **clean) if clean else cfg
    if extra_add_dirs:
        merged = replace(merged, add_dirs=[*merged.add_dirs, *extra_add_dirs])
    return merged


def resolve(
    *,
    env_config_path: Path | None = None,
    config_path: Path | None = None,
    overrides: dict[str, Any] | None = None,
) -> Config:
    """Full resolution: defaults < env `glove.yaml` < `--config` < flags.

    `env_config_path` is the environment's own config under
    `~/.glove/envs/<env-id>/glove.yaml`; `config_path` is an optional `--config`
    overlay for one-off/explicit runs. Both are merged at the mapping level
    (top-level keys from the later source win) before flag overrides.
    """
    data: dict[str, Any] = {}
    if env_config_path is not None and env_config_path.is_file():
        data.update(_load_mapping(env_config_path))
    if config_path is not None:
        data.update(_load_mapping(config_path))
    cfg = _coerce(data) if data else Config()
    return merge_overrides(cfg, overrides or {})
