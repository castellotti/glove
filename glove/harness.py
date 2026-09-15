"""Harness profile registry.

Each profile keeps the glove core generic: it declares the base image build
context, the config-home env var + in-container path, the TUI entry command,
the context file that carries the host-sudo relay rule, and default env.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

from .config import ConfigError

HARNESSES_DIR = Path(__file__).parent / "harnesses"


@dataclass(frozen=True)
class HarnessProfile:
    name: str
    image: str  # image tag glove builds/uses
    entry: list[str]  # TUI entry command
    config_home_env: str  # env var pointing the harness at its config dir
    config_home_path: str  # in-container config dir (on a writable volume)
    context_file: str  # in-container path for the sudo-relay instruction
    # Where this harness writes its `*.jsonl` transcripts, relative to
    # `config_home_path`. Pi/Vibe nest them under `sessions/<project>/`; Claude
    # Code uses `projects/<slug>/`. sessions_dir joins this onto the host home.
    sessions_subdir: str = "sessions"
    default_env: dict[str, str] = field(default_factory=dict)
    # Read-only paths the harness's own interpreter/runtime needs beyond nono's
    # default system reads — e.g. the python venv or node prefix the entry binary
    # execs from. Added to the ring-1 *harness* profile's read list so `nono run`
    # can actually launch the TUI (its shebang/interpreter lives here). Omitting
    # them makes the harness exec fail with exit 127 under Landlock.
    runtime_paths: tuple[str, ...] = ("/usr/local",)
    # Command that installs Python packages into the image, for plugin/user `pip`
    # layers. None ⇒ this harness ships no Python installer (a `pip` layer is an
    # error). Vibe installs via uv; the Node-based harnesses have none.
    pip_install: tuple[str, ...] | None = None
    # Resume-flag mapping (see resume_args). `resume_continue` re-opens the most
    # recent session; `resume_session` re-opens a specific id — the literal
    # "{id}" token is replaced with the requested session id. None ⇒ the harness
    # can't resume that way, and resume_args raises.
    resume_continue: tuple[str, ...] | None = None
    resume_session: tuple[str, ...] | None = None

    @property
    def dockerfile(self) -> Path:
        return HARNESSES_DIR / self.name / "Dockerfile"

    def resume_args(self, session_id: str | None) -> list[str]:
        """Harness flags to resume a session; raises if unsupported.

        `session_id is None` ⇒ continue the most recent session; otherwise
        re-open that specific id."""
        if session_id is None:
            if not self.resume_continue:
                raise ConfigError(
                    f"harness {self.name!r} does not support --resume"
                )
            return list(self.resume_continue)
        if not self.resume_session:
            raise ConfigError(
                f"harness {self.name!r} does not support --session"
            )
        return [session_id if p == "{id}" else p for p in self.resume_session]


_REGISTRY: dict[str, HarnessProfile] = {
    "vibe": HarnessProfile(
        name="vibe",
        # 0.4.0: minimal base — harness + ring-1 enforcer (baked nono binary +
        # pre_tool hook) only. Optional capabilities are opt-in plugins.
        image="glove/vibe:0.4.0",
        entry=["vibe", "--trust", "--yolo", "--workdir", "/work"],
        config_home_env="VIBE_HOME",
        config_home_path="/home/agent/.vibe",
        context_file="/home/agent/.vibe/AGENTS.md",
        default_env={"VIBE_HOME": "/home/agent/.vibe"},
        # vibe is installed with `uv tool install` under /opt/uv; its shebang
        # points at that venv's python (→ /usr/local's cpython).
        runtime_paths=("/opt/uv", "/usr/local"),
        # Python packages install system-wide via the baked uv.
        pip_install=("uv", "pip", "install", "--system"),
        # Vibe help: `[-c | --resume [SESSION_ID]]` — one flag, optional id.
        resume_continue=("--resume",),
        resume_session=("--resume", "{id}"),
    ),
    "pi": HarnessProfile(
        name="pi",
        # 0.4.0: minimal base — harness + ring-1 enforcer (baked nono binary +
        # enforcer extension) only. Optional capabilities are opt-in plugins.
        image="glove/pi:0.4.0",
        # Load only the always-on ring-1 `enforcer` extension (deps are node
        # builtins) from a system path; the user's own extensions still load from
        # the config home. Capability extensions (search, browser) are opt-in
        # plugins added to this entry when enabled — absent by default.
        entry=[
            "pi",
            "-e", "/opt/glove/pi-extensions/enforcer",
        ],
        config_home_env="PI_CODING_AGENT_DIR",
        config_home_path="/home/agent/.pi/agent",
        context_file="/home/agent/.pi/agent/AGENTS.md",
        # PI_OFFLINE stops Pi's startup egress attempts (fd download, version
        # check, telemetry) that fail in the no-egress sandbox.
        default_env={
            "PI_CODING_AGENT_DIR": "/home/agent/.pi/agent",
            "PI_OFFLINE": "1",
        },
        # `pi --continue` reopens the last session; `--session <id>` accepts a
        # path or partial UUID.
        resume_continue=("--continue",),
        resume_session=("--session", "{id}"),
    ),
    "claude-code": HarnessProfile(
        name="claude-code",
        image="glove/claude-code:0.1.0",
        entry=["claude"],
        config_home_env="CLAUDE_CONFIG_DIR",
        config_home_path="/home/agent/.claude",
        context_file="/home/agent/.claude/CLAUDE.md",
        default_env={"CLAUDE_CONFIG_DIR": "/home/agent/.claude"},
        # CC stores transcripts under `~/.claude/projects/<slug>/`, not `sessions/`.
        sessions_subdir="projects",
        # Documented CC flags; image is a stub — wired but untested.
        resume_continue=("--continue",),
        resume_session=("--resume", "{id}"),
    ),
}


def _image_contributing_plugins(plugins: list[str], harness: str) -> list[str]:
    """Subset of plugin names that add image layers for ``harness``.

    Imported lazily: the plugins package imports ``HarnessProfile`` from here, so
    a top-level import would cycle. Unknown names are left in place so tag
    computation stays a pure function and the loud "unknown plugin" error still
    surfaces where plugins are actually resolved."""
    if not plugins:
        return plugins
    from .plugins import get_plugin

    contributing: list[str] = []
    for name in plugins:
        try:
            plugin = get_plugin(name)
        except ValueError:
            contributing.append(name)
            continue
        if plugin.layers_for(harness):
            contributing.append(name)
    return contributing


def effective_image(
    profile: HarnessProfile,
    apt_packages: list[str] | None = None,
    pip_packages: list[str] | None = None,
    plugins: list[str] | None = None,
) -> str:
    """Image tag for a profile, suffixed with a hash when extra packages or
    plugins are requested so each distinct set gets its own image (and rebuilds).

    Plugin names are part of the hash: a plugin name deterministically maps to
    its image contribution, so the set of enabled plugins uniquely identifies the
    composed image. Only plugins that actually contribute image layers *for this
    harness* count — one whose contribution is purely runtime wiring (e.g.
    ``browser`` on Vibe, which adds an MCP server but no layer) leaves the image
    byte-identical to the base, so it must not force a distinct tag and a
    redundant derived build. With nothing extra, returns the plain minimal base
    tag."""
    apt_packages = apt_packages or []
    pip_packages = pip_packages or []
    plugins = _image_contributing_plugins(plugins or [], profile.name)
    if not apt_packages and not pip_packages and not plugins:
        return profile.image
    payload = (
        "apt:" + ",".join(sorted(apt_packages))
        + "|pip:" + ",".join(sorted(pip_packages))
        + "|plugins:" + ",".join(sorted(plugins))
    )
    digest = hashlib.sha1(payload.encode()).hexdigest()[:10]
    base, sep, tag = profile.image.rpartition(":")
    return f"{base}:{tag}-{digest}" if sep else f"{profile.image}-{digest}"


def get_profile(name: str) -> HarnessProfile:
    try:
        return _REGISTRY[name]
    except KeyError:
        raise ValueError(
            f"unknown harness {name!r}; known: {', '.join(sorted(_REGISTRY))}"
        ) from None


def known_harnesses() -> list[str]:
    return sorted(_REGISTRY)
