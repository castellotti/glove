"""Transcript discovery for `--resume` / `--session`.

A harness session's state is a transcript the harness writes into the persistent
per-session home glove bind-mounts (see `_home_dir` in the CLI). The container is
ephemeral; only these `*.jsonl` files matter, and they survive image/container
deletion. These helpers locate and enumerate them so the CLI can validate a
resume request and surface a post-exit hint — resume itself only appends the
harness's own flag (see `HarnessProfile.resume_args`).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .config import Config
from .harness import HarnessProfile
from .harnessconfig import rel_config_home


def sessions_dir(profile: HarnessProfile, home_dir: Path) -> Path:
    """Host dir holding this harness's transcripts for the mounted home.

    Maps the in-container config dir onto `home_dir` (via `rel_config_home`,
    the same mapping `harnessconfig` uses to seed that dir), then appends the
    harness's `sessions_subdir` (Pi/Vibe use `sessions/`; Claude Code uses
    `projects/`)."""
    return Path(home_dir) / rel_config_home(profile) / profile.sessions_subdir


@dataclass(frozen=True)
class SessionRef:
    id: str  # UUID parsed from the filename (…_<uuid>.jsonl), else the stem
    path: Path
    mtime: float


def _parse_id(path: Path) -> str:
    """The trailing `<uuid>` of a `<ts>_<uuid>.jsonl` name (else the whole stem)."""
    stem = path.stem
    return stem.rpartition("_")[2] or stem


def list_sessions(directory: Path) -> list[SessionRef]:
    """All transcripts under `directory`, newest-first by mtime.

    Recursive so it finds Pi's per-project subdir (e.g. `--work--/`). Missing
    dir ⇒ empty list (a never-run / wiped env is not an error here)."""
    if not directory.is_dir():
        return []
    refs = [
        SessionRef(id=_parse_id(p), path=p, mtime=p.stat().st_mtime)
        for p in directory.rglob("*.jsonl")
        if p.is_file()
    ]
    refs.sort(key=lambda r: r.mtime, reverse=True)
    return refs


def match_session(refs: list[SessionRef], session_id: str) -> SessionRef | None:
    """First (newest) ref in `refs` matching `session_id`, else None.

    Accepts the forms the `--session` help documents: a full/partial UUID
    (substring of the parsed id or filename) or a transcript path (matched by
    its basename, so a full `/…/<ts>_<uuid>.jsonl` still resolves). Takes an
    already-listed `refs` so callers holding one don't re-walk the dir."""
    needle_name = Path(session_id).name
    for ref in refs:
        if (
            session_id in ref.id
            or session_id in ref.path.name
            or ref.path.name == needle_name
        ):
            return ref
    return None


def find_session(directory: Path, session_id: str) -> SessionRef | None:
    """Newest transcript under `directory` matching `session_id` (see match_session)."""
    return match_session(list_sessions(directory), session_id)


def widening_warnings(prev: Config, cur: Config) -> list[str]:
    """Human-readable warnings where `cur` grants broader access than `prev`.

    `prev` is the session's *original* baseline (the config it was first created
    under — see the persisted baseline snapshot in the CLI), not merely the last
    run, so a narrow→wide→narrow sequence never emits a spurious warning against a
    drifted comparison point. Resuming re-injects the prior conversation (which
    may carry prompt-injected instructions the model absorbed) into a sandbox the
    user may have widened, so those instructions would run with more reach. We
    compare the security-relevant grants and warn — never block; deliberate
    widening is the whole point of the feature (the §7.3 safeguard). Compares net,
    add_dirs (added paths + ro→rw upgrades), plugins, allow_root, allow_sensitive,
    and services."""
    warnings: list[str] = []

    added_net = [n for n in cur.net if n != "none" and n not in prev.net]
    if added_net:
        warnings.append(
            f"net: {list(prev.net)} → {list(cur.net)} (added {added_net})"
        )

    prev_dirs = {d.path: d.mode for d in prev.add_dirs}
    for d in cur.add_dirs:
        if d.path not in prev_dirs:
            warnings.append(f"add_dir: new mount {d.path} ({d.mode})")
        elif prev_dirs[d.path] == "ro" and d.mode == "rw":
            warnings.append(f"add_dir: {d.path} upgraded ro → rw")

    added_plugins = [p for p in cur.plugins if p not in prev.plugins]
    if added_plugins:
        warnings.append(f"plugins: added {added_plugins}")

    if cur.allow_root and not prev.allow_root:
        warnings.append("allow_root: false → true (root/sudo now permitted)")
    if cur.allow_sensitive and not prev.allow_sensitive:
        warnings.append("allow_sensitive: false → true (/ or $HOME mountable)")

    prev_svcs = {s.name for s in prev.services}
    added_svcs = [s.name for s in cur.services if s.name not in prev_svcs]
    if added_svcs:
        warnings.append(f"services: added {added_svcs}")

    return warnings
