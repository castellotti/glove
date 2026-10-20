"""`glove clean` — remove what glove left on Docker and Podman.

A session's stack is the compose project `glove-<session id>`: compose labels
its containers, networks and volumes with that project, so the labels (not
names) say what is glove's. A project counts only when its id is a v3 session
id (`ID_RE`); anything else on a runtime is never glove's to remove.

A stack whose session is live in this registry, or with a container that is
not `exited`/`dead` (running, starting, paused, …), is never touched. Of the
rest, the stopped containers and the networks go. The volumes (VPN state,
observe events, …) go only when the session is provably gone: its row's
directory now holds another session (re-launched under a new id). A missing
directory may have moved, and a project with no row may be another
GLOVE_HOME's (an integration test's): their volumes stay unless `--volumes`.

With an `<age>` (`12h`, `3d`, `2w`), `clean` also reclaims what has not been
used for that long. A session's last use is the mtime of its
`.glove/compose.yml` (every `glove plan`/`up` rewrites it; else its row's
`created`), and that file's `image:`s are the images it uses.
- An idle session (live here, nothing running, unused for `<age>`) loses its
  stopped containers and networks; its volumes stay, so `glove up` restarts it.
- A `glove/*` image goes when no container left uses it and its last use (the
  newest of the sessions naming it, else its creation) is older than `<age>`.
  A base tag a kept image was built from (the kept tag's prefix) stays.
- `--build-cache` also prunes Docker's build cache (machine-wide) older than `<age>`.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

import typer

from glove.api.commands import ID_RE, RegistryError, console, err, fail, load_registry, project_name, row_state

RANK = 10  # its place in `glove --help` (commands/README.md)

PROJECT_LABEL = "com.docker.compose.project"
RUNTIMES = ("docker", "podman")
STOPPED = frozenset({"exited", "dead"})
TIMEOUT = 60  # seconds, per runtime call
PRUNE_TIMEOUT = 1800  # a build cache can hold ~100 GB
_PREFIX = project_name("")
AGE_RE = re.compile(r"([0-9]+)([hdw])\Z")
HOURS = {"h": 1, "d": 24, "w": 24 * 7}
IMAGE_RE = re.compile(r"^\s*image:\s*['\"]?(glove/[^'\"\s]+)", re.M)
_WHEN_RE = re.compile(r"(\d{4}-\d\d-\d\d)[T ](\d\d:\d\d:\d\d)(?:\.\d+)?\s*(Z|[+-]\d\d:?\d\d)?")
UNITS = {"B": 1, "kB": 1e3, "KB": 1e3, "MB": 1e6, "GB": 1e9, "TB": 1e12}


@dataclass
class Stack:
    """One session's resources on one runtime."""

    runtime: str
    sid: str
    containers: dict[str, str] = field(default_factory=dict)  # id → state
    networks: list[str] = field(default_factory=list)
    volumes: list[str] = field(default_factory=list)

    @property
    def active(self) -> bool:
        return any(state not in STOPPED for state in self.containers.values())

    def describe(self) -> str:
        return ", ".join(f"{len(v)} {k}" for k, v in (("container(s)", self.containers), ("network(s)", self.networks),
                                                      ("volume(s)", self.volumes)) if v)


def _out(cli: str, *args: str, partial: bool = False) -> list[str] | None:
    """The command's stdout lines; None when the runtime can't answer. With
    `partial`, a failure that still printed lines returns them (an `inspect` of
    several ids, one of which went in the meantime)."""
    try:
        r = subprocess.run([cli, *args], capture_output=True, text=True, check=False, timeout=TIMEOUT)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return r.stdout.splitlines() if r.returncode == 0 or (partial and r.stdout.strip()) else None


def runtimes(only: str | None = None) -> list[str]:
    """The runtimes to look at: `only`, else each one on PATH."""
    return [only] if only else [c for c in RUNTIMES if shutil.which(c)]


def _inspect(cli: str, kind: str, ls: list[str], fmt: str) -> list[str] | None:
    """`fmt` of each `kind` the listing `ls` names (`<kind> inspect`)."""
    ids = _out(cli, *ls)
    if not ids:
        return ids
    rows = _out(cli, kind, "inspect", "-f", fmt, *dict.fromkeys(ids), partial=True)
    return None if rows is None else [r for r in rows if r.strip()]


def _labelled(cli: str, kind: str, labels: str, *fields: str) -> list[list[str]] | None:
    """[project, *fields] of each `kind` (container|network|volume) carrying
    compose's project label; `labels` is where `inspect` keeps its labels."""
    ls = ["ps", "-aq"] if kind == "container" else [kind, "ls", "-q"]
    fmt = " ".join([f'{{{{index {labels} "{PROJECT_LABEL}"}}}}', *(f"{{{{{f}}}}}" for f in fields)])
    rows = _inspect(cli, kind, [*ls, "--filter", f"label={PROJECT_LABEL}"], fmt)
    return None if rows is None else [r.split() for r in rows]


def stacks(cli: str) -> list[Stack] | None:
    """Every glove v3 session's stack on `cli`; None when it can't be asked."""
    found = (_labelled(cli, "container", ".Config.Labels", ".Id", ".State.Status"),
             _labelled(cli, "network", ".Labels", ".Name"),
             _labelled(cli, "volume", ".Labels", ".Name"))
    if any(f is None for f in found):
        return None
    by: dict[str, Stack] = {}

    def stack(project: str) -> Stack | None:
        sid = project.removeprefix(_PREFIX)
        if not project.startswith(_PREFIX) or not ID_RE.match(sid):
            return None
        return by.setdefault(sid, Stack(cli, sid))

    containers, networks, volumes = found
    for project, cid, state in (r for r in containers if len(r) == 3):
        if (s := stack(project)) is not None:
            s.containers[cid] = state
    for rows, attr in ((networks, "networks"), (volumes, "volumes")):
        for project, name in (r for r in rows if len(r) == 2):
            if (s := stack(project)) is not None:
                getattr(s, attr).append(name)
    return sorted(by.values(), key=lambda s: s.sid)


def remove(s: Stack, *, volumes: bool) -> list[str]:
    """Remove a stack's containers, then its networks (and volumes); the
    resources the runtime refused."""
    failed = []
    for kind, names in (("container", list(s.containers)), ("network", s.networks),
                        ("volume", s.volumes if volumes else [])):
        for name in names:
            if not _ok([s.runtime, "rm", "-f", name] if kind == "container" else [s.runtime, kind, "rm", name]):
                failed.append(f"{s.runtime} {kind} {name}")
    return failed


def _ok(cmd: list[str], timeout: int = TIMEOUT) -> bool:
    try:
        return subprocess.run(cmd, capture_output=True, check=False, timeout=timeout).returncode == 0
    except subprocess.TimeoutExpired:
        return False


# --- <age>: idle sessions, unused images, the build cache --------------------------------


def parse_age(age: str) -> int:
    """`<n>h|d|w` in hours."""
    if not (m := AGE_RE.match(age)):
        raise fail(f"<age>: expected <n>h, <n>d or <n>w (e.g. 3d), got {age!r}")
    return int(m[1]) * HOURS[m[2]]


def _when(s: str | None) -> datetime | None:
    """A runtime's or the registry's timestamp (RFC 3339, or Podman's
    `2026-10-19 06:44:54.8 +0000 UTC`), aware; None when unreadable."""
    if not s or not (m := _WHEN_RE.match(s)):
        return None
    when = datetime.fromisoformat(f"{m[1]}T{m[2]}{m[3] or ''}")
    return when if when.tzinfo else when.replace(tzinfo=UTC)


def last_uses(entries) -> tuple[dict[str, datetime], dict[str, datetime]]:
    """(each `glove/*` image's last use by a registered session, each
    session's last use): its compose file's mtime, else its row's `created`."""
    images: dict[str, datetime] = {}
    sessions: dict[str, datetime] = {}
    for e in entries:
        f = Path(e.dir) / ".glove" / "compose.yml"
        try:
            used, text = datetime.fromtimestamp(f.stat().st_mtime, UTC), f.read_text()
        except OSError:
            if (created := _when(e.created)) is not None:
                sessions[e.id] = created
            continue
        sessions[e.id] = used
        for tag in IMAGE_RE.findall(text):
            images[tag] = max(images.get(tag, used), used)
    return images, sessions


@dataclass
class Image:
    """One `glove/*` tag on one runtime."""

    runtime: str
    ref: str  # as the runtime names it (Podman: `localhost/glove/…`)
    last: datetime

    @property
    def tag(self) -> str:
        return self.ref.removeprefix("localhost/")


def unused_images(cli: str, cutoff: datetime, used: dict[str, datetime], leaving: set[str]) -> list[Image] | None:
    """The `glove/*` tags on `cli` last used before `cutoff` that no container
    uses but those in `leaving`, derived tags first; None when it can't be asked."""
    images = _inspect(cli, "image", ["image", "ls", "-q", "--filter", "reference=glove/*"],
                      '{{.Id}}|{{.Created}}|{{join .RepoTags " "}}')
    users = _inspect(cli, "container", ["ps", "-aq"], "{{.Id}} {{.Image}}")
    if images is None or users is None:
        return None
    in_use = {r.split()[1] for r in users if len(r.split()) == 2 and r.split()[0] not in leaving}
    old, kept = [], set()
    for iid, created, tags in (r.split("|", 2) for r in images if r.count("|") == 2):
        for ref in tags.split():
            img = Image(cli, ref, used.get(ref.removeprefix("localhost/")) or _when(created) or datetime.now(UTC))
            if not img.tag.startswith("glove/"):
                continue
            if iid in in_use or img.last >= cutoff:
                kept.add(img.tag)
            else:
                old.append(img)
    old = [i for i in old if not any(k.startswith(f"{i.tag}-") for k in kept)]
    return sorted(old, key=lambda i: (-len(i.tag), i.tag))


def disk(cli: str) -> float | None:
    """What `cli` holds on disk (`system df`'s sizes), in bytes."""
    rows = _out(cli, "system", "df", "--format", "{{.Size}}")
    sizes = [re.fullmatch(r"([0-9.]+)\s*([kKMGT]?B)", r.strip()) for r in rows or []]
    return sum(float(m[1]) * UNITS[m[2]] for m in sizes if m) if rows else None


def command(
    age: str | None = typer.Argument(None, metavar="[AGE]", help="also what has not been used for this long: "
                                                                  "<n>h, <n>d or <n>w (e.g. 3d)"),
    yes: bool = typer.Option(False, "--yes", "-y", help="do not ask"),
    dry_run: bool = typer.Option(False, "--dry-run", help="list only"),
    volumes: bool = typer.Option(False, "--volumes", help="also the volumes of sessions that may still exist "
                                                           "elsewhere (a moved directory, another GLOVE_HOME)"),
    build_cache: bool = typer.Option(False, "--build-cache", help="with an AGE: also Docker's build cache older "
                                                                   "than it (machine-wide, not only glove's)"),
    runtime: str | None = typer.Option(None, "--runtime", help="docker | podman (default: each on PATH)"),
) -> None:
    """Remove the stopped stacks of sessions that no longer exist here: their
    containers and networks, and their volumes when the session is provably gone
    (its directory now holds another session). With an AGE, also idle sessions'
    stopped containers and networks (never their volumes) and the glove images
    unused for that long. Nothing running is touched.
    (`glove gc` removes registry rows and exports.)"""
    if runtime not in (None, *RUNTIMES):
        raise fail(f"--runtime: expected one of {', '.join(RUNTIMES)}, got {runtime!r}")
    hours = None if age is None else parse_age(age)
    if build_cache and hours is None:
        raise fail("--build-cache needs an AGE (e.g. glove clean 7d --build-cache)")
    try:
        entries = load_registry()
    except RegistryError as e:
        raise fail(str(e)) from e
    states = {e.id: row_state(e) for e in entries}
    cutoff = None if hours is None else datetime.now(UTC) - timedelta(hours=hours)
    used, last = last_uses(entries) if cutoff else ({}, {})
    dead: list[tuple[Stack, bool]] = []  # (stack, its volumes go)
    images: list[Image] = []
    prune: list[str] = []
    looked: list[str] = []
    for rt in runtimes(runtime):
        found = stacks(rt)
        if found is None:
            err.print(f"[yellow]warn:[/yellow] {rt} did not answer: its stacks were not checked")
            continue
        looked.append(rt)
        for s in found:
            state = states.get(s.sid)
            if s.active:
                if state != "ok":  # another GLOVE_HOME's, or one whose directory went while up
                    err.print(f"[yellow]warn:[/yellow] {rt} stack {project_name(s.sid)} is active: left alone")
                continue
            if state == "ok":
                when = last.get(s.sid)
                if cutoff and when and when < cutoff and (s.containers or s.networks):
                    dead.append((s, False))  # idle: its volumes stay
                continue
            gone = state == "stale" or volumes
            if s.containers or s.networks or (gone and s.volumes):
                dead.append((s, gone))
            if s.volumes and not gone:
                why = "its directory is missing (moved?)" if state == "missing" else "not in this registry"
                console.print(f"  [dim]keeping {rt} {project_name(s.sid)}'s {len(s.volumes)} volume(s): {why}; "
                              "--volumes removes them[/dim]")
        if cutoff:
            leaving = {c for s, _ in dead if s.runtime == rt for c in s.containers}
            if (old := unused_images(rt, cutoff, used, leaving)) is None:
                err.print(f"[yellow]warn:[/yellow] {rt} did not list its images: none were checked")
            images += old or []
            if build_cache and rt == "docker":
                prune.append(rt)
    if not (dead or images or prune):
        console.print("[green]✓[/green] nothing to clean")
        return
    for s, gone in dead:
        shown = Stack(s.runtime, s.sid, s.containers, s.networks, s.volumes if gone else [])
        idle = " [dim](idle: its volumes stay)[/dim]" if states.get(s.sid) == "ok" else ""
        console.print(f"  {s.runtime} stack {project_name(s.sid)}: {shown.describe()}{idle}")
    for i in images:
        console.print(f"  {i.runtime} image {i.ref} [dim](last used {i.last:%Y-%m-%d})[/dim]")
    for rt in prune:
        console.print(f"  {rt} build cache unused for {age} [yellow](machine-wide: not only glove's)[/yellow]")
    if dry_run:
        return
    if not yes and not typer.confirm("Remove these?", default=False):
        raise typer.Exit(1)
    before = {rt: disk(rt) for rt in looked}
    failed = [f for s, gone in dead for f in remove(s, volumes=gone)]
    failed += [f"{i.runtime} image {i.ref}" for i in images if not _ok([i.runtime, "rmi", i.ref])]
    failed += [f"{rt} build cache" for rt in prune
               if not _ok([rt, "builder", "prune", "-f", "--filter", f"until={hours}h"], PRUNE_TIMEOUT)]
    for f in failed:
        err.print(f"[yellow]warn:[/yellow] could not remove {f}")
    freed = [f"{(b - a) / 1e9:.1f} GB on {rt}" for rt, b in before.items()
             if b is not None and (a := disk(rt)) is not None]
    console.print(f"[green]✓[/green] removed {len(dead)} stack(s), {len(images)} image(s)"
                  + (f"; reclaimed {', '.join(freed)}" if freed else ""))
