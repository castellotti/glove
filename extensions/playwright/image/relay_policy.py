"""The playwright `browser-event` channel's relay policy: which events the
agent may send to the browser sidecar, and what each one runs there. relayd
(the relay extension's supervisor, vendored as image/relayd.py) loads it by
path inside the `pw` sidecar, beside the X display the events act on.

The agent sends an event with the `browser-event` shell command:

  browser-event status
      The display's size, the pointer, XTest, and whether the operator is
      recording (`glove playwright record`). Sends no input.

  browser-event recordings
      The ids of the recordings the agent can replay (`glove playwright
      record` keeps them in the sidecar once it has saved them).

  browser-event replay PLAN [--dry-run]
  browser-event replay --recording ID [--dry-run]
      Replay the input sequence the agent staged at <channel>/plans/PLAN on
      the sidecar's display (browser_event.py has the plan format). PLAN is a
      bare file name in plans/ (neither it nor plans/ may be a link), at most
      PLAN_MAX bytes, and short enough to finish within the timeout. The
      policy reads it once, removes it from plans/, and writes those very
      bytes to the replay's own directory, where the agent can't write: that
      copy is what runs. While the operator is recording, a replay is refused
      (its input would end up in their recording); only the session's
      `replay_while_recording` allows it, never the agent.
      With --recording, the plan is built from a saved recording instead (one
      the agent may read anyway: `record` keeps them only with event_relay and
      `to: work`): the recorder's SAVED/ID/events.jsonl (at most PLAN_MAX
      bytes) as its events, each row cut to ROW, and meta.json's display, both
      read without following a link (the agent can't write there). From then on it is
      the same: one validator, the timeout, the log, the replay's plan.json.

What the agent chooses: the event, the plan's name or recording's id, and
--dry-run. Not the program, the display, the output directory or any other
argument; argv reaches relayd as NUL-separated words and runs as a list, never
through a shell. The program gets no stdin, the environment `setup` builds (DISPLAY, a
minimal PATH, no proxy: there is no route to give), and relayd kills its
process group at the timeout.

Every event is logged before it runs, and every refusal too: one JSON line in
the `browser-events` output's log.jsonl, which the sidecar writes and the
harness reads read-only at /work/browser-events/. An event that can't be
logged is refused. What the output holds stays bounded: past LOG_MAX the log
moves to log.1.jsonl (replacing the one before), and only the newest KEEP
replays' directories are kept (the session's `event_keep`).
"""

from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import importlib.util
import json
import os
import re
import secrets
import shutil
import stat
import time


class Refused(Exception):
    """This event is not run (relayd shows the message; exit 126)."""


CHANNEL = "/run/glove/browser-event"
LOG_ROOT = "/run/glove-output/browser-events"  # the `browser-events` output, as core binds it here
DISPLAY = ":1"
PROGRAM = os.path.join(os.path.dirname(os.path.abspath(__file__)), "browser_event.py")
TIMEOUT_S = int(os.environ.get("PW_EVENT_TIMEOUT", "120"))  # relayd's --timeout (glove-pw-start)
MARGIN_S = 10  # what a replay needs besides its events (the display, two frames)
PLAN_MAX = 2 * 1024 * 1024
PLAN_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\.json\Z")
WHILE_RECORDING = os.environ.get("PW_REPLAY_WHILE_RECORDING") == "true"  # the session's, never the agent's
LOG_MAX = 4 * 1024 * 1024
# replays' directories (each: the plan, at most PLAN_MAX, two frames and the result); `event_keep`
KEEP = int(os.environ.get("PW_EVENT_KEEP", "20"))
ID = re.compile(r"[0-9]{8}-[0-9]{6}-[0-9a-f]{6}\Z")  # a replay's
META_MAX = 64 * 1024
ROW = ("t", "type", "x", "y", "button")  # what a recording's row keeps in a plan (the sidecar's output is hostile)

COMMANDS = frozenset({"browser-event"})
HOSTS = ()  # the program makes no network calls: no fence, no proxy

_spec = importlib.util.spec_from_file_location("browser_event", PROGRAM)
program = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(program)  # its plan validator and recording check: one set of rules


def setup(ctx: dict) -> dict[str, str]:
    os.makedirs(os.path.join(CHANNEL, "plans"), mode=0o700, exist_ok=True)  # where the agent stages plans
    return {"PATH": "/usr/bin:/bin", "HOME": "/tmp", "DISPLAY": DISPLAY, "LANG": "C.UTF-8",
            "TZ": os.environ.get("TZ", "UTC")}


def _log(entry: dict) -> None:
    """Append one line to log.jsonl, or refuse the event: one that can't be logged doesn't run."""
    line = json.dumps({"ts": dt.datetime.now(dt.UTC).isoformat(timespec="milliseconds"), **entry})
    path = os.path.join(LOG_ROOT, "log.jsonl")
    try:
        with contextlib.suppress(FileNotFoundError):
            if os.stat(path, follow_symlinks=False).st_size > LOG_MAX:
                os.replace(path, os.path.join(LOG_ROOT, "log.1.jsonl"))
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o644)
        try:
            os.write(fd, (line + "\n").encode())
        finally:
            os.close(fd)
    except OSError as e:
        raise Refused(f"the event log is unwritable ({e.strerror}): not running an event that isn't logged") from None


def _prune() -> None:
    """Leave room for one more replay: remove the oldest directories beyond KEEP - 1."""
    ids = sorted(n for n in os.listdir(LOG_ROOT) if ID.fullmatch(n))
    for rid in ids[:max(0, len(ids) - (KEEP - 1))]:
        shutil.rmtree(os.path.join(LOG_ROOT, rid), ignore_errors=True)


def _opendir(path: str, what: str, dir_fd: int | None = None) -> int:
    try:
        return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd)
    except OSError as e:
        raise Refused(f"{what}: {e.strerror}") from None


def _read(dfd: int, name: str, limit: int, what: str) -> bytes:
    """<dfd>/<name>, opened without following a link: a regular file of at most `limit` bytes."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
    except OSError as e:
        raise Refused(f"{what}: {e.strerror}") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise Refused(f"{what}: not a regular file")
        if st.st_size > limit:
            raise Refused(f"{what}: {st.st_size} bytes (at most {limit})")
        return os.pread(fd, limit + 1, 0)
    finally:
        os.close(fd)


def _checked(plan, what: str) -> dict:
    if (err := program.validate(plan)) is not None:
        raise Refused(f"{what}: {err}")
    return plan


def _take_plan(name: str) -> tuple[bytes, dict]:
    """Read <channel>/plans/<name> once (plans/ and the file opened without following a link; a
    regular file of at most PLAN_MAX), remove it, and check it: its bytes and the plan."""
    if not PLAN_NAME.fullmatch(name):
        raise Refused(f"plan {name!r}: want a file name in {CHANNEL}/plans/ matching {PLAN_NAME.pattern}")
    dfd = _opendir(os.path.join(CHANNEL, "plans"), f"{CHANNEL}/plans")
    try:
        raw = _read(dfd, name, PLAN_MAX, f"plan {name}")
        os.unlink(name, dir_fd=dfd)  # one plan, one replay: staged plans can't fill the channel
    finally:
        os.close(dfd)
    try:
        plan = json.loads(raw)
    except ValueError as e:
        raise Refused(f"plan {name}: not JSON ({e})") from None
    return raw, _checked(plan, f"plan {name}")


def _from_recording(cid: str) -> tuple[bytes, dict]:
    """Build the plan of the saved recording <cid> (the recorder's SAVED and its directory opened without
    following a link): {"v": 1, "display": meta.json's, "events": events.jsonl's rows, each cut to ROW}.
    Its bytes and the plan."""
    what, rec = f"recording {cid}", program._recorder()
    if not rec.ID.fullmatch(cid):
        raise Refused(f"recording {cid[:40]!r}: want a recording's id, like 20261020-101741-0a1b2c "
                      "(`browser-event recordings` lists them)")
    root = _opendir(str(rec.SAVED), "no saved recordings (`glove playwright record` keeps them, with "
                                    "event_relay and recording: {to: work}, once it has saved them)")
    try:
        dfd = _opendir(cid, f"{what} (`browser-event recordings` lists the saved ones)", root)
    finally:
        os.close(root)
    try:
        meta = _read(dfd, "meta.json", META_MAX, f"{what}: meta.json (not finished?)")
        rows = _read(dfd, "events.jsonl", PLAN_MAX, f"{what}: events.jsonl")
    finally:
        os.close(dfd)
    try:
        meta, events = json.loads(meta), [json.loads(line) for line in rows.splitlines() if line.strip()]
    except ValueError as e:
        raise Refused(f"{what}: not JSON ({e})") from None
    events = [{k: e[k] for k in ROW if k in e} if isinstance(e, dict) else e for e in events]
    plan = {"v": 1, "display": meta.get("display") if isinstance(meta, dict) else None, "events": events}
    return json.dumps(plan, separators=(",", ":")).encode(), _checked(plan, what)


def prepare(req, env: dict[str, str]) -> list[str]:
    event, args = (req.argv[1], req.argv[2:]) if len(req.argv) > 1 else ("", [])
    try:
        return _prepare(event, args)
    except Refused as e:
        with contextlib.suppress(Refused):  # refused either way
            _log({"event": event[:40], "args": [a[:100] for a in args[:4]], "refused": str(e)[:300]})
        raise


def _prepare(event: str, args: list[str]) -> list[str]:
    if event == "status":
        if args:
            raise Refused("status takes no arguments")
        _log({"event": "status"})
        return ["/usr/bin/python3", PROGRAM, "status", "--display", DISPLAY]
    if event == "recordings":
        if args:
            raise Refused("recordings takes no arguments")
        _log({"event": "recordings"})
        return ["/usr/bin/python3", PROGRAM, "recordings"]
    if event != "replay":
        raise Refused("usage: browser-event status | browser-event recordings | "
                      "browser-event replay PLAN|--recording ID [--dry-run]")
    dry_run, cid, names = False, None, []
    words = iter(args)
    for a in words:
        if a == "--dry-run" and not dry_run:
            dry_run = True
        elif a == "--recording" and cid is None:
            cid = next(words, "")
        elif a.startswith("-"):
            raise Refused(f"replay: unexpected {a} (it takes --dry-run and --recording ID, each at most once)")
        else:
            names.append(a)
    if len(names) + (cid is not None) != 1:
        raise Refused("replay takes one plan name, or --recording ID")
    recording = program.recording()
    if recording and not dry_run and not WHILE_RECORDING:
        raise Refused("the operator is recording (`glove playwright record`): a replay's input would end up in "
                      "their recording; wait until they tell you they are done")
    if cid is not None:
        kind, name = "recording", cid
        raw, plan = _from_recording(cid)
    else:
        kind, name = "plan", names[0]
        raw, plan = _take_plan(name)
    seconds = (plan["events"][-1]["t"] - plan["events"][0]["t"]) / 1000
    if seconds > TIMEOUT_S - MARGIN_S:
        raise Refused(f"{kind} {name} lasts {seconds:.0f} s: a replay must end within {TIMEOUT_S - MARGIN_S} s "
                      f"(event_timeout {TIMEOUT_S} s); split it into shorter plans")
    rid = time.strftime("%Y%m%d-%H%M%S", time.gmtime()) + "-" + secrets.token_hex(3)
    _log({"event": "replay", "id": rid, kind: name, "plan_sha256": hashlib.sha256(raw).hexdigest(),
          "events": len(plan["events"]), "dry_run": dry_run, "while_recording": recording})
    out = os.path.join(LOG_ROOT, rid)
    try:
        _prune()
        os.mkdir(out, 0o755)
        program.create(os.path.join(out, "plan.json"), raw)
    except OSError as e:
        raise Refused(f"cannot keep the replay's plan ({e.strerror})") from None
    return ["/usr/bin/python3", PROGRAM, "replay", os.path.join(out, "plan.json"), "--out", out, "--id", rid,
            "--display", DISPLAY, *(["--dry-run"] if dry_run else []),
            *(["--while-recording"] if WHILE_RECORDING else [])]
