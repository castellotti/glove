"""The playwright `browser-event` channel's relay policy: which events the
agent may send to the browser sidecar, and what each one runs there. relayd
(the relay extension's supervisor, vendored as image/relayd.py) loads it by
path inside the `pw` sidecar, beside the X display the events act on.

The agent sends an event with the `browser-event` shell command:

  browser-event status
      The display's size, the pointer, XTest, and whether the operator is
      recording (`glove playwright record`). Sends no input.

  browser-event replay PLAN [--dry-run]
      Replay the input sequence the agent staged at <channel>/plans/PLAN on
      the sidecar's display (browser_event.py has the plan format). PLAN is a
      bare file name in plans/ (neither it nor plans/ may be a link), at most
      PLAN_MAX bytes, and short enough to finish within the timeout. The
      policy reads it once, removes it from plans/, and writes those very
      bytes to the replay's own directory, where the agent can't write: that
      copy is what runs. While the operator is recording, a replay is refused
      (its input would end up in their recording); only the session's
      `replay_while_recording` allows it, never the agent.

What the agent chooses: the event, the plan's name and --dry-run. Not the
program, the display, the output directory or any other argument; argv
reaches relayd as NUL-separated words and runs as a list, never through a
shell. The program gets no stdin, the environment `setup` builds (DISPLAY, a
minimal PATH, no proxy: there is no route to give), and relayd kills its
process group at the timeout.

Every event is logged before it runs, and every refusal too: one JSON line in
the `browser-events` output's log.jsonl, which the sidecar writes and the
harness reads read-only at /work/browser-events/. An event that can't be
logged is refused. What the output holds stays bounded: past LOG_MAX the log
moves to log.1.jsonl (replacing the one before), and only the newest KEEP
replays' directories are kept.
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
KEEP = 20  # replays' directories (each: the plan, at most PLAN_MAX, two frames and the result)
REPLAY_ID = re.compile(r"[0-9]{8}-[0-9]{6}-[0-9a-f]{6}\Z")

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
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW,
                     0o644)
        try:
            os.write(fd, (line + "\n").encode())
        finally:
            os.close(fd)
    except OSError as e:
        raise Refused(f"the event log is unwritable ({e.strerror}): not running an event that isn't logged") from None


def _prune() -> None:
    """Leave room for one more replay: remove the oldest directories beyond KEEP - 1."""
    ids = sorted(n for n in os.listdir(LOG_ROOT) if REPLAY_ID.fullmatch(n))
    for rid in ids[:max(0, len(ids) - (KEEP - 1))]:
        shutil.rmtree(os.path.join(LOG_ROOT, rid), ignore_errors=True)


def _take_plan(name: str) -> tuple[bytes, dict]:
    """Read <channel>/plans/<name> once (plans/ and the file opened without following a link; a
    regular file of at most PLAN_MAX), remove it, and check it: its bytes and the plan."""
    if not PLAN_NAME.fullmatch(name):
        raise Refused(f"plan {name!r}: want a file name in {CHANNEL}/plans/ matching {PLAN_NAME.pattern}")
    try:
        dfd = os.open(os.path.join(CHANNEL, "plans"), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as e:
        raise Refused(f"{CHANNEL}/plans: {e.strerror}") from None
    try:
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
        except OSError as e:
            raise Refused(f"plan {name}: {e.strerror}") from None
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise Refused(f"plan {name}: not a regular file")
            if st.st_size > PLAN_MAX:
                raise Refused(f"plan {name}: {st.st_size} bytes (at most {PLAN_MAX})")
            raw = os.pread(fd, PLAN_MAX + 1, 0)
        finally:
            os.close(fd)
        os.unlink(name, dir_fd=dfd)  # one plan, one replay: staged plans can't fill the channel
    finally:
        os.close(dfd)
    try:
        plan = json.loads(raw)
    except ValueError as e:
        raise Refused(f"plan {name}: not JSON ({e})") from None
    if (err := program.validate(plan)) is not None:
        raise Refused(f"plan {name}: {err}")
    return raw, plan


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
    if event != "replay":
        raise Refused("usage: browser-event status | browser-event replay PLAN [--dry-run]")
    flags = [a for a in args if a.startswith("-")]
    names = [a for a in args if not a.startswith("-")]
    if bad := [f for f in flags if f != "--dry-run"] or flags[1:]:
        raise Refused(f"replay: unexpected {bad[0]} (it takes --dry-run, at most once)")
    if len(names) != 1:
        raise Refused("replay takes one plan name")
    dry_run, recording = bool(flags), program.recording()
    if recording and not dry_run and not WHILE_RECORDING:
        raise Refused("the operator is recording (`glove playwright record`): a replay's input would end up in "
                      "their recording; wait until they tell you they are done")
    raw, plan = _take_plan(names[0])
    seconds = (plan["events"][-1]["t"] - plan["events"][0]["t"]) / 1000
    if seconds > TIMEOUT_S - MARGIN_S:
        raise Refused(f"plan {names[0]} lasts {seconds:.0f} s: a replay must end within {TIMEOUT_S - MARGIN_S} s "
                      f"(event_timeout {TIMEOUT_S} s); split it into shorter plans")
    rid = time.strftime("%Y%m%d-%H%M%S", time.gmtime()) + "-" + secrets.token_hex(3)
    _log({"event": "replay", "id": rid, "plan": names[0], "plan_sha256": hashlib.sha256(raw).hexdigest(),
          "events": len(plan["events"]), "dry_run": dry_run, "while_recording": recording})
    out = os.path.join(LOG_ROOT, rid)
    try:
        _prune()
        os.mkdir(out, 0o755)
        program.create(os.path.join(out, "plan.json"), raw)
    except OSError as e:
        raise Refused(f"cannot keep the replay's plan ({e.strerror})") from None
    return ["/usr/bin/python3", PROGRAM, "replay", os.path.join(out, "plan.json"), "--out", out,
            "--display", DISPLAY, *(["--dry-run"] if dry_run else []),
            *(["--while-recording"] if WHILE_RECORDING else [])]
