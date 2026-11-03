#!/usr/bin/env python3
"""The browser sidecar's side of `browser-event` (playwright `event_relay`):
what an event the agent sent does on this sidecar's X display. relayd runs it,
with the argv relay_policy.py built; the agent never picks its arguments.

    browser_event.py status [--display :1]
        One JSON object: the display's size, the pointer, whether XTest is
        there, and whether the operator is recording. Sends no input.

    browser_event.py recordings
        One JSON object: the ids of the recordings in browser-output/
        (RECORDINGS here; `glove playwright record` writes them), the newest
        LIST_MAX, oldest first, and how many more there are. `browser-event
        replay --recording` checks one only when it replays it.

    browser_event.py replay PLAN --out DIR --id ID [--display :1] [--dry-run] [--while-recording]
        Replay PLAN's input events on the display, then write DIR/result.json
        (also printed) and DIR/before.png, DIR/after.png. The result names
        itself: the replay's `id`, its `dir` and the `frames` written, as the
        agent sees them (under SEEN_AT). --dry-run checks the plan against the
        display and sends nothing. Refused while the operator records, unless
        --while-recording (the session's `replay_while_recording`, which the
        policy passes on).

A plan (v1) is a timed input sequence in the recorder's own `events.jsonl`
shape (`glove playwright record`), so a recording replays as it is (one
longer than the event timeout allows must be split; `from_recording` builds
one for `--recording`):

    {"v": 1, "display": [w, h],
     "events": [{"t": ms, "type": "move|down|up|wheel", "x": X, "y": Y, "button": B}, …]}

`t` never decreases; each event is replayed `t - events[0].t` ms after the
first. Each moves the pointer to (x, y) first; `down`/`up` then press or
release button 1-3, 8 or 9 (back, forward) there, `wheel` clicks button 4-7.
Other keys (the recorder's `xt`, `wall`, `mask`) are ignored. A button still
held at the end, or when anything fails, is released; one of 1-3 held when a
replay starts (left by a replay killed at its timeout) is released first. The
input is XTest's (python3-xlib), which the X server treats like a real
device's. Whatever fails, a replay writes its result and exits 2.
"""

from __future__ import annotations

import argparse
import contextlib
import functools
import importlib.machinery
import importlib.util
import json
import math
import os
import re
import stat
import sys
import time

RECORDER = "/usr/local/bin/glove-pw-capture"  # the operator's recorder: is it running, wall(), png()
# `recording: {to: work}` (which needs `downloads: work`): where `record` writes each one's checked copy, as core
# binds the browser-output output here; the harness reads it at /work/browser-output/recordings/
RECORDINGS = "/run/glove-output/browser-output/recordings"
LIST_MAX = 200
ID = re.compile(r"[0-9]{8}-[0-9]{6}-[0-9a-f]{6}\Z")  # a recording's id (capture.ID on the host)
SEEN_AT = "/work/browser-events"  # the `browser-events` output, as the harness mounts it
MAX_EVENTS = 10_000
TIMEOUT_S = int(os.environ.get("PW_EVENT_TIMEOUT", "120"))  # relayd's --timeout (glove-pw-start)
MARGIN_S = 10  # what a replay needs besides its events (the display, two frames)
ROW = ("t", "type", "x", "y", "button")  # what a recording's row keeps in a plan (the sidecar's output is hostile)
MAX_SIDE = 1 << 14
PRESS = (1, 2, 3, 8, 9)  # left, middle, right, back, forward
BUTTONS = {"down": PRESS, "up": PRESS, "wheel": (4, 5, 6, 7), "move": None}


def _num(v, lo: float, hi: float) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) and lo <= v < hi


def validate(plan) -> str | None:
    """None when `plan` is a replayable v1 plan; otherwise why not."""
    if not isinstance(plan, dict) or plan.get("v") != 1:
        return "not a v1 plan (want {\"v\": 1, \"display\": [w, h], \"events\": [...]})"
    disp = plan.get("display")
    if not (isinstance(disp, list) and len(disp) == 2 and all(isinstance(n, int) and _num(n, 1, MAX_SIDE)
                                                              for n in disp)):
        return "display: want [width, height] in pixels"
    events = plan.get("events")
    if not isinstance(events, list) or not 1 <= len(events) <= MAX_EVENTS:
        return f"events: want a list of 1 to {MAX_EVENTS} events"
    last = 0
    for i, e in enumerate(events):
        if not isinstance(e, dict) or e.get("type") not in BUTTONS:
            return f"events[{i}]: type must be one of {sorted(BUTTONS)}"
        if not _num(e.get("t"), last, math.inf):
            return f"events[{i}]: t must be a number of ms, never less than the one before"
        last = e["t"]
        if not (_num(e.get("x"), 0, disp[0]) and _num(e.get("y"), 0, disp[1])):
            return f"events[{i}]: x, y must be inside the display {disp[0]}x{disp[1]}"
        if (allowed := BUTTONS[e["type"]]) is not None and e.get("button") not in allowed:
            return f"events[{i}]: a {e['type']} needs button {'1-3, 8 or 9' if allowed is PRESS else '4-7'}"
    return None


def fits(plan) -> str | None:
    """None when `plan` (a valid one) ends within the event timeout; otherwise why not."""
    seconds = (plan["events"][-1]["t"] - plan["events"][0]["t"]) / 1000
    if seconds > TIMEOUT_S - MARGIN_S:
        return f"lasts {seconds:.0f} s: a replay must end within {TIMEOUT_S - MARGIN_S} s (event_timeout {TIMEOUT_S} s)"
    return None


def from_recording(meta: bytes, rows: bytes):
    """The plan of a recording: {"v": 1, "display": meta.json's, "events": events.jsonl's rows, each cut
    to ROW}, unchecked. ValueError when either isn't JSON."""
    try:
        meta, events = json.loads(meta), [json.loads(line) for line in rows.splitlines() if line.strip()]
    except RecursionError:
        raise ValueError("nested too deeply") from None
    events = [{k: e[k] for k in ROW if k in e} if isinstance(e, dict) else e for e in events]
    return {"v": 1, "display": meta.get("display") if isinstance(meta, dict) else None, "events": events}


def create(path: str, data: bytes) -> None:
    """Write a new file (never over one, never through a link)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


@functools.cache
def _recorder():
    loader = importlib.machinery.SourceFileLoader("glove_pw_capture", RECORDER)
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
    loader.exec_module(module)
    return module


def recording() -> bool:
    """Whether the operator is recording: a live recorder, not just its marker left behind."""
    return _recorder().running() is not None


class Screen:
    """The X display, through python3-xlib: its size, the pointer, XTest input and frames."""

    def __init__(self, name: str):
        from Xlib import X, display
        from Xlib.ext import xtest
        self.X, self.xtest = X, xtest
        self.d = display.Display(name)
        self.root = self.d.screen().root
        self.size = [self.d.screen().width_in_pixels, self.d.screen().height_in_pixels]

    def pointer(self) -> list[int]:
        q = self.root.query_pointer()
        return [q.root_x, q.root_y]

    def move(self, x: float, y: float) -> None:
        self.xtest.fake_input(self.d, self.X.MotionNotify, root=self.root, x=int(x), y=int(y))
        self.d.sync()

    def held(self) -> list[int]:
        """The buttons 1-3 the X server has down."""
        mask = self.root.query_pointer().mask
        return [b for b in (1, 2, 3) if mask & (self.X.Button1Mask << (b - 1))]

    def button(self, button: int, press: bool) -> None:
        self.xtest.fake_input(self.d, self.X.ButtonPress if press else self.X.ButtonRelease, detail=button)
        self.d.sync()

    def frame(self, path: str) -> None:
        img = self.root.get_image(0, 0, *self.size, self.X.ZPixmap, 0xFFFFFFFF)
        create(path, _recorder().png(*self.size, img.data))


def status(display: str) -> int:
    out = {"display": None, "pointer": None, "xtest": False, "recording": recording()}
    try:
        s = Screen(display)
        out.update(display=s.size, pointer=s.pointer(), xtest=bool(s.d.query_extension("XTEST")))
    except Exception as e:
        out["error"] = f"display {display} unreachable: {e}"
    print(json.dumps(out))
    return 1 if "error" in out else 0


def _is_dir(path: str) -> bool:
    try:
        return stat.S_ISDIR(os.lstat(path).st_mode)
    except OSError:  # removed meanwhile
        return False


def recordings() -> int:
    try:
        ids = sorted(n for n in os.listdir(RECORDINGS) if ID.fullmatch(n) and _is_dir(os.path.join(RECORDINGS, n)))
        out = {"recordings": ids[-LIST_MAX:], **({"more": len(ids) - LIST_MAX} if len(ids) > LIST_MAX else {})}
    except FileNotFoundError:
        out = {"recordings": []}
    except OSError as e:
        out = {"recordings": [], "error": f"{RECORDINGS}: {e.strerror}"}
    print(json.dumps(out))
    return 1 if "error" in out else 0


def replay(plan: dict, display: str, out: str, rid: str, dry_run: bool, while_recording: bool = False) -> int:
    events, seen = plan["events"], f"{SEEN_AT}/{rid}"
    result = {"id": rid, "dir": seen, "synthetic": True, "dry_run": dry_run, "events": len(events),
              "duration_ms": round(events[-1]["t"] - events[0]["t"])}
    try:
        _replay(plan, Screen(display), out, dry_run, while_recording, result)
    except Exception as e:  # the display or a frame: still a result, and exit 2
        result.update(status="error", error=result.get("error") or f"{type(e).__name__}: {e}"[:300])
    result["frames"] = {k: f"{seen}/{k}.png" for k in ("before", "after")
                        if os.path.exists(os.path.join(out, f"{k}.png"))}
    body = json.dumps(result, indent=1)
    with contextlib.suppress(OSError):
        create(os.path.join(out, "result.json"), (body + "\n").encode())
    print(body)
    return {"ok": 0, "dry-run": 0}.get(result["status"], 2)


def _replay(plan: dict, s: Screen, out: str, dry_run: bool, while_recording: bool, result: dict) -> None:
    result.update(display=s.size, pointer_before=s.pointer())
    if s.size != plan["display"]:
        result.update(status="refused", error=f"the display is {s.size[0]}x{s.size[1]}, the plan was made for "
                                              f"{plan['display'][0]}x{plan['display'][1]}")
    elif dry_run:
        result["status"] = "dry-run"
    elif not _recorder().claim_replay(while_recording):
        result.update(status="refused", error="the operator is recording (`glove playwright record`): a replay's "
                                              "input would end up in their recording")
    else:
        try:
            _send(s, plan["events"], out, result)
        finally:
            _recorder().release_replay()


def _send(s: Screen, events: list[dict], out: str, result: dict) -> None:
    result.update(status="ok", started_at=_recorder().wall(), sent=0, released_first=s.held())
    for b in result["released_first"]:
        s.button(b, False)
    s.frame(os.path.join(out, "before.png"))
    held: set[int] = set()
    start, base = time.monotonic(), events[0]["t"]
    try:
        for e in events:
            if (wait := start + (e["t"] - base) / 1000 - time.monotonic()) > 0:
                time.sleep(wait)
            s.move(e["x"], e["y"])
            if e["type"] in ("down", "wheel"):
                s.button(e["button"], True)
                held.add(e["button"])
            if e["type"] in ("up", "wheel"):
                s.button(e["button"], False)
                held.discard(e["button"])
            result["sent"] += 1
    except Exception as e:
        result.update(status="error", error=str(e))
    finally:
        result["released"] = sorted(held)
        for b in result["released"]:
            with contextlib.suppress(Exception):  # the X server may be gone: the rest still get released
                s.button(b, False)
    result.update(ended_at=_recorder().wall(), pointer_after=s.pointer())
    result["end_error_px"] = max(abs(a - int(b)) for a, b in
                                 zip(result["pointer_after"], (events[-1]["x"], events[-1]["y"]), strict=True))
    s.frame(os.path.join(out, "after.png"))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="browser_event.py")
    sub = ap.add_subparsers(dest="event", required=True)
    st = sub.add_parser("status")
    st.add_argument("--display", default=":1")
    sub.add_parser("recordings")
    rp = sub.add_parser("replay")
    rp.add_argument("plan")
    rp.add_argument("--out", required=True)
    rp.add_argument("--id", required=True)
    rp.add_argument("--display", default=":1")
    rp.add_argument("--dry-run", action="store_true")
    rp.add_argument("--while-recording", action="store_true")
    a = ap.parse_args(argv)
    if a.event == "status":
        return status(a.display)
    if a.event == "recordings":
        return recordings()
    with open(a.plan, encoding="utf-8") as f:
        plan = json.load(f)
    if (err := validate(plan)) is not None:
        print(f"browser_event: {err}", file=sys.stderr)
        return 2
    return replay(plan, a.display, a.out, a.id, a.dry_run, a.while_recording)


if __name__ == "__main__":
    sys.exit(main())
