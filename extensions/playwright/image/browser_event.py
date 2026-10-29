#!/usr/bin/env python3
"""The browser sidecar's side of `browser-event` (playwright `event_relay`):
what an event the agent sent does on this sidecar's X display. relayd runs it,
with the argv relay_policy.py built; the agent never picks its arguments.

    browser_event.py status [--display :1]
        One JSON object: the display's size, the pointer, whether XTest is
        there, and whether the operator is recording. Sends no input.

    browser_event.py replay PLAN --out DIR [--display :1] [--dry-run]
        Replay PLAN's input events on the display, then write DIR/result.json
        (also printed) and DIR/before.png, DIR/after.png. --dry-run checks the
        plan against the display and sends nothing.

A plan (v1) is a timed input sequence in the recorder's own `events.jsonl`
shape (`glove playwright record`), so a recording replays as it is:

    {"v": 1, "display": [w, h],
     "events": [{"t": ms, "type": "move|down|up|wheel", "x": X, "y": Y, "button": B}, …]}

`t` never decreases; each event is replayed `t - events[0].t` ms after the
first. Each moves the pointer to (x, y) first; `down`/`up` then press or
release button 1-3 there, `wheel` clicks button 4-7. Other keys (the
recorder's `xt`, `wall`, `mask`) are ignored. A button still held at the end,
or when anything fails, is released; one held when a replay starts (left by a
replay killed at its timeout) is released first. The input is XTest's
(python3-xlib), which the X server treats like a real device's.
"""

from __future__ import annotations

import argparse
import functools
import importlib.machinery
import importlib.util
import json
import math
import os
import sys
import time

RECORDER = "/usr/local/bin/glove-pw-capture"  # the operator's recorder: is it running, wall(), png()
MAX_EVENTS = 10_000
MAX_SIDE = 1 << 14
BUTTONS = {"down": range(1, 4), "up": range(1, 4), "wheel": range(4, 8), "move": None}


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
            return f"events[{i}]: a {e['type']} needs button {allowed.start}-{allowed.stop - 1}"
    return None


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


def replay(plan: dict, display: str, out: str, dry_run: bool) -> int:
    s = Screen(display)
    events = plan["events"]
    result = {"synthetic": True, "dry_run": dry_run, "events": len(events),
              "duration_ms": round(events[-1]["t"] - events[0]["t"]), "display": s.size,
              "pointer_before": s.pointer()}
    if s.size != plan["display"]:
        result.update(status="refused", error=f"the display is {s.size[0]}x{s.size[1]}, the plan was made for "
                                              f"{plan['display'][0]}x{plan['display'][1]}")
    elif dry_run:
        result["status"] = "dry-run"
    else:
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
            for b in sorted(held):
                s.button(b, False)
            result["released"] = sorted(held)
        result.update(ended_at=_recorder().wall(), pointer_after=s.pointer())
        result["end_error_px"] = max(abs(a - int(b)) for a, b in
                                     zip(result["pointer_after"], (events[-1]["x"], events[-1]["y"]), strict=True))
        s.frame(os.path.join(out, "after.png"))
    body = json.dumps(result, indent=1)
    create(os.path.join(out, "result.json"), (body + "\n").encode())
    print(body)
    return {"ok": 0, "dry-run": 0}.get(result["status"], 2)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="browser_event.py")
    sub = ap.add_subparsers(dest="event", required=True)
    st = sub.add_parser("status")
    st.add_argument("--display", default=":1")
    rp = sub.add_parser("replay")
    rp.add_argument("plan")
    rp.add_argument("--out", required=True)
    rp.add_argument("--display", default=":1")
    rp.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)
    if a.event == "status":
        return status(a.display)
    with open(a.plan, encoding="utf-8") as f:
        plan = json.load(f)
    if (err := validate(plan)) is not None:
        print(f"browser_event: {err}", file=sys.stderr)
        return 2
    return replay(plan, a.display, a.out, a.dry_run)


if __name__ == "__main__":
    sys.exit(main())
