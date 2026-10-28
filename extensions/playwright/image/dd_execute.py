#!/usr/bin/env python3
"""dd_execute.py — execute a dd_drag_plan.py plan on the X desktop.

Input backends (auto: prefer xtest, fall back to xdotool):
  * xtest   — python-xlib XTest (shipped in the pw sidecar image; no install
              needed, runs unprivileged). XTest-faked events enter the X
              server like real hardware input: the target page sees trusted
              OS-level events (isTrusted===true), same class as xdotool.
  * xdotool — subprocess calls (used where python-xlib is absent, e.g. the
              analysis sandbox — which has no display, so live runs refuse).

Runs on the SIDEcar (where Playwright's Chromium renders on the VNC/X
desktop) — in the harness/analysis sandbox it validates and dry-runs only.
Display coordinate space IS the desktop px space of the challenge captures
(1280x800, dpr=1) — no conversion needed.

Usage:
  dd_execute.py PLAN.json [--out RESULT.json] [--dry-run]
                  [--display :1] [--backend auto|xtest|xdotool]

Behaviour:
  * validates the plan (schema v1), reads display geometry + mouse position
  * waits study_delay_ms (the human "read the puzzle" beat)
  * press at path[0]; timed move per path point; release at the last point
  * if anything fails mid-drag, the button is always released (never held)
  * result JSON is always marked "synthetic": true and carries ISO start/
    press/end times, so a concurrent challenge recording can identify and
    exclude these events from human (operator) solves
  * writes the result JSON (or prints it)

--dry-run: validates the plan and prints the schedule without dispatching
anything — safe anywhere.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone

SCHEMA_V = 1


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def fail(msg):
    sys.stderr.write("dd_execute: %s\n" % msg)
    sys.exit(1)


def validate(plan):
    if plan.get("v") != SCHEMA_V:
        fail("plan schema v=%s (expected %d)" % (plan.get("v"), SCHEMA_V))
    for k in ("site", "display", "press", "release", "path"):
        if k not in plan:
            fail("plan missing key %r" % k)
    p = plan["path"]
    if not isinstance(p, list) or len(p) < 2:
        fail("path needs >= 2 points")
    t_prev = -1
    for i, pt in enumerate(p):
        for k in ("t_ms", "x", "y"):
            if k not in pt:
                fail("path[%d] missing %r" % (i, k))
        if pt["t_ms"] < t_prev:
            fail("path times not monotonic at index %d" % i)
        t_prev = pt["t_ms"]
        if not (0 <= pt["x"] < 8192 and 0 <= pt["y"] < 8192):
            fail("path[%d] coordinates out of range" % i)
    if not isinstance(plan.get("study_delay_ms", 0), int):
        fail("study_delay_ms must be an int (ms)")


class XTestIO:
    """python-xlib XTest: fake hardware-class input events into the X server.

    Grounded in the real python-xlib source (Xlib/ext/xtest.py — unchanged in
    shape since 2000, incl. 0.33): the extension registers
    ``display.xtest_fake_input(event_type, detail=0, time=CurrentTime,
    root=NONE, x=0, y=0)`` where event_type is a CORE X event type
    (X.ButtonPress=4, X.ButtonRelease=5, X.MotionNotify=6) and detail is the
    button number. The module-level ``xtest.fake_input`` is the same function
    unbound (takes the display as first argument). All 2026-10-23 live
    debugging traced back to assumptions that contradicted this source.
    """

    def __init__(self, display_name):
        try:
            from Xlib import X
            from Xlib import display as xd
            from Xlib.ext import xtest
        except ImportError:
            raise RuntimeError("python-xlib not importable")
        self.X = X
        self.xtest = xtest
        # positional display arg: works on all versions (0.33 rejects the
        # display_name= keyword)
        self.d = xd.Display(display_name)
        self.root = self.d.screen().root
        # canonical entry point is the method registered on Display by
        # xtest.init(); fall back to the module-level unbound function
        if hasattr(self.d, "xtest_fake_input"):
            self._call = lambda *a, **k: self.d.xtest_fake_input(*a, **k)
        else:
            self._call = lambda *a, **k: xtest.fake_input(self.d, *a, **k)
        try:
            import Xlib
            self.version = list(getattr(Xlib, "__version__", ("?",))) or "?"
        except Exception:
            self.version = "?"
        # swallow stray X protocol errors (e.g. a RandR probe the sidecar's
        # Xvnc answers with BadRRModeError) — they must not abort a drag;
        # they are recorded in the result for diagnostics
        self.xerrors = []
        try:
            self.d.set_error_handler(self._xerr)
        except Exception:
            pass

    def _xerr(self, *args):
        self.xerrors.append(repr(args[0]) if args else "?")

    def mousemove(self, x, y):
        self._call(self.X.MotionNotify, detail=0, root=self.root,
                   x=int(x), y=int(y))
        self.d.sync()  # block until the server has delivered the event

    def mousedown(self):
        # button 1 at the pointer's current position (root defaults to X.NONE)
        self._call(self.X.ButtonPress, detail=1)
        self.d.sync()

    def mouseup(self):
        self._call(self.X.ButtonRelease, detail=1)
        self.d.sync()

    def mouse_pos(self):
        q = self.root.query_pointer()
        return {"x": int(q.root_x), "y": int(q.root_y)}

    def screenshot_ppm(self, out_path, x=420, y=180, w=430, h=420):
        """Grab a region of the X root window -> binary RGB PPM (P6).

        X pixels arrive as native-endian 32-bit values; on the arm64 sidecar
        that is little-endian, so each 4-byte group is [B, G, R, X]. We emit
        P6 (the universally-supported binary color format — note P5 is
        officially *graymap* and Pillow/OpenCV read 3-plane P5 as grayscale,
        so it is a non-starter for round-tripping through decoders).
        Channel planes are extracted with C-speed bytes slicing; the final
        RGB interleave is a ~0.3 s join for the 430x420 card region —
        comfortably inside the 15 s puzzle window.
        """
        t0 = time.monotonic()
        img = self.root.get_image(x, y, w, h, self.X.ZPixmap, 0xffffffff)
        raw = img.data
        if isinstance(raw, str):
            raw = raw.encode("latin-1")
        raw = raw[: w * h * 4]
        r, g, b = raw[2::4], raw[1::4], raw[0::4]
        rgb = bytearray(w * h * 3)
        rgb[0::3] = r
        rgb[1::3] = g
        rgb[2::3] = b
        rgb = bytes(rgb)
        header = ("P6\n%d %d\n255\n" % (w, h)).encode()
        with open(out_path, "wb") as f:
            f.write(header + rgb)
        ms = int((time.monotonic() - t0) * 1000)
        # sanity diagnostics: the card is mostly light grey/white
        mean = sum(r[:1024]) / min(1024, len(r))
        return {"path": out_path, "x": x, "y": y, "w": w, "h": h,
                "grab_ms": ms, "file_bytes": len(header) + len(rgb),
                "mean_r_sample": int(mean)}

    def display_geometry(self):
        s = self.d.screen()
        return [int(s.width_in_pixels), int(s.height_in_pixels)]

    def close(self):
        self.d.close()


class XdotoolIO:
    """xdotool subprocess backend (fallback)."""

    def __init__(self, display_name):
        self.display = display_name
        if shutil.which("xdotool") is None:
            raise RuntimeError("xdotool not found in PATH")

    def _run(self, *args):
        env = dict(os.environ)
        if self.display:
            env["DISPLAY"] = self.display
        r = subprocess.run(["xdotool", *args], env=env,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if r.returncode != 0:
            raise RuntimeError("xdotool %s failed: %s"
                               % (args[0], (r.stdout or r.stderr).decode().strip()[:120]))
        return (r.stdout or r.stderr).decode().strip()

    def mousemove(self, x, y):
        self._run("mousemove", "--sync", "--clearmodifiers", str(int(x)), str(int(y)))

    def mousedown(self):
        self._run("mousedown", "1")

    def mouseup(self):
        self._run("mouseup", "1")

    def mouse_pos(self):
        out = self._run("getmouselocation")
        pos = {}
        for tok in out.replace("\n", " ").split():
            if tok.startswith("x:"):
                pos["x"] = int(tok[2:])
            elif tok.startswith("y:"):
                pos["y"] = int(tok[2:])
        return pos or None

    def display_geometry(self):
        try:
            parts = self._run("getdisplaygeometry").split()
            return [int(v) for v in parts[:2]]
        except RuntimeError:
            return None

    def close(self):
        pass


def open_io(backend, display):
    """Return (io, backend_name). backend 'auto': xtest if available, else xdotool."""
    errors = []
    if backend in ("auto", "xtest"):
        try:
            return XTestIO(display), "xtest"
        except Exception as e:  # noqa: BLE001
            if backend == "xtest":
                raise
            errors.append("xtest: %s" % e)
    if backend in ("auto", "xdotool"):
        try:
            return XdotoolIO(display), "xdotool"
        except Exception as e:  # noqa: BLE001
            errors.append("xdotool: %s" % e)
    raise RuntimeError("no input backend available (%s)" % ("; ".join(errors) or backend))


def execute(plan, display=None, backend="auto", dry=False, shots_dir=None):
    validate(plan)
    io = None
    backend_name = None
    result = {
        "tool": "dd_execute", "plan_file": plan.get("plan_file"),
        "site": plan["site"],
        "display_expected": list(plan["display"]),
        "display_requested": display,
        "dry_run": dry,
        "synthetic": True,  # ALWAYS: events from this tool are machine-generated
    }
    if not dry:
        try:
            io, backend_name = open_io(backend, display)
        except Exception as e:  # noqa: BLE001
            fail("no usable input backend: %s (hint: --backend xtest|xdotool, "
                 "DISPLAY set? python-xlib installed? xdotool in PATH?)" % e)
        result["backend"] = backend_name
        if backend_name == "xtest":
            result["xlib_version"] = getattr(io, "version", "?")
            result["xerrors_swallowed"] = len(getattr(io, "xerrors", []))
        result["display_actual"] = io.display_geometry()
        result["started_at"] = now_iso()
        try:
            result["mouse_before"] = io.mouse_pos()
        except Exception as e:  # noqa: BLE001
            io.close()
            fail("could not read mouse position: %s "
                 "(DISPLAY=%s set? X server reachable?)" % (e, display))
        if result["mouse_before"] is None:
            io.close()
            fail("could not read mouse position (DISPLAY=%s set? X reachable?)"
                 % display)

    path = plan["path"]
    study = plan.get("study_delay_ms", 0)
    print("plan: site=%s dx=%d study=%dms events=%d duration=%dms%s" % (
        plan["site"], path[-1]["x"] - path[0]["x"], study,
        len(path), path[-1]["t_ms"],
        "" if dry else "  [backend=%s display=%s]" % (backend_name, display)),
        flush=True)

    if dry:
        result.update(status="dry-run", events_dispatched=0)
        return result

    pressed = False
    t0 = None
    try:
        time.sleep(max(0.0, study / 1000.0))
        io.mousemove(path[0]["x"], path[0]["y"])
        time.sleep(0.05)  # settle on the knob before pressing
        io.mousedown()
        pressed = True
        result["t_press"] = now_iso()
        t0 = time.monotonic()
        if shots_dir and hasattr(io, "screenshot_ppm"):
            try:
                os.makedirs(shots_dir, exist_ok=True)
                result["shot_press"] = io.screenshot_ppm(
                    os.path.join(shots_dir,
                                 "press-%s.ppm" % result["t_press"].replace(":", "-")))
            except Exception as e:  # noqa: BLE001
                result["shot_press_error"] = str(e)
        n = 1
        for pt in path[1:]:
            target = t0 + pt["t_ms"] / 1000.0
            now = time.monotonic()
            if target > now:
                time.sleep(target - now)
            io.mousemove(pt["x"], pt["y"])
            n += 1
        io.mouseup()
        result["t_end"] = now_iso()
        result.update(status="ok", events_dispatched=n + 1,
                      wall_duration_ms=int((time.monotonic() - t0) * 1000))
        if shots_dir and hasattr(io, "screenshot_ppm"):
            try:
                result["shot_post"] = io.screenshot_ppm(
                    os.path.join(shots_dir,
                                 "post-%s.ppm" % result["t_end"].replace(":", "-")))
            except Exception as e:  # noqa: BLE001
                result["shot_post_error"] = str(e)
    except Exception as e:  # noqa: BLE001 - report and clean up
        result.update(status="error", error=str(e))
        if pressed:
            try:
                io.mouseup()
                result["released_after_error"] = True
            except Exception:  # noqa: BLE001
                pass
    finally:
        if io is not None:
            try:
                result["mouse_after"] = io.mouse_pos()
                b, a = result.get("mouse_before"), result.get("mouse_after")
                if b and a:
                    result["actual_dx"] = a["x"] - b["x"]
                    result["actual_dy"] = a["y"] - b["y"]
                    result["dx_error_px"] = result["actual_dx"] - (
                        path[-1]["x"] - path[0]["x"])
                # the real M1/M2 success metric: the pointer must END at the
                # planned release point, regardless of where it started
                rel = plan.get("release")
                if a and rel:
                    result["release_expected"] = [rel["x"], rel["y"]]
                    result["landing_error_px"] = max(
                        abs(a["x"] - rel["x"]), abs(a["y"] - rel["y"]))
            except Exception:  # noqa: BLE001
                pass
            try:
                io.close()
            except Exception:  # noqa: BLE001
                pass
    return result


def main():
    ap = argparse.ArgumentParser(description="execute a drag plan on the X desktop")
    ap.add_argument("plan")
    ap.add_argument("--out", help="write result JSON here (default: stdout)")
    ap.add_argument("--display", default=None,
                    help="X display, e.g. :1 (default: $DISPLAY / local default)")
    ap.add_argument("--backend", choices=["auto", "xtest", "xdotool"],
                    default="auto")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--shots", default=None, metavar="DIR",
                    help="grab a PPM of the card region (x420 y180 430x420) "
                         "at press-time and after release, into DIR "
                         "(XTest backend only; the sidecar wrapper copies "
                         "them back to the harness)")
    a = ap.parse_args()
    try:
        with open(a.plan) as f:
            plan = json.load(f)
    except Exception as e:  # noqa: BLE001
        fail("cannot read plan: %s" % e)
    plan["plan_file"] = a.plan
    if a.shots:
        os.makedirs(a.shots, exist_ok=True)
    res = execute(plan, display=a.display, backend=a.backend, dry=a.dry_run,
                  shots_dir=a.shots)
    out = json.dumps(res, indent=1)
    if a.out:
        with open(a.out, "w") as f:
            f.write(out + "\n")
        print("result written to %s" % a.out)
    else:
        print(out)
    if res.get("status") == "error":
        sys.exit(2)


if __name__ == "__main__":
    main()
