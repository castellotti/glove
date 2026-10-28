#!/usr/bin/env python3
"""dd_preflight.py — liveness probe for the dd trigger relay (runs in the pw
sidecar under relayd; `dd-preflight` from the sandbox reaches it over the
dd channel). Sends NO input events. Prints one JSON object on stdout:

  {"display": [w, h], "pointer": [x, y], "xtest": true,
   "recording": false, "x_socket": true}

`recording` mirrors the `/tmp/capture/.current` marker a `glove playwright
solve` session arms (the same one the relay policy's guard reads), so the
agent can see a recording state that would make `dd-exec` refuse.
Exit 1 (with `error` in the JSON) when the X display is unreachable.
"""
import argparse
import json
import os
import sys


def main() -> int:
    ap = argparse.ArgumentParser(description="dd trigger preflight probe")
    ap.add_argument("--display", default=os.environ.get("PW_DD_DISPLAY", ":1"))
    a = ap.parse_args()
    out = {
        "display": None,
        "pointer": None,
        "xtest": False,
        "recording": os.path.exists("/tmp/capture/.current"),
        "x_socket": os.path.exists("/tmp/.X11-unix/X1"),
    }
    try:
        from Xlib import display as xd
        from Xlib.ext import xtest  # noqa: F401  (importable == XTest available)
        d = xd.Display(a.display)
        s = d.screen()
        out["display"] = [s.width_in_pixels, s.height_in_pixels]
        out["xtest"] = True
        try:
            p = d.query_pointer().root_returned
            out["pointer"] = [p.win_x, p.win_y]
        except Exception:
            pass
        d.close()
    except Exception as e:
        out["error"] = f"display unreachable: {e}"
        print(json.dumps(out))
        return 1
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
