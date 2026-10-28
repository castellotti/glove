"""The playwright `dd` channel's relay policy (loaded by path by relay's
relayd.py, which runs in the `pw` sidecar beside the X display the agent's
trigger fires on).

Commands (the whole static set — anything else is refused by relayd):

  dd-exec PLAN [--allow-while-recording] [--dry-run]
      Run the pinned /opt/glove/dd/dd_execute.py on this sidecar's X display
      with the plan the agent staged in this channel: `<chan>/plans/PLAN`
      (PLAN is a bare file name — no path, no escapes), at most STALE_S old
      (the puzzle it aims at is gone after ~15–18 s), schema v1, press and
      release inside the display, release.x > press.x, monotone path. Refused
      while a `glove playwright solve` recording is armed
      (`/tmp/capture/.current` — the same marker `glove-pw-front.js` and the
      manual `dd-sidecar.sh` guard read) unless --allow-while-recording is
      given. The child gets no stdin, no network of its own (its env is the
      one `setup` returns), the plan only as a checked /dev/fd, fixed
      --out/--shots paths under the channel, and relayd kills its process
      group after --timeout.

  dd-preflight
      Probe, no pointer events: X display reachable, XTest importable,
      display size, pointer position, recording state. (Relay-level
      liveness — "is the door there" — the agent gets from dd-exec's exit
      127 when relayd is not serving.)

Trust edge (what this file polices, and only this):

- The agent may write plan files under `<chan>/plans/` (a writable channel
  dir, like any /work file) and may read `<chan>/out/` and `/work/dd-audit/`.
- It may choose: the plan file name (regex below), --allow-while-recording,
  --dry-run. It may not choose: the program, the display, the output paths,
  any flag, or any value that reaches the child. argv is a NUL-separated
  file relayd execs as a list — no shell anywhere near agent data.
- Audit: one JSON line per request is appended (O_APPEND) to the dd-audit
  output root before the child starts; the harness reads that root
  read-only at /work/dd-audit (the agent cannot write or delete there), and
  relayd's own `… -> rc` line lands in the sidecar's container log on the
  host. A request that could not be audited is refused, never fired.

Rollout note: --dry-run is valid at every stage (the tool dispatches nothing
with it); S2 exercises it, S3 simply stops using it.
"""

from __future__ import annotations

import datetime as _dt
import fcntl
import hashlib
import json
import os
import re
import shutil
import time

# --- pinned, reviewed data -------------------------------------------------------

# Where relayd's --channel points (glove-pw-start) and where the dd-audit
# output root is bound into the sidecar (core's OUTPUT_ROOT convention).
CHAN = os.environ.get("DD_CHANNEL", "/run/glove/dd")
AUDIT = os.environ.get("DD_AUDIT_DIR", "/run/glove-output/dd-audit")
DISPLAY = os.environ.get("PW_DD_DISPLAY", ":1")
STALE_S = float(os.environ.get("PW_DD_STALE_S", "25"))  # puzzle lifetime ~15–18 s

TOOL = "/opt/glove/dd/dd_execute.py"
PFLIGHT = "/opt/glove/dd/dd_preflight.py"

# SHA-256 of the pinned executables, as baked into this image. When a tool
# changes, rebuild the image and record its new hash here (a human act):
# a mismatch at relayd start kills relayd, so the channel stops being served
# (fail closed) instead of running code that is not the reviewed one.
PINNED: dict[str, str] = {
    TOOL: "a7169295fe2b61f0d70acaeb3dbac9fb3aa50629fe19907848633b14520ff14a",
    PFLIGHT: "d2318916b1bf36ac2adbbda3b4f5b96002d29fdf4943f7b781f668477cbabdc6",
}

COMMANDS = frozenset({"dd-exec", "dd-preflight"})
HOSTS = ()  # the children make no network calls; relayd builds no fence


class Refused(Exception):
    """This invocation is not relayed (relayd shows the message, exit 126)."""


# --- audit -----------------------------------------------------------------------


def _audit_line(obj: dict) -> None:
    """Append one JSON line to the audit output root; refusing (not firing)
    when the audit is unwritable: a trigger that could not be audited must
    not be reported as fired."""
    fd = os.open(os.path.join(AUDIT, "trigger.jsonl"),
                 os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, (json.dumps(obj, separators=(",", ":")) + "\n").encode())
    finally:
        os.close(fd)


def _utcnow() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="milliseconds")


# --- startup: pin check ------------------------------------------------------------


def setup(ctx: dict) -> dict[str, str]:
    """Runs once in relayd before it serves: verify the pinned executables,
    else refuse to serve at all (SystemExit: no door, every trigger is a
    fail-closed no-op)."""
    for path, want in sorted(PINNED.items()):
        if want.startswith("<set-by-install.sh"):
            raise SystemExit(f"relayd: {path} has no pin recorded (run install.sh); refusing to serve")
        try:
            h = hashlib.sha256(open(path, "rb").read()).hexdigest()
        except OSError as e:
            raise SystemExit(f"relayd: pinned {path} missing ({e.strerror}); refusing to serve") from None
        if h != want:
            raise SystemExit(f"relayd: pinned {path} hash mismatch (want {want[:16]}…, got {h[:16]}…); "
                             "refusing to serve")
    import importlib.util
    if importlib.util.find_spec("Xlib") is None:
        raise SystemExit("relayd: python-xlib missing from the sidecar image; refusing to serve")
    print("relayd: dd policy ok: " + ", ".join(f"{os.path.basename(p)} pinned" for p in PINNED), flush=True)
    return {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": "/home/pw",
        "DISPLAY": DISPLAY,
        "TZ": os.environ.get("TZ", "UTC"),
        "LANG": "C.UTF-8",
    }


# --- plan checks (mirror dd_execute.py's validator, which re-checks in the child) --


PLAN_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\.json\Z")
PLAN_MAX = 64 * 1024
PTS_MAX = 8192  # dd_execute.py's coordinate cap


def _num(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and v == v and v not in (float("inf"), float("-inf"))


def validate_plan(p: dict) -> str | None:
    """None when the plan is fireable; a reason otherwise."""
    if p.get("v") != 1:
        return f"plan v != 1 (got {p.get('v')!r})"
    for k in ("site", "display", "press", "release", "path"):
        if k not in p:
            return f"plan missing key {k!r}"
    disp = p["display"]
    if not (isinstance(disp, list) and len(disp) == 2 and all(_num(n) and 0 < n <= PTS_MAX for n in disp)):
        return "plan display is not [w, h] within bounds"
    for k in ("press", "release"):
        pt = p[k]
        if not isinstance(pt, dict) or not (_num(pt.get("x")) and _num(pt.get("y"))):
            return f"plan {k} missing numeric x/y"
        if not (0 <= pt["x"] < disp[0] and 0 <= pt["y"] < disp[1]):
            return f"plan {k} outside display bounds {disp}"
    if not p["release"]["x"] > p["press"]["x"]:
        return "release.x not > press.x (no forward drag)"
    path = p["path"]
    if not isinstance(path, list) or len(path) < 2:
        return "plan path missing or < 2 points"
    t_prev = -1
    for i, pt in enumerate(path):
        if not (isinstance(pt, dict) and all(k in pt for k in ("t_ms", "x", "y"))):
            return f"path[{i}] missing t_ms/x/y"
        if not (_num(pt["t_ms"]) and _num(pt["x"]) and _num(pt["y"])):
            return f"path[{i}] non-numeric"
        if pt["t_ms"] < t_prev:
            return f"path times not monotonic at index {i}"
        t_prev = pt["t_ms"]
        if not (0 <= pt["x"] < PTS_MAX and 0 <= pt["y"] < PTS_MAX):
            return f"path[{i}] coordinates out of range"
    if not (isinstance(p.get("study_delay_ms", 0), int) and not isinstance(p.get("study_delay_ms", 0), bool)
            and 0 <= p["study_delay_ms"] <= 60000):
        return "study_delay_ms must be an int in [0, 60000] ms"
    return None


# --- request handling --------------------------------------------------------------


def _open_plan(req, name: str) -> tuple[int, dict, float, str]:
    """Open the staged plan race-free and checked; return (fd, plan, age_s, sha256).

    Bare name under <chan>/plans/ (a symlink is refused by O_NOFOLLOW); the
    fd is what the child will read, so swapping the path later changes
    nothing ("what is checked is what was opened").
    """
    if not PLAN_NAME.fullmatch(name):
        raise Refused(f"plan name {name!r} must match {PLAN_NAME.pattern} (a file in the channel's plans/ dir)")
    path = os.path.join(CHAN, "plans", name)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as e:
        raise Refused(f"cannot open plans/{name}: {e.strerror}") from None
    st = os.fstat(fd)
    import stat as _stat
    if not _stat.S_ISREG(st.st_mode):
        os.close(fd)
        raise Refused(f"plans/{name} is not a regular file")
    if st.st_size > PLAN_MAX:
        os.close(fd)
        raise Refused(f"plans/{name} is {st.st_size} bytes (limit {PLAN_MAX})")
    age = time.time() - st.st_mtime
    fcntl.fcntl(fd, fcntl.F_SETFL, fcntl.fcntl(fd, fcntl.F_GETFL) & ~os.O_NONBLOCK)
    raw = os.read(fd, PLAN_MAX)
    sha = hashlib.sha256(raw).hexdigest()
    # rewind: the child reads this same fd, and the read above left it at EOF
    os.lseek(fd, 0, os.SEEK_SET)
    try:
        plan = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        os.close(fd)
        raise Refused(f"plans/{name} is not parseable JSON: {e}") from None
    if not isinstance(plan, dict):
        os.close(fd)
        raise Refused("plans/%s is not a JSON object" % name)
    return fd, plan, age, sha


def prepare(req, env: dict[str, str]) -> list[str]:
    argv = req.argv
    cmd, args = argv[0], argv[1:]

    if cmd == "dd-preflight":
        if args:
            raise Refused("dd-preflight takes no arguments")
        _audit_line({"ts": _utcnow(), "channel": CHAN, "cmd": "dd-preflight"})
        return ["/usr/bin/python3", PFLIGHT, "--display", DISPLAY]

    if cmd != "dd-exec":
        raise Refused(f"this relay runs only {sorted(COMMANDS)}")

    flags: set[str] = set()
    names = []
    for a in args:
        if a in ("--allow-while-recording", "--dry-run"):
            if a in flags:
                raise Refused(f"flag {a} given twice")
            flags.add(a)
        elif a.startswith("-"):
            raise Refused(f"unknown flag {a!r} (allowed: --allow-while-recording, --dry-run)")
        else:
            names.append(a)
    if len(names) != 1:
        raise Refused(f"dd-exec takes exactly one plan name, got {names!r}")

    # Recording guard: the same /tmp/capture/.current marker the manual
    # dd-sidecar.sh guard and glove-pw-front.js use — synthetic drags would
    # be ambiguous inside an operator solve.
    if os.path.exists("/tmp/capture/.current") and "--allow-while-recording" not in flags:
        raise Refused("a `glove playwright solve` recording is active: synthetic drags would be captured and "
                      "could be mislabeled as operator solves; wait for it to finish, or pass "
                      "--allow-while-recording to override")

    name = names[0]
    fd, plan, age, sha = _open_plan(req, name)
    if (err := validate_plan(plan)) is not None:
        os.close(fd)
        raise Refused(err)
    if age > STALE_S:
        os.close(fd)
        raise Refused(f"stale: plans/{name} is {age:.1f} s old (limit {STALE_S:g} s) — the puzzle it aims at "
                      "is gone; re-aim and stage a fresh plan")

    # One audit line before anything runs (see module docstring).
    try:
        _audit_line({"ts": _utcnow(), "channel": CHAN, "cmd": "dd-exec", "plan": name,
                     "plan_sha256": sha, "age_s": round(age, 1), "stale_s": STALE_S,
                     "allow_recording": "--allow-while-recording" in flags,
                     "dry_run": "--dry-run" in flags, "display": plan.get("display"),
                     "dx": plan["release"]["x"] - plan["press"]["x"]})
    except OSError as e:
        os.close(fd)
        raise Refused(f"audit is unwritable ({e.strerror}): refusing to fire un-audited") from None

    # Fixed, policy-owned output paths (the agent picks none of them): fresh
    # per firing — single-flight (relayd --max 1) means no live reader.
    out = os.path.join(CHAN, "out")
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(os.path.join(out, "shots"), mode=0o700, exist_ok=True)
    result = os.path.join(out, "result.json")

    # Hand the checked fd to the child (relayd passes req.fds via pass_fds).
    req.fds.append(fd)
    child = ["/usr/bin/python3", TOOL, f"/dev/fd/{fd}",
             "--out", result, "--shots", os.path.join(out, "shots"), "--display", DISPLAY]
    if "--dry-run" in flags:
        child.append("--dry-run")
    return child


if __name__ == "__main__":  # sandbox self-test: python3 relay_policy.py --selftest
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        import tempfile
        print("relay_policy: self-test runs from tests/test_policy.py "
              "(it exercises prepare() with fake channel/audit/marker dirs)")
        sys.exit(1)
    raise SystemExit("relay_policy.py is loaded by relayd; use tests/test_policy.py --run")
