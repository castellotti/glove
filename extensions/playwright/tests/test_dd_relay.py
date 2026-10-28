"""`playwright` `dd` trigger relay: the sidecar policy (`image/relay_policy.py`)
policies what the agent may fire on the sidecar's X display. This exercises
`prepare()` against a fake channel / audit dir / recording marker and a fake
relay `Request`, and holds every refusal path the policy promises.

Stdlib only (it loads the policy by path, so it needs no glove dependencies) and
runs under both pytest (the `test_*` functions) and directly
(`python3 test_dd_relay.py`).
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import stat
import sys
import tempfile
import time
from pathlib import Path

IMAGE = Path(__file__).resolve().parent.parent / "image"
POLICY_PATH = IMAGE / "relay_policy.py"
MARKER = "/tmp/capture/.current"  # the sidecar's real recording marker


def make_plan(dx=142, press=(521, 533), release=None, **over):
    if release is None:
        release = (press[0] + dx, press[1])
    path, n = [], 24
    for i in range(n):
        t, f = 200 + i * 90, i / (n - 1)
        x = press[0] + (release[0] - press[0]) * (1 - (1 - f) ** 2)
        y = press[1] + (1 if i % 2 else -1)
        path.append({"t_ms": t, "x": int(x), "y": int(y)})
    plan = {"v": 1, "site": "carfax.com", "display": [1280, 800],
            "press": {"x": press[0], "y": press[1]}, "release": {"x": release[0], "y": release[1]},
            "path": path, "study_delay_ms": 3000}
    plan.update(over)
    return plan


class FakeRequest:
    """relayd's Request, minus /proc: the policy opens the plan itself, so this
    only stands in for argv and the fds list the child would inherit."""

    def __init__(self, argv):
        self.argv = argv
        self.cwd_fd = os.open("/tmp", os.O_RDONLY | os.O_DIRECTORY)
        self.work = ""
        self.settings = {}
        self.fds = [self.cwd_fd]


class Env:
    """A throwaway channel + audit tree the policy (via env) points at."""

    def __init__(self, stale_s="25", audit_writable=True):
        self.root = tempfile.mkdtemp(prefix="dd-relay-test-")
        self.chan = os.path.join(self.root, "chan")
        self.audit = os.path.join(self.root, "audit")
        os.makedirs(os.path.join(self.chan, "plans"))
        if audit_writable:
            os.makedirs(self.audit)
        else:  # an unwritable audit: a file, not a dir -> O_CREAT fails -> refused
            self.audit = os.path.join(self.root, "a-file")
            with open(self.audit, "w") as f:
                f.write("x")
        os.makedirs(os.path.dirname(MARKER), exist_ok=True)

    def stage(self, name, plan, age_s=0.0):
        p = os.path.join(self.chan, "plans", name)
        with open(p, "w") as f:
            json.dump(plan, f)
        if age_s:
            t = time.time() - age_s
            os.utime(p, (t, t))
        return p

    def load(self, stale_s="25"):
        os.environ.update({"DD_CHANNEL": self.chan, "DD_AUDIT_DIR": self.audit,
                           "PW_DD_STALE_S": stale_s, "PW_DD_DISPLAY": ":1"})
        spec = importlib.util.spec_from_file_location("dd_relay_policy_under_test", POLICY_PATH)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        for k in ("DD_CHANNEL", "DD_AUDIT_DIR", "PW_DD_STALE_S", "PW_DD_DISPLAY"):
            os.environ.pop(k, None)
        return mod

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)


def prepare(pol, argv):
    """prepare(); return the child argv, or the Refused message (a string)."""
    req = FakeRequest(argv)
    try:
        out = pol.prepare(req, {})
        return out, req
    except pol.Refused as e:
        return str(e), None


def audit_lines(env):
    try:
        return [json.loads(l) for l in open(os.path.join(env.audit, "trigger.jsonl"))]
    except OSError:
        return []


def test_command_registry():
    pol = Env().load()
    assert pol.COMMANDS == frozenset({"dd-exec", "dd-preflight"})
    assert pol.HOSTS == ()  # the children make no network calls: no egress fence


def test_valid_fire():
    env = Env()
    pol = env.load()
    env.stage("20261028-01.json", make_plan())
    want_sha = hashlib.sha256(open(os.path.join(env.chan, "plans", "20261028-01.json"), "rb").read()).hexdigest()
    out, req = prepare(pol, ["dd-exec", "20261028-01.json"])
    assert isinstance(out, list), out
    assert out[:2] == ["/usr/bin/python3", pol.TOOL], out          # the pinned tool
    assert out[2].startswith("/dev/fd/"), out                        # the plan as a checked fd
    assert int(out[2].rsplit("/", 1)[1]) in req.fds                  # relayd passes it to the child
    assert out[out.index("--out") + 1] == os.path.join(env.chan, "out", "result.json")
    assert out[out.index("--display") + 1] == ":1"                   # the display is pinned
    lines = audit_lines(env)
    assert len(lines) == 1 and lines[0]["cmd"] == "dd-exec", lines
    assert lines[0]["plan_sha256"] == want_sha and lines[0]["dx"] == 142 and lines[0]["dry_run"] is False
    env.cleanup()


def test_dry_run_flag():
    env = Env()
    pol = env.load()
    env.stage("dry.json", make_plan())
    out, _ = prepare(pol, ["dd-exec", "dry.json", "--dry-run"])
    assert isinstance(out, list) and out[-1] == "--dry-run", out
    env.cleanup()


def test_staleness():
    env = Env()
    pol = env.load()
    env.stage("old.json", make_plan(), age_s=30)
    msg, _ = prepare(pol, ["dd-exec", "old.json"])
    assert isinstance(msg, str) and msg.startswith("stale:"), msg   # 30 s > 25 s
    env.stage("fresh.json", make_plan())
    out, _ = prepare(pol, ["dd-exec", "fresh.json"])
    assert isinstance(out, list)                                      # 0 s still fires
    env.cleanup()


def test_schema():
    env = Env()
    pol = env.load()
    cases = [("v=2", make_plan(v=2), "v != 1"),
             ("release.x <= press.x", make_plan(press=(600, 533), release=(521, 533)), "not > press.x"),
             ("press outside display", make_plan(press=(2000, 533)), "outside display"),
             ("study_delay float", make_plan(study_delay_ms=1.5), "study_delay_ms"),
             ("path with one point", make_plan(path=[{"t_ms": 0, "x": 521, "y": 533}]), "< 2 points")]
    bad_range = make_plan(); bad_range["path"][5] = {"t_ms": 600, "x": 99999, "y": 533}
    bad_mono = make_plan(); bad_mono["path"][5]["t_ms"] = -1
    cases += [("path point out of range", bad_range, "out of range"),
              ("non-monotonic path", bad_mono, "not monotonic")]
    for label, plan, want in cases:
        env.stage("c.json", plan)
        msg, _ = prepare(pol, ["dd-exec", "c.json"])
        assert isinstance(msg, str) and want in msg, (label, msg)
    env.cleanup()


def test_recording_guard():
    env = Env()
    pol = env.load()
    env.stage("g.json", make_plan())
    with open(MARKER, "w") as f:
        f.write("00000000-000000-000000 4242\n")
    try:
        msg, _ = prepare(pol, ["dd-exec", "g.json"])
        assert isinstance(msg, str) and "recording is active" in msg, msg
        out, _ = prepare(pol, ["dd-exec", "g.json", "--allow-while-recording"])
        assert isinstance(out, list), out                             # the explicit override
    finally:
        os.unlink(MARKER)
    env.cleanup()


def test_names_and_paths():
    env = Env()
    pol = env.load()
    env.stage("ok.json", make_plan())
    for name in ("../ok.json", "/etc/passwd", "plan.txt", "OK.JSON", ".hidden.json", "a" * 70 + ".json"):
        msg, _ = prepare(pol, ["dd-exec", name])
        assert isinstance(msg, str) and "plan name" in msg, (name, msg)
    msg, _ = prepare(pol, ["dd-exec", "nope.json"])
    assert isinstance(msg, str) and "cannot open" in msg, msg
    link = os.path.join(env.chan, "plans", "link.json")
    os.symlink(os.path.join(env.chan, "plans", "ok.json"), link)
    msg, _ = prepare(pol, ["dd-exec", "link.json"])
    assert isinstance(msg, str) and "link.json" in msg, msg          # O_NOFOLLOW / S_ISREG
    big = env.stage("big.json", make_plan())
    with open(big, "a") as f:
        f.write(" " * (pol.PLAN_MAX + 1))
    msg, _ = prepare(pol, ["dd-exec", "big.json"])
    assert isinstance(msg, str) and "bytes" in msg, msg
    with open(os.path.join(env.chan, "plans", "arr.json"), "w") as f:
        f.write("[1, 2, 3]")
    msg, _ = prepare(pol, ["dd-exec", "arr.json"])
    assert isinstance(msg, str) and "not a JSON object" in msg, msg
    env.cleanup()


def test_flags_and_args():
    env = Env()
    pol = env.load()
    env.stage("f.json", make_plan())
    msg, _ = prepare(pol, ["dd-exec", "f.json", "--bogus"])
    assert isinstance(msg, str) and "unknown flag" in msg, msg
    msg, _ = prepare(pol, ["dd-exec", "f.json", "g.json"])
    assert isinstance(msg, str) and "exactly one plan" in msg, msg
    msg, _ = prepare(pol, ["dd-exec"])
    assert isinstance(msg, str) and "exactly one plan" in msg, msg
    msg, _ = prepare(pol, ["dd-exec", "f.json", "--dry-run", "--dry-run"])
    assert isinstance(msg, str) and "twice" in msg, msg
    out, _ = prepare(pol, ["dd-preflight"])
    assert isinstance(out, list) and out[1] == pol.PFLIGHT, out
    msg, _ = prepare(pol, ["dd-preflight", "--x"])
    assert isinstance(msg, str) and "no arguments" in msg, msg
    msg, _ = prepare(pol, ["dd-other", "f.json"])
    assert isinstance(msg, str) and "runs only" in msg, msg
    env.cleanup()


def test_audit_fail_closed():
    env = Env(audit_writable=False)
    pol = env.load()
    env.stage("a.json", make_plan())
    msg, _ = prepare(pol, ["dd-exec", "a.json"])
    assert isinstance(msg, str) and "audit is unwritable" in msg, msg  # refused, never fired
    env.cleanup()


_TESTS = [test_command_registry, test_valid_fire, test_dry_run_flag, test_staleness,
          test_schema, test_recording_guard, test_names_and_paths, test_flags_and_args,
          test_audit_fail_closed]


def main():
    print(f"policy under test: {POLICY_PATH}")
    failed = 0
    for t in _TESTS:
        try:
            t()
            print(f"ok   {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL {t.__name__}: {e}")
    print(f"\n{failed} failure(s) across {len(_TESTS)} tests")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
