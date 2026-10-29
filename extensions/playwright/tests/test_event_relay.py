"""`playwright: {event_relay: true}`: the agent sends events to the browser
sidecar (`browser-event status|replay`) over the `browser-event` relay channel.
The policy (image/relay_policy.py) against a fake channel, log and recording
marker; the replay program (image/browser_event.py) against a fake display; and
what the setting adds to the session."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from helpers import make_cfg, render

from glove.extensions import IN_TREE_DIR, ExtensionError

PW = IN_TREE_DIR / "playwright"
IMAGE = PW / "image"

# the recorder's own rows (glove-pw-capture's events.jsonl): a recording replays as it is
EVENTS = [
    {"t": 1437, "xt": 20567499, "wall": "2026-10-20T10:17:42.895Z", "type": "down", "button": 1,
     "x": 300, "y": 400, "mask": 256},
    {"t": 1538, "xt": 20567600, "wall": "2026-10-20T10:17:42.996Z", "type": "move", "button": 0,
     "x": 320, "y": 401, "mask": 256},
    {"t": 1971, "xt": 20568034, "wall": "2026-10-20T10:17:43.430Z", "type": "up", "button": 1,
     "x": 700, "y": 420, "mask": 0},
    {"t": 2400, "xt": 20568463, "wall": "2026-10-20T10:17:43.859Z", "type": "wheel", "button": 5,
     "x": 700, "y": 420, "mask": 0},
]
PLAN = {"v": 1, "display": [1280, 800], "events": EVENTS}


def _load(name: str):
    spec = importlib.util.spec_from_file_location(f"pw_{name}_under_test", IMAGE / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FakeRequest:
    """What relayd hands the policy: the argv (and the fds the program would inherit: none here)."""

    def __init__(self, argv):
        self.argv = argv
        self.fds: list[int] = []


@pytest.fixture
def pol(tmp_path, monkeypatch):
    pol = _load("relay_policy")
    (tmp_path / "chan" / "plans").mkdir(parents=True)
    (tmp_path / "log").mkdir()
    monkeypatch.setattr(pol, "CHANNEL", str(tmp_path / "chan"))
    monkeypatch.setattr(pol, "LOG_ROOT", str(tmp_path / "log"))
    monkeypatch.setattr(pol.program, "recording", lambda: False)
    yield pol


def _stage(pol, name: str, plan=PLAN) -> str:
    path = os.path.join(pol.CHANNEL, "plans", name)
    with open(path, "w") as f:
        f.write(plan if isinstance(plan, str) else json.dumps(plan))
    return path


def _prepare(pol, *argv):
    """The program's argv, or the refusal's message."""
    req = FakeRequest(["browser-event", *argv])
    try:
        return pol.prepare(req, {}), req
    except pol.Refused as e:
        return str(e), req


def _log(pol) -> list[dict]:
    path = os.path.join(pol.LOG_ROOT, "log.jsonl")
    return [json.loads(line) for line in open(path)] if os.path.exists(path) else []


# --- the policy --------------------------------------------------------------------------------------------------

def test_one_command_and_no_route(pol):
    assert set(pol.COMMANDS) == {"browser-event"} and pol.HOSTS == ()
    env = pol.setup({})
    assert env["DISPLAY"] == ":1" and not {"HTTP_PROXY", "HTTPS_PROXY", "http_proxy"} & set(env)


def test_status_runs_the_probe_and_is_logged(pol):
    argv, _ = _prepare(pol, "status")
    assert argv == ["/usr/bin/python3", pol.PROGRAM, "status", "--display", ":1"]
    assert [e["event"] for e in _log(pol)] == ["status"]


def test_replay_runs_the_checked_copy_of_the_plan(pol):
    staged = _stage(pol, "p1.json")
    raw = Path(staged).read_bytes()
    argv, req = _prepare(pol, "replay", "p1.json")
    out = argv[argv.index("--out") + 1]
    assert argv[:4] == ["/usr/bin/python3", pol.PROGRAM, "replay", os.path.join(out, "plan.json")] and not req.fds
    assert os.path.dirname(out) == pol.LOG_ROOT and Path(out, "plan.json").read_bytes() == raw
    assert not os.path.exists(staged)  # used up: rewriting plans/ afterwards changes nothing
    assert argv[argv.index("--display") + 1] == ":1" and "--dry-run" not in argv
    (entry,) = _log(pol)
    assert entry["event"] == "replay" and entry["id"] == os.path.basename(out) and entry["events"] == 4
    assert entry["dry_run"] is False and entry["plan_sha256"] == hashlib.sha256(raw).hexdigest()


def test_dry_run_is_passed_on(pol):
    _stage(pol, "p.json")
    argv, _ = _prepare(pol, "replay", "p.json", "--dry-run")
    assert argv[-1] == "--dry-run" and _log(pol)[0]["dry_run"] is True


@pytest.mark.parametrize(("argv", "match"), [
    ((), "usage: browser-event status"),
    (("click",), "usage: browser-event status"),
    (("status", "now"), "status takes no arguments"),
    (("replay",), "one plan name"),
    (("replay", "a.json", "b.json"), "one plan name"),
    (("replay", "p.json", "--force"), "unexpected --force"),
    (("replay", "p.json", "--dry-run", "--dry-run"), "unexpected --dry-run"),
    (("replay", "p.json", "--allow-while-recording"), "unexpected --allow-while-recording"),  # the session's call
])
def test_arguments_the_policy_does_not_take_are_refused(pol, argv, match):
    _stage(pol, "p.json")
    msg, req = _prepare(pol, *argv)
    assert isinstance(msg, str) and match in msg and not req.fds
    (entry,) = _log(pol)  # a refusal is logged too
    assert entry["refused"] == msg and entry["args"] == list(argv[1:5])


def test_a_refusal_logs_what_was_asked_bounded(pol):
    _prepare(pol, "x" * 500, *["y" * 500] * 9)
    (entry,) = _log(pol)
    assert len(entry["event"]) == 40 and len(entry["args"]) == 4 and {len(a) for a in entry["args"]} == {100}


@pytest.mark.parametrize("name", ["../p.json", "/etc/passwd", "p.txt", "P.JSON", ".p.json", "a" * 70 + ".json"])
def test_a_plan_is_a_bare_name_in_plans(pol, name):
    msg, _ = _prepare(pol, "replay", name)
    assert "want a file name in" in msg


def test_a_plan_must_be_a_small_regular_json_file(pol):
    assert "No such file" in _prepare(pol, "replay", "none.json")[0]
    os.symlink(_stage(pol, "real.json"), os.path.join(pol.CHANNEL, "plans", "link.json"))
    assert "link.json" in _prepare(pol, "replay", "link.json")[0]  # O_NOFOLLOW
    os.mkdir(os.path.join(pol.CHANNEL, "plans", "dir.json"))
    assert "not a regular file" in _prepare(pol, "replay", "dir.json")[0]
    _stage(pol, "big.json", " " * (pol.PLAN_MAX + 1))
    assert "bytes (at most" in _prepare(pol, "replay", "big.json")[0]
    _stage(pol, "bad.json", "{")
    assert "not JSON" in _prepare(pol, "replay", "bad.json")[0]
    _stage(pol, "v2.json", {**PLAN, "v": 2})
    assert "not a v1 plan" in _prepare(pol, "replay", "v2.json")[0]
    long = {**PLAN, "events": [EVENTS[0], {**EVENTS[2], "t": EVENTS[0]["t"] + 1000 * pol.TIMEOUT_S}]}
    _stage(pol, "long.json", long)
    assert "must end within" in _prepare(pol, "replay", "long.json")[0]
    assert all("refused" in e for e in _log(pol))  # nothing refused is logged as run


def test_plans_must_not_be_a_link(pol, tmp_path):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "p.json").write_text(json.dumps(PLAN))
    plans = os.path.join(pol.CHANNEL, "plans")
    os.rmdir(plans)
    os.symlink(elsewhere, plans)
    msg, _ = _prepare(pol, "replay", "p.json")
    assert isinstance(msg, str) and "plans" in msg and (elsewhere / "p.json").exists()


def test_no_replay_while_the_operator_records(pol, monkeypatch):
    _stage(pol, "p.json")
    monkeypatch.setattr(pol.program, "recording", lambda: True)
    msg, _ = _prepare(pol, "replay", "p.json")
    assert "the operator is recording" in msg and "--" not in msg  # nothing for the agent to override it with
    assert os.path.exists(os.path.join(pol.CHANNEL, "plans", "p.json"))  # refused before the plan is taken
    argv, _ = _prepare(pol, "replay", "p.json", "--dry-run")  # sends no input
    assert isinstance(argv, list) and "--while-recording" not in argv
    assert isinstance(_prepare(pol, "status")[0], list)  # status sends no input: never refused for it


def test_the_session_may_allow_a_replay_while_recording(pol, monkeypatch):
    _stage(pol, "p.json")
    monkeypatch.setattr(pol.program, "recording", lambda: True)
    monkeypatch.setattr(pol, "WHILE_RECORDING", True)
    argv, _ = _prepare(pol, "replay", "p.json")
    assert argv[-1] == "--while-recording" and _log(pol)[0]["while_recording"] is True


def test_the_output_stays_bounded(pol, monkeypatch):
    monkeypatch.setattr(pol, "KEEP", 3)
    monkeypatch.setattr(pol, "LOG_MAX", 200)
    old = ["20261020-101741-00000" + str(i) for i in range(4)]
    for rid in old:
        os.makedirs(os.path.join(pol.LOG_ROOT, rid, "x"))
    os.mkdir(os.path.join(pol.LOG_ROOT, "keep-me"))  # not a replay's
    for i in range(3):
        _stage(pol, f"p{i}.json")
        _prepare(pol, "replay", f"p{i}.json")
    kept = sorted(os.listdir(pol.LOG_ROOT))
    replays = [n for n in kept if pol.REPLAY_ID.fullmatch(n)]
    assert len(replays) == 3 and not set(old) & set(replays) and "keep-me" in kept
    assert "log.1.jsonl" in kept and os.path.getsize(os.path.join(pol.LOG_ROOT, "log.jsonl")) <= 2 * 200


def test_an_event_that_cannot_be_logged_does_not_run(pol, monkeypatch):
    _stage(pol, "p.json")
    monkeypatch.setattr(pol, "LOG_ROOT", os.path.join(pol.CHANNEL, "missing"))
    for argv in (("status",), ("replay", "p.json")):
        msg, req = _prepare(pol, *argv)
        assert "event log is unwritable" in msg and not req.fds


# --- the plan format ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize(("change", "match"), [
    ({"v": "1"}, "not a v1 plan"),
    ({"display": [1280]}, "display: want"),
    ({"display": [1280.0, 800]}, "display: want"),
    ({"display": [0, 800]}, "display: want"),
    ({"events": []}, "a list of 1 to"),
    ({"events": [{**EVENTS[0], "type": "key"}]}, "type must be one of"),
    ({"events": [EVENTS[1], EVENTS[0]]}, "never less than the one before"),
    ({"events": [{**EVENTS[0], "t": True}]}, "t must be a number"),
    ({"events": [{**EVENTS[0], "x": 1280}]}, "inside the display 1280x800"),
    ({"events": [{**EVENTS[0], "y": -1}]}, "inside the display"),
    ({"events": [{**EVENTS[0], "x": float("nan")}]}, "inside the display"),
    ({"events": [{**EVENTS[0], "button": 4}]}, "a down needs button 1-3, 8 or 9"),
    ({"events": [{**EVENTS[0], "button": 10}]}, "a down needs button 1-3, 8 or 9"),
    ({"events": [{**EVENTS[3], "button": 1}]}, "a wheel needs button 4-7"),
])
def test_validate_refuses_what_it_cannot_replay(change, match):
    err = _load("browser_event").validate({**PLAN, **change})
    assert err is not None and match in err


def test_a_recording_is_a_plan():
    prog = _load("browser_event")
    assert prog.validate(PLAN) is None
    assert prog.validate({**PLAN, "events": [{"t": 0.5, "type": "move", "x": 1.5, "y": 2}]}) is None
    back = [{**EVENTS[0], "button": 8}, {**EVENTS[2], "button": 8}]  # the recorder logs any button
    assert prog.validate({**PLAN, "events": back}) is None


# --- the replay, on a fake display -------------------------------------------------------------------------------

class FakeScreen:
    def __init__(self, size=(1280, 800), fail_at=None, held=()):
        self.size, self.calls, self.fail_at, self.at, self.down = list(size), [], fail_at, [0, 0], list(held)

    def held(self):
        return self.down

    def pointer(self):
        return list(self.at)

    def move(self, x, y):
        if len(self.calls) == self.fail_at:
            raise RuntimeError("X went away")
        self.at = [int(x), int(y)]
        self.calls.append(("move", int(x), int(y)))

    def button(self, b, press):
        self.calls.append(("press" if press else "release", b))

    def frame(self, path):
        open(path, "xb").close()


def _with_recorder(prog, tmp_path, monkeypatch, recording=False):
    """browser_event's recorder module (its wall(), png() and claim), on a fake /tmp/capture."""
    monkeypatch.setattr(prog, "RECORDER", str(IMAGE / "glove-pw-capture"))
    rec = prog._recorder()
    root = tmp_path / "capture"
    for name, path in (("ROOT", root), ("LOCK", root / ".lock"), ("REPLAY", root / ".replay"),
                       ("CURRENT", root / ".current")):
        monkeypatch.setattr(rec, name, path)
    monkeypatch.setattr(rec, "running", lambda: ("20261020-101741-0a1b2c", 1) if recording else None)
    return rec


def _replay(tmp_path, monkeypatch, screen, plan=PLAN, dry_run=False, recording=False, while_recording=False):
    prog = _load("browser_event")
    rec = _with_recorder(prog, tmp_path, monkeypatch, recording)
    monkeypatch.setattr(prog, "Screen", screen if callable(screen) else lambda _name: screen)
    monkeypatch.setattr(prog.time, "sleep", lambda _s: None)
    out = tmp_path / "out"
    out.mkdir(parents=True)
    rc = prog.replay(plan, ":1", str(out), dry_run, while_recording)
    assert not rec.REPLAY.exists()  # the claim ends with the replay
    return rc, json.loads((out / "result.json").read_text())


def test_replay_sends_the_events_in_order(tmp_path, monkeypatch):
    screen = FakeScreen()
    rc, result = _replay(tmp_path, monkeypatch, screen)
    assert rc == 0 and result["status"] == "ok" and result["synthetic"] is True
    assert screen.calls == [("move", 300, 400), ("press", 1), ("move", 320, 401), ("move", 700, 420),
                            ("release", 1), ("move", 700, 420), ("press", 5), ("release", 5)]
    assert result["sent"] == 4 and result["released"] == [] and result["end_error_px"] == 0
    assert result["duration_ms"] == 963
    assert sorted(p.name for p in (tmp_path / "out").iterdir()) == ["after.png", "before.png", "result.json"]


def test_back_and_forward_buttons_replay(tmp_path, monkeypatch):
    screen = FakeScreen()
    plan = {**PLAN, "events": [{**EVENTS[0], "button": 9}, {**EVENTS[2], "button": 9}]}
    rc, _ = _replay(tmp_path, monkeypatch, screen, plan)
    assert rc == 0 and ("press", 9) in screen.calls and screen.calls[-1] == ("release", 9)


def test_no_input_while_a_recorder_runs(tmp_path, monkeypatch):
    screen = FakeScreen()
    rc, result = _replay(tmp_path, monkeypatch, screen, recording=True)
    assert rc == 2 and result["status"] == "refused" and "the operator is recording" in result["error"]
    assert screen.calls == []
    rc, result = _replay(tmp_path / "again", monkeypatch, FakeScreen(), recording=True, while_recording=True)
    assert rc == 0 and result["status"] == "ok"  # the session allowed it


def test_a_recorder_does_not_arm_while_a_replay_sends_input(tmp_path, monkeypatch):
    prog = _load("browser_event")
    rec = _with_recorder(prog, tmp_path, monkeypatch)
    assert rec.claim_replay(False) and int(rec.REPLAY.read_text()) == os.getpid()
    monkeypatch.setattr(rec, "replaying", lambda: os.getpid())
    monkeypatch.setattr(rec, "OVERLAP_OK", False)
    monkeypatch.setattr(rec.subprocess, "Popen", lambda *a, **k: pytest.fail("armed"))
    assert rec.start(SimpleNamespace(max_seconds=60, motion_hz=60, glove_version="")) == 1
    rec.release_replay()
    assert not rec.REPLAY.exists()


@pytest.mark.parametrize("where", ["display", "frame"])
def test_a_failing_display_still_leaves_a_result(tmp_path, monkeypatch, where):
    def no_display(_name):
        raise ConnectionError("Can't connect to display :1")

    screen = FakeScreen()
    if where == "frame":
        screen.frame = lambda _path: (_ for _ in ()).throw(OSError("get_image failed"))
    rc, result = _replay(tmp_path, monkeypatch, no_display if where == "display" else screen)
    assert rc == 2 and result["status"] == "error"
    assert ("Can't connect" if where == "display" else "get_image failed") in result["error"]


def test_a_button_an_aborted_replay_left_held_is_released_first(tmp_path, monkeypatch):
    screen = FakeScreen(held=[1])
    rc, result = _replay(tmp_path, monkeypatch, screen)
    assert rc == 0 and result["released_first"] == [1] and screen.calls[0] == ("release", 1)


def test_recording_means_a_live_recorder(tmp_path, monkeypatch):
    prog = _load("browser_event")
    monkeypatch.setattr(prog, "RECORDER", str(IMAGE / "glove-pw-capture"))
    rec = prog._recorder()
    monkeypatch.setattr(rec, "CURRENT", tmp_path / ".current")
    assert prog.recording() is False
    (tmp_path / ".current").write_text("20261020-101741-0a1b2c 999999\n")  # a recorder long gone
    assert prog.recording() is False


def test_a_held_button_is_released_when_replay_fails(tmp_path, monkeypatch):
    screen = FakeScreen(fail_at=2)  # after the press, before the release
    rc, result = _replay(tmp_path, monkeypatch, screen)
    assert rc == 2 and result["status"] == "error" and "X went away" in result["error"]
    assert screen.calls[-1] == ("release", 1) and result["released"] == [1]


def test_a_replay_for_another_display_size_sends_nothing(tmp_path, monkeypatch):
    screen = FakeScreen(size=(1920, 1080))
    rc, result = _replay(tmp_path, monkeypatch, screen)
    assert rc == 2 and result["status"] == "refused" and "made for 1280x800" in result["error"]
    assert screen.calls == []


def test_dry_run_sends_nothing(tmp_path, monkeypatch):
    screen = FakeScreen()
    rc, result = _replay(tmp_path, monkeypatch, screen, dry_run=True)
    assert rc == 0 and result["status"] == "dry-run" and screen.calls == []


# --- the session -------------------------------------------------------------------------------------------------

def test_the_vendored_relayd_is_the_relay_extensions(tmp_path):
    # a sidecar binds only its own extension's assets and the pw image can't build FROM relay's content-hashed
    # image, so it carries a copy: it must stay the same file
    assert (IMAGE / "relayd.py").read_bytes() == (IN_TREE_DIR / "relay" / "image" / "relayd.py").read_bytes()

def _session(tmp_path, **settings):
    work = tmp_path / "work"
    work.mkdir(parents=True, exist_ok=True)
    cfg = make_cfg(harness="pi", name="s", workdir=str(work), subnet="172.31.4.0/24",
                   extensions={"direct": {}, "playwright": {"mode": "novnc", **settings}})
    plan, text = render(cfg, tmp_path, session_dir=str(tmp_path))
    return plan, yaml.safe_load(text)


def test_event_relay_adds_the_channel_the_log_and_the_command(tmp_path):
    plan, doc = _session(tmp_path, event_relay=True, event_timeout=30)
    comp = plan.composition
    assert [(c.name, c.services) for c in comp.channels] == [("browser-event", ("pw",))]
    assert [o.name for o in comp.outputs] == ["browser-events"]
    assert "relay" in [a.name for a in comp.active]
    copies = [c for ext, layer in comp.image_layers if ext == "playwright" for c in layer.get("copy") or []]
    assert ["shim/browser-event", "/usr/local/bin/browser-event"] in copies
    env = doc["services"]["glove-s-pw"]["environment"]
    assert env["PW_EVENT_RELAY"] == "true" and env["PW_EVENT_TIMEOUT"] == "30"
    assert env["PW_REPLAY_WHILE_RECORDING"] == "false"
    brief = dict(comp.rendered_briefs())["playwright"]
    assert "browser-event replay" in brief and "/run/glove/browser-event/plans/" in brief


def test_off_by_default(tmp_path):
    plan, doc = _session(tmp_path)
    comp = plan.composition
    assert not comp.channels and not comp.outputs and "relay" not in [a.name for a in comp.active]
    assert "PW_EVENT_RELAY" not in doc["services"]["glove-s-pw"]["environment"]
    assert "browser-event" not in dict(comp.rendered_briefs())["playwright"]


def test_event_relay_needs_novnc(tmp_path):
    with pytest.raises(ExtensionError, match="event_relay applies to mode: novnc only"):
        _session(tmp_path, mode="headless", event_relay=True)


@pytest.mark.parametrize("timeout", [0, 29, 3601])
def test_event_timeout_is_bounded(tmp_path, timeout):
    with pytest.raises(Exception, match="event_timeout: an integer from 30 to 3600"):
        _session(tmp_path, event_relay=True, event_timeout=timeout)
