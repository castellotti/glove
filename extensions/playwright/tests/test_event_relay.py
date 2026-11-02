"""`playwright: {event_relay: true}`: the agent sends events to the browser
sidecar (`browser-event status|recordings|replay`) over the `browser-event` relay channel.
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
CID = "20261020-101741-0a1b2c"


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
    (tmp_path / "saved").mkdir()
    monkeypatch.setattr(pol, "CHANNEL", str(tmp_path / "chan"))
    monkeypatch.setattr(pol.program, "RECORDER", str(IMAGE / "glove-pw-capture"))
    monkeypatch.setattr(pol.program._recorder(), "SAVED", tmp_path / "saved")
    monkeypatch.setattr(pol, "LOG_ROOT", str(tmp_path / "log"))
    monkeypatch.setattr(pol.program, "recording", lambda: False)
    yield pol


def _stage(pol, name: str, plan=PLAN) -> str:
    path = os.path.join(pol.CHANNEL, "plans", name)
    with open(path, "w") as f:
        f.write(plan if isinstance(plan, str) else json.dumps(plan))
    return path


def _save(pol, cid=CID, events=EVENTS, meta=None) -> Path:
    """A recording `record` saved: what glove-pw-capture `saved` leaves in SAVED/<cid>/."""
    d = pol.program._recorder().SAVED / cid
    d.mkdir()
    (d / "events.jsonl").write_text("".join(json.dumps(e) + "\n" for e in events))
    if meta is not False:
        (d / "meta.json").write_text(json.dumps(meta or {"capture": 1, "display": [1280, 800], "duration_ms": 3000}))
    return d


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
    (("recordings", "all"), "recordings takes no arguments"),
    (("replay",), "one plan name"),
    (("replay", "p.json", "--recording", CID), "one plan name, or --recording"),
    (("replay", "--recording", CID, "--recording", CID), "unexpected --recording"),
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
    long = {**PLAN, "events": [EVENTS[0], {**EVENTS[2], "t": EVENTS[0]["t"] + 1000 * pol.program.TIMEOUT_S}]}
    _stage(pol, "long.json", long)
    assert "must end within" in _prepare(pol, "replay", "long.json")[0]
    _stage(pol, "deep.json", "[" * 100_000 + "]" * 100_000)
    assert "not JSON" in _prepare(pol, "replay", "deep.json")[0]  # RecursionError, refused
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
    monkeypatch.setattr(pol, "KEEP", 3)  # `event_keep`
    monkeypatch.setattr(pol, "LOG_MAX", 200)
    old = ["20261020-101741-00000" + str(i) for i in range(4)]
    for rid in old:
        os.makedirs(os.path.join(pol.LOG_ROOT, rid, "x"))
    os.mkdir(os.path.join(pol.LOG_ROOT, "keep-me"))  # not a replay's
    for i in range(3):
        _stage(pol, f"p{i}.json")
        _prepare(pol, "replay", f"p{i}.json")
    kept = sorted(os.listdir(pol.LOG_ROOT))
    replays = [n for n in kept if pol.program._recorder().ID.fullmatch(n)]
    assert len(replays) == 3 and not set(old) & set(replays) and "keep-me" in kept
    assert "log.1.jsonl" in kept and os.path.getsize(os.path.join(pol.LOG_ROOT, "log.jsonl")) <= 2 * 200


def test_event_keep_reaches_the_policy(monkeypatch):
    monkeypatch.setenv("PW_EVENT_KEEP", "200")
    assert _load("relay_policy").KEEP == 200
    monkeypatch.delenv("PW_EVENT_KEEP")
    assert _load("relay_policy").KEEP == 20


@pytest.mark.parametrize(("value", "want"), [("0", 5), ("1", 5), ("99999", 1000), ("lots", 20)])
def test_event_keep_is_bounded_in_the_policy_too(monkeypatch, value, want):
    monkeypatch.setenv("PW_EVENT_KEEP", value)  # an image run by hand: never prune every replay, never fail
    assert want == _load("relay_policy").KEEP


def test_the_recorder_and_the_host_agree_on_ids():
    from glove_ext.playwright import capture

    prog = _load("browser_event")
    prog.RECORDER = str(IMAGE / "glove-pw-capture")
    # a capture's id (the policy's replays look the same): `record` (on the host) checks it too
    assert prog._recorder().ID.pattern == capture.ID.pattern.removeprefix("^")


def test_recordings_lists_them_and_is_logged(pol):
    argv, _ = _prepare(pol, "recordings")
    assert argv == ["/usr/bin/python3", pol.PROGRAM, "recordings"] and _log(pol)[0]["event"] == "recordings"


@pytest.mark.parametrize("dry_run", [False, True])
def test_a_saved_recording_replays_by_id(pol, dry_run):
    _save(pol)
    argv, _ = _prepare(pol, "replay", "--recording", CID, *(["--dry-run"] if dry_run else []))
    out = argv[argv.index("--out") + 1]
    assert argv[3] == os.path.join(out, "plan.json") and argv[argv.index("--id") + 1] == os.path.basename(out)
    raw = Path(out, "plan.json").read_bytes()
    rows = [{k: e[k] for k in ("t", "type", "x", "y", "button")} for e in EVENTS]
    assert json.loads(raw) == {**PLAN, "events": rows}  # meta.json's display, events.jsonl's rows cut to ROW
    assert ("--dry-run" in argv) is dry_run
    assert (pol.program._recorder().SAVED / CID / "events.jsonl").exists()  # a recording replays as often as asked
    (entry,) = _log(pol)
    assert entry["recording"] == CID and "plan" not in entry and entry["events"] == 4
    assert entry["plan_sha256"] == hashlib.sha256(raw).hexdigest() and entry["dry_run"] is dry_run


def test_a_recording_is_refused_unless_saved_whole_and_small(pol, tmp_path):
    msgs = {}
    msgs["id"] = _prepare(pol, "replay", "--recording", "../" + CID)[0]
    msgs["none"] = _prepare(pol, "replay", "--recording", CID)[0]
    msgs["no value"] = _prepare(pol, "replay", "--recording")[0]
    _save(pol, "20261020-101741-000001", meta=False)  # still recording: meta.json is written last
    msgs["unfinished"] = _prepare(pol, "replay", "--recording", "20261020-101741-000001")[0]
    big = _save(pol, "20261020-101741-000002")
    (big / "events.jsonl").write_text(" " * (pol.PLAN_MAX + 1))
    msgs["big"] = _prepare(pol, "replay", "--recording", "20261020-101741-000002")[0]
    os.symlink(_save(pol, "20261020-101741-000003"), pol.program._recorder().SAVED / "20261020-101741-000004")
    msgs["dir link"] = _prepare(pol, "replay", "--recording", "20261020-101741-000004")[0]
    files = _save(pol, "20261020-101741-000005", meta=False)
    os.symlink(big / "meta.json", files / "meta.json")
    msgs["file link"] = _prepare(pol, "replay", "--recording", "20261020-101741-000005")[0]
    bad = _save(pol, "20261020-101741-000006")
    (bad / "events.jsonl").write_text("{\n")
    msgs["not json"] = _prepare(pol, "replay", "--recording", "20261020-101741-000006")[0]
    _save(pol, "20261020-101741-000007", meta={"display": [200, 200]})
    msgs["invalid"] = _prepare(pol, "replay", "--recording", "20261020-101741-000007")[0]
    assert "want a recording's id" in msgs["id"] and "want a recording's id" in msgs["no value"]
    assert "No such file" in msgs["none"] and "recordings` lists" in msgs["none"]
    assert "meta.json (not finished?)" in msgs["unfinished"]
    assert "events.jsonl" in msgs["big"] and "bytes (at most" in msgs["big"]
    assert "20261020-101741-000004" in msgs["dir link"] and "meta.json" in msgs["file link"]  # O_NOFOLLOW
    assert "not JSON" in msgs["not json"] and "inside the display 200x200" in msgs["invalid"]
    log = _log(pol)
    assert len(log) == len(msgs) and all("refused" in e for e in log)
    assert not [n for n in os.listdir(pol.LOG_ROOT) if pol.program._recorder().ID.fullmatch(n)]  # nothing ran


def test_no_saved_recordings_at_all(pol):
    os.rmdir(pol.program._recorder().SAVED)
    assert "no saved recordings" in _prepare(pol, "replay", "--recording", CID)[0]


def test_a_recording_too_long_for_the_timeout_is_refused(pol):
    _save(pol, events=[EVENTS[0], {**EVENTS[2], "t": EVENTS[0]["t"] + 1000 * pol.program.TIMEOUT_S}])
    msg, _ = _prepare(pol, "replay", "--recording", CID)
    assert msg.startswith(f"recording {CID} lasts") and "copy its rows from browser-output/" in msg


def test_a_deeply_nested_recording_is_refused(pol):
    d = _save(pol)
    (d / "events.jsonl").write_text("[" * 100_000 + "]" * 100_000 + "\n")
    assert "nested too deeply" in _prepare(pol, "replay", "--recording", CID)[0]


def test_no_recording_replays_while_the_operator_records(pol, monkeypatch):
    _save(pol)
    monkeypatch.setattr(pol.program, "recording", lambda: True)
    assert "the operator is recording" in _prepare(pol, "replay", "--recording", CID)[0]
    assert isinstance(_prepare(pol, "replay", "--recording", CID, "--dry-run")[0], list)


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
    monkeypatch.setattr(rec, "EVENTS_PROGRAM", str(IMAGE / "browser_event.py"))
    root = tmp_path / "capture"
    for name, path in (("ROOT", root), ("LOCK", root / ".lock"), ("REPLAY", root / ".replay"),
                       ("CURRENT", root / ".current"), ("SAVED", root / ".saved")):
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
    rc = prog.replay(plan, ":1", str(out), "20261101-090000-abcdef", dry_run, while_recording)
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
    seen = "/work/browser-events/20261101-090000-abcdef"  # the result names itself, as the agent sees it
    assert result["id"] == "20261101-090000-abcdef" and result["dir"] == seen
    assert result["frames"] == {"before": f"{seen}/before.png", "after": f"{seen}/after.png"}


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
    assert result["id"] == "20261101-090000-abcdef" and result["frames"] == {}  # only frames that were written


def test_only_the_frames_written_are_named(tmp_path, monkeypatch):
    screen = FakeScreen(fail_at=2)
    rc, result = _replay(tmp_path, monkeypatch, screen)
    assert rc == 2 and list(result["frames"]) == ["before", "after"]
    screen = FakeScreen()
    screen.frame = lambda path: (_ for _ in ()).throw(OSError("get_image failed")) if "after" in path else \
        open(path, "xb").close()
    rc, result = _replay(tmp_path / "again", monkeypatch, screen)
    assert rc == 2 and list(result["frames"]) == ["before"]


def test_recordings_lists_the_saved_ones(tmp_path, monkeypatch, capsys):
    prog = _load("browser_event")
    rec = _with_recorder(prog, tmp_path, monkeypatch)
    assert prog.recordings() == 0 and json.loads(capsys.readouterr().out) == {"recordings": []}
    for name in ("20261020-101741-000002", "20261020-101741-000001", "notes", ".x"):
        (rec.SAVED / name).mkdir(parents=True)
    (rec.SAVED / "20261020-101741-000003").write_text("")  # neither a file nor a link is a recording
    (rec.SAVED / "20261020-101741-000004").symlink_to(rec.SAVED / "20261020-101741-000001")
    prog.recordings()
    assert json.loads(capsys.readouterr().out)["recordings"] == ["20261020-101741-000001", "20261020-101741-000002"]


# --- what the recorder keeps once `record` has saved a capture -------------------------------------------------

def _capture(rec, cid, events=EVENTS):
    d = rec.ROOT / cid
    (d / "shots").mkdir(parents=True)
    (d / "shots" / "1-arm.png").write_bytes(b"png")
    (d / "events.jsonl").write_text(events if isinstance(events, str) else
                                    "".join(json.dumps(e) + "\n" for e in events))
    (d / "windows.jsonl").write_text("{}\n")
    (d / "meta.json").write_text(json.dumps({"display": PLAN["display"]}))
    (rec.ROOT / f".{cid}.log").write_text("")
    return d


def test_saved_keeps_what_a_replay_needs(tmp_path, monkeypatch, capsys):
    prog = _load("browser_event")
    rec = _with_recorder(prog, tmp_path, monkeypatch)
    _capture(rec, CID)
    assert rec.saved(CID) == 0
    assert capsys.readouterr().out.startswith(f"kept for `browser-event replay --recording {CID}`")
    assert sorted(os.listdir(rec.ROOT)) == [".saved"]  # the capture and its log are gone
    assert sorted(p.name for p in (rec.SAVED / CID).iterdir()) == ["events.jsonl", "meta.json"]
    assert rec.saved("../x") == 1


def test_saved_keeps_nothing_a_replay_would_refuse(tmp_path, monkeypatch, capsys):
    prog = _load("browser_event")
    rec = _with_recorder(prog, tmp_path, monkeypatch)
    too_long = [EVENTS[0], {**EVENTS[2], "t": EVENTS[0]["t"] + 1000 * prog.TIMEOUT_S}]
    whys = []
    for i, (events, why) in enumerate([("x" * (rec.SAVED_MAX + 1), "bytes (at most"),
                                       ("", "events: want a list of 1 to"),
                                       ([EVENTS[0]] * (prog.MAX_EVENTS + 1), "events: want a list of 1 to"),
                                       (too_long, "must end within"), ("{\n", "not JSON"),
                                       (EVENTS, "unfinished (no meta.json)")]):
        cid = f"20261020-101741-00000{i}"
        d = _capture(rec, cid, events)
        if why.startswith("unfinished"):
            (d / "meta.json").unlink()
        assert rec.saved(cid) == 0
        whys.append((why, capsys.readouterr().out))
    assert all(out.startswith("not kept for replay: ") and why in out for why, out in whys), whys
    assert os.listdir(rec.ROOT) == []


def test_saved_never_keeps_half_a_recording(tmp_path, monkeypatch):
    prog = _load("browser_event")
    rec = _with_recorder(prog, tmp_path, monkeypatch)
    _capture(rec, CID)
    real = os.replace

    def full(src, dst):
        if str(src).endswith("meta.json"):
            raise OSError(28, "No space left on device")
        real(src, dst)

    monkeypatch.setattr(rec.os, "replace", full)
    assert rec.saved(CID) == 0
    assert not (rec.SAVED / CID).exists() and not (rec.ROOT / CID).exists()


def test_saved_never_removes_a_copy_it_did_not_make(tmp_path, monkeypatch, capsys):
    prog = _load("browser_event")
    rec = _with_recorder(prog, tmp_path, monkeypatch)
    _capture(rec, CID)
    (rec.SAVED / CID).mkdir(parents=True)  # another `record` of the same capture kept it first
    (rec.SAVED / CID / "events.jsonl").write_text("theirs")
    assert rec.saved(CID) == 0 and "not kept for replay" in capsys.readouterr().out
    assert (rec.SAVED / CID / "events.jsonl").read_text() == "theirs"


def test_saved_keeps_the_newest(tmp_path, monkeypatch):
    prog = _load("browser_event")
    rec = _with_recorder(prog, tmp_path, monkeypatch)
    monkeypatch.setattr(rec, "SAVED_KEEP", 2)
    for i in range(4):
        _capture(rec, f"20261020-101741-00000{i}")
        rec.saved(f"20261020-101741-00000{i}")
    assert sorted(p.name for p in rec.SAVED.iterdir()) == ["20261020-101741-000002", "20261020-101741-000003"]


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
    assert env["PW_EVENT_RELAY"] == "true" and env["PW_EVENT_TIMEOUT"] == "30" and env["PW_EVENT_KEEP"] == "20"
    assert env["PW_REPLAY_WHILE_RECORDING"] == "false"
    brief = dict(comp.rendered_briefs())["playwright"]
    assert "browser-event replay" in brief and "/run/glove/browser-event/plans/" in brief
    assert "--recording <id>" in brief


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


def test_event_keep_is_the_sessions(tmp_path):
    _, doc = _session(tmp_path, event_relay=True, event_keep=200)
    assert doc["services"]["glove-s-pw"]["environment"]["PW_EVENT_KEEP"] == "200"


@pytest.mark.parametrize("keep", [0, 4, 1001, 5000])
def test_event_keep_is_bounded(tmp_path, keep):
    with pytest.raises(Exception, match="event_keep: an integer from 5 to 1000"):
        _session(tmp_path, event_relay=True, event_keep=keep)
