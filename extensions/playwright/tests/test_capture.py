"""`playwright: {recording: …}` and `glove playwright record`'s host side:
the setting's refusals, the brief, and a capture copied out of the (hostile)
sidecar: checked, then written without following links."""

from __future__ import annotations

import importlib
import io
import json
import os
import stat
import tarfile

import pytest
from helpers import make_cfg

from glove.extensions import IN_TREE_DIR, ExtensionError, load_module
from glove.plan import build_session_plan

PW = IN_TREE_DIR / "playwright"
load_module(PW / "hooks.py", "playwright")
capture = importlib.import_module("glove_ext.playwright.capture")

CID = "20261020-101741-0a1b2c"
NOVNC = {"mode": "novnc", "allow_control": True}
PNG = b"\x89PNG\r\n\x1a\n" + b"\0" * 32
EVENTS = [
    {"t": 1437, "xt": 20567499, "wall": "2026-10-20T10:17:42.895Z", "type": "down", "button": 1,
     "x": 300, "y": 400, "mask": 256},
    {"t": 1538, "xt": 20567600, "wall": "2026-10-20T10:17:42.996Z", "type": "move", "button": 0,
     "x": 320, "y": 401, "mask": 256},
    {"t": 1971, "xt": 20568034, "wall": "2026-10-20T10:17:43.430Z", "type": "up", "button": 1,
     "x": 700, "y": 420, "mask": 0},
]
WINDOWS = [{"t": 0, "wall": "2026-10-20T10:17:41.459Z", "reason": "arm", "display": [1280, 800],
            "windows": [{"id": 7, "title": "Example page", "x": 0, "y": 0, "w": 1279, "h": 799}]},
           {"t": 1334, "wall": "2026-10-20T10:17:42.792Z", "reason": "change", "display": [1280, 800],
            "windows": [{"id": 7, "title": "Results\x1b]0;pwned\x07", "x": 0, "y": 0, "w": 1279, "h": 799}]}]
META = {"capture": 1, "glove_version": "3.0.0", "display": [1280, 800], "viewport": "1280x800",
        "armed": "2026-10-20T10:17:41.458Z", "stopped": "viewer-closed", "stopped_at": "2026-10-20T10:17:48.235Z",
        "duration_ms": 6777, "events": 3, "shots": 4, "dropped_shots": 0,
        "shot_ms": {"min": 2.0, "median": 3.7, "max": 5.2}}


def _plan(tmp_path, **settings):
    work = tmp_path / "work"
    work.mkdir(parents=True, exist_ok=True)
    cfg = make_cfg(harness="pi", name="s", workdir=str(work), subnet="172.31.4.0/24",
                   extensions={"direct": {}, "playwright": settings})
    return build_session_plan(cfg, home_dir=str(tmp_path / "h"), state_dir=str(tmp_path / "ext"))


def _brief(plan) -> str:
    return dict(plan.composition.rendered_briefs())["playwright"]


def _jsonl(rows) -> bytes:
    return "".join(json.dumps(r) + "\n" for r in rows).encode()


def _tar(files: dict[str, bytes], extra=()) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for d in (CID, f"{CID}/shots"):
            info = tarfile.TarInfo(d)
            info.type = tarfile.DIRTYPE
            t.addfile(info)
        for name, body in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(body)
            t.addfile(info, io.BytesIO(body))
        for info in extra:
            t.addfile(info)
    return buf.getvalue()


def _good() -> dict[str, bytes]:
    return {f"{CID}/events.jsonl": _jsonl(EVENTS), f"{CID}/windows.jsonl": _jsonl(WINDOWS),
            f"{CID}/meta.json": json.dumps(META).encode(), f"{CID}/shots/0001-arm.png": PNG,
            f"{CID}/shots/0002-down.png": PNG}


# --- the setting -------------------------------------------------------------------------------------------------

def test_off_by_default_and_defaults_when_on(tmp_path):
    plan = _plan(tmp_path, **NOVNC)
    assert "glove playwright record" not in _brief(plan)
    assert capture.spec({**NOVNC, "downloads": "session"}) is None
    assert capture.spec({**NOVNC, "downloads": "session", "recording": {}}) == \
        {"to": "session", "max_seconds": 600, "motion_hz": 120}


def test_the_brief_says_hand_off_and_stay_out(tmp_path):
    brief = _brief(_plan(tmp_path, **NOVNC, recording={}))
    assert "ask them to run `glove playwright record`" in brief
    assert "Don't use the browser until they tell you they are done." in brief
    assert "recordings" not in brief  # nothing about where the recording goes


@pytest.mark.parametrize(("settings", "match"), [
    ({"mode": "novnc"}, "needs mode: novnc and allow_control: true"),
    ({"mode": "headless"}, "needs mode: novnc and allow_control: true"),
    ({**NOVNC, "recording": {"to": "work"}}, "needs downloads: work"),
    ({**NOVNC, "recording": {"to": "disk"}}, "session or work"),
    ({**NOVNC, "recording": {"max_seconds": 5}}, "max_seconds: an integer from 10 to 3600"),
    ({**NOVNC, "recording": {"motion_hz": True}}, "motion_hz: an integer"),
    ({**NOVNC, "recording": {"keys": True}}, "unknown key"),
])
def test_refusals_at_plan_time(tmp_path, settings, match):
    settings = {"recording": {}, **settings}
    with pytest.raises(ExtensionError, match=match):
        _plan(tmp_path, **settings)


def test_to_work_with_downloads_work():
    assert capture.spec({**NOVNC, "downloads": "work", "recording": {"to": "work"}})["to"] == "work"


# --- the capture's checks ----------------------------------------------------------------------------------------

def test_a_good_capture_passes_rewritten_from_parsed_values():
    cap = capture.read_tar(_tar(_good()), CID)
    assert cap.dropped == 0
    assert sorted(cap.files) == ["events.jsonl", "meta.json", "shots/0001-arm.png", "shots/0002-down.png",
                                 "windows.jsonl"]
    assert cap.events == EVENTS and cap.meta == META
    assert [json.loads(line) for line in cap.files["events.jsonl"].splitlines()] == EVENTS


def test_hostile_names_and_kinds_are_dropped():
    files = {**_good(),
             f"{CID}/../escape.json": b"{}", f"/{CID}/abs.json": b"{}", f"{CID}/.hidden.json": b"{}",
             f"{CID}/Upper.json": b"{}", f"{CID}/a/b/c.png": PNG, f"{CID}/shots/0003-up.json": b"{}",
             f"{CID}/notes.txt": b"x", "other/meta.json": b"{}", f"{CID}/shots/0004-up.png": b"GIF89a",
             f"{CID}/unknown.json": b"{}"}
    link = tarfile.TarInfo(f"{CID}/link.json")
    link.type, link.linkname = tarfile.SYMTYPE, "/etc/passwd"
    hard = tarfile.TarInfo(f"{CID}/hard.json")
    hard.type, hard.linkname = tarfile.LNKTYPE, f"{CID}/meta.json"
    cap = capture.read_tar(_tar(files, (link, hard)), CID)
    assert sorted(cap.files) == ["events.jsonl", "meta.json", "shots/0001-arm.png", "shots/0002-down.png",
                                 "windows.jsonl"]
    assert cap.dropped == 12


def test_oversized_and_too_many_shots_are_dropped(monkeypatch):
    monkeypatch.setattr(capture, "MAX_SHOTS", 1)
    files = {**_good(), f"{CID}/windows.jsonl": b"x" * (capture.MAX_FILE["jsonl"] + 1)}
    cap = capture.read_tar(_tar(files), CID)
    assert "windows.jsonl" not in cap.files and "shots/0002-down.png" not in cap.files and cap.dropped == 2


def test_bad_json_lines_and_extra_keys_are_dropped_line_by_line():
    bad_rows = [{**EVENTS[0], "key": "a"},  # a key it never records
                {**EVENTS[0], "x": -1}, {**EVENTS[0], "type": "click"}, {**EVENTS[0], "t": True},
                {**EVENTS[0], "wall": "yesterday"}]
    files = {**_good(), f"{CID}/events.jsonl": _jsonl(EVENTS) + b"not json\n" + _jsonl(bad_rows),
             f"{CID}/meta.json": json.dumps({**META, "evil": "x", "duration_ms": "long"}).encode()}
    cap = capture.read_tar(_tar(files), CID)
    assert cap.events == EVENTS and cap.dropped == 6
    assert "evil" not in cap.meta and "duration_ms" not in cap.meta and cap.meta["stopped"] == "viewer-closed"
    meta = _good()
    meta[f"{CID}/meta.json"] = json.dumps({**META, "stopped": "hacked"}).encode()
    cap = capture.read_tar(_tar(meta), CID)
    assert "meta.json" not in cap.files and cap.dropped == 1


@pytest.mark.parametrize(("pattern", "ok"), [(capture.ID, CID), (capture.NAME, "0001-arm.png"),
                                             (capture.WALL, "2026-10-20T10:17:42.895Z")])
def test_a_trailing_newline_is_refused(pattern, ok):
    assert pattern.match(ok) and not pattern.match(ok + "\n")
    assert not capture.WALL.match("2026-10-20T10:17:42x895Z")


def test_deeply_nested_json_is_dropped_not_a_crash():
    deep = b"[" * 100_000 + b"]" * 100_000
    files = {**_good(), f"{CID}/meta.json": deep, f"{CID}/events.jsonl": _jsonl(EVENTS) + deep + b"\n"}
    cap = capture.read_tar(_tar(files), CID)
    assert cap.events == EVENTS and "meta.json" not in cap.files and cap.dropped == 2


def test_doctor_reports_a_bad_setting():
    hooks = load_module(PW / "hooks.py", "playwright")
    ctx = type("Ctx", (), {"settings": {**NOVNC, "mode": "headless", "downloads": "session", "login": None,
                                        "recording": {}}})()
    assert hooks.doctor(ctx, None)[0][:2] == ("playwright recording", "fail")


def test_not_a_tar_or_a_bad_id_is_refused():
    with pytest.raises(ValueError, match="not a readable tar"):
        capture.read_tar(b"\x00garbage" * 200, CID)
    with pytest.raises(ValueError, match="not a capture id"):
        capture.read_tar(_tar(_good()), "../x")


# --- writing -------------------------------------------------------------------------------------------------------

def test_written_private_and_to_work(tmp_path):
    cap = capture.read_tar(_tar(_good()), CID)
    host = capture.write(tmp_path, cap, private=True)
    assert (host / "shots" / "0002-down.png").read_bytes() == PNG
    assert stat.S_IMODE(host.stat().st_mode) == 0o700 and stat.S_IMODE((host / "meta.json").stat().st_mode) == 0o600
    out = tmp_path / "browser-output"
    out.mkdir()
    work = capture.write(out, cap, private=False)
    assert stat.S_IMODE((work / "events.jsonl").stat().st_mode) == 0o644
    with pytest.raises(FileExistsError):  # never an overwrite
        capture.write(out, cap, private=False)


def test_a_planted_link_is_refused_not_followed(tmp_path):
    cap = capture.read_tar(_tar(_good()), CID)
    out, elsewhere = tmp_path / "browser-output", tmp_path / "elsewhere"
    out.mkdir()
    elsewhere.mkdir()
    os.symlink(elsewhere, out / "recordings")
    with pytest.raises(OSError):
        capture.write(out, cap, private=False)
    os.symlink(elsewhere, tmp_path / "linked-base")
    with pytest.raises(OSError):
        capture.write(tmp_path / "linked-base", cap, private=False)
    assert list(elsewhere.iterdir()) == []


# --- what the operator sees ----------------------------------------------------------------------------------------

def test_summary_and_titles_are_printable():
    cap = capture.read_tar(_tar(_good()), CID)
    text = capture.summary(cap)
    assert "1 press(es)" in text and "drags 400 px in 534 ms" in text and "stopped: viewer-closed" in text
    assert "\x1b" not in text and "\x07" not in text and "Results]0;pwned" in text
    assert capture.front_title(WINDOWS[0]) == "Example page"
