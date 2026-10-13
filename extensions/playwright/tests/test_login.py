"""`glove playwright login` and `storage_state`: the login settings, what the
login browser's state is filtered to, the captures, the CDP pipe, the sidecar
seeding and the refusals."""

from __future__ import annotations

import base64
import gzip
import json
import sys
import time

import pytest
import typer
import yaml
from helpers import plan_pw, pw_service

from glove.extensions import IN_TREE_DIR, ExtensionError, launch_env, load_module

PW = IN_TREE_DIR / "playwright"
cli = load_module(PW / "cli.py", "playwright")
hooks = cli._hooks()  # the instances the CLI uses, so patching them reaches it
lg = hooks.host_module("login")
cdp = hooks.host_module("cdp")

LOGIN = {"start_url": "https://wiki.corp.example/", "domains": ["*.corp.example", "corp.example", "idp.example"],
         "capture": {"chat-d": {"cookie": {"domain": "chat.example", "name": "d"}},
                     "chat-xoxc": {"storage": {"origin": "https://app.chat.example", "key": "cfg",
                                               "match": "xoxc-[a-z0-9-]+"}}}}
COOKIES = [
    {"name": "sso", "value": "S1", "domain": ".corp.example", "path": "/", "expires": 2_000_000_000,
     "httpOnly": True, "secure": True, "session": False, "sameSite": "None"},
    {"name": "wiki", "value": "W1", "domain": "wiki.corp.example", "path": "/", "expires": -1,
     "httpOnly": False, "secure": True, "session": True},
    {"name": "ads", "value": "A1", "domain": ".tracker.example", "path": "/", "expires": 1_900_000_000,
     "session": False},
    {"name": "part", "value": "P1", "domain": "wiki.corp.example", "path": "/", "session": True,
     "partitionKey": {"topLevelSite": "https://x.example"}},
    {"name": "d", "value": "xoxd-123", "domain": ".chat.example", "path": "/", "session": False,
     "expires": 1_950_000_000},
]
STORAGE = {"https://wiki.corp.example": {"k": "v"}, "https://app.chat.example": {"cfg": '{"t":"xoxc-ab-12"}'},
           "https://other.example": {"secret": "no"}}


# --- settings ---------------------------------------------------------------------


def test_a_full_spec():
    spec = lg.spec(LOGIN, "keychain:corp-browser")
    assert spec.state_service == "corp-browser" and spec.domains == ("*.corp.example", "corp.example", "idp.example")
    assert [c.service for c in spec.captures] == ["chat-d", "chat-xoxc"]
    assert spec.captures[1].storage == ("https://app.chat.example", "cfg", "xoxc-[a-z0-9-]+")
    assert lg.spec(None, "keychain:x") is None  # storage_state may come from elsewhere


@pytest.mark.parametrize(("login", "state", "match"), [
    ({**LOGIN, "extra": 1}, None, "keys are"),
    ({**LOGIN, "start_url": "file:///etc/passwd"}, None, "http"),
    ({**LOGIN, "domains": ["*corp.example"]}, None, "host names"),
    ({**LOGIN, "domains": ["Corp.Example"]}, None, "lower-case"),
    (LOGIN, "env:STATE", "must be keychain"),
    ({"start_url": "https://a.example/"}, "keychain:s", "domains: required"),
    ({"start_url": "https://a.example/", "domains": ["a.example"]}, None, "nothing to store"),
    ({**LOGIN, "capture": {"-x": {"cookie": {"domain": "a.example", "name": "d"}}}}, None, "service name"),
    ({**LOGIN, "capture": {"x": {"cookie": {"domain": "a.example"}}}}, None, "cookie:"),
    ({**LOGIN, "capture": {"x": {"cookie": {"domain": "*.a.example", "name": "d"}}}}, None, "cookie:"),
    ({**LOGIN, "capture": {"x": {"cookie": {"domain": "a", "name": "d"}, "storage": {}}}}, None, "exactly one"),
    ({**LOGIN, "capture": {"x": {"storage": {"origin": "https://a.example/", "key": "k"}}}}, None, "storage:"),
    ({**LOGIN, "capture": {"x": {"storage": {"origin": "https://a.example", "key": "k", "match": "("}}}}, None,
     "match"),
    ({**LOGIN, "capture": {"st": {"cookie": {"domain": "a.example", "name": "d"}}}}, "keychain:st",
     "storage_state's own"),
])
def test_bad_specs(login, state, match):
    with pytest.raises(lg.LoginError, match=match):
        lg.spec(login, state)


# --- what is exported ----------------------------------------------------------------


@pytest.mark.parametrize(("host", "ok"), [
    ("corp.example", True), (".corp.example", True), ("wiki.corp.example", True), ("a.b.corp.example", True),
    ("idp.example", True), ("x.idp.example", False), ("evilcorp.example", False), ("corp.example.evil", False),
])
def test_domain_matching(host, ok):
    assert lg.matches(host, ("*.corp.example", "corp.example", "idp.example")) is ok
    # `*.x` alone is x's subdomains, not x
    assert lg.matches(".corp.example", ("*.corp.example",)) is False


def test_the_state_holds_only_the_named_hosts():
    ex = lg.export_state(COOKIES, STORAGE, ("*.corp.example", "corp.example"))
    assert [c["name"] for c in ex.state["cookies"]] == ["sso", "wiki"]
    sso, wiki = ex.state["cookies"]
    assert sso == {"name": "sso", "value": "S1", "domain": ".corp.example", "path": "/", "expires": 2_000_000_000,
                   "httpOnly": True, "secure": True, "sameSite": "None"}
    assert wiki["expires"] == -1 and wiki["sameSite"] == "Lax"   # a session cookie; Lax when CDP gives none
    assert ex.state["origins"] == [{"origin": "https://wiki.corp.example", "localStorage": [{"name": "k",
                                                                                           "value": "v"}]}]
    # what was left out, by host and count, never by value
    assert ex.dropped == {"tracker.example": 1, "wiki.corp.example (partitioned)": 1, "chat.example": 1,
                          "https://app.chat.example": 1, "https://other.example": 1}
    assert "S1" not in ex.summary and "2 cookie(s) for corp.example, wiki.corp.example" in ex.summary


def test_captures_pick_one_value_each():
    spec = lg.spec(LOGIN, None)
    assert lg.captures(spec.captures, COOKIES, STORAGE) == {"chat-d": "xoxd-123", "chat-xoxc": "xoxc-ab-12"}


def test_a_missing_capture_names_what_is_missing_never_a_value():
    spec = lg.spec(LOGIN, None)
    with pytest.raises(lg.LoginError) as e:
        lg.captures(spec.captures, COOKIES[:3], {"https://app.chat.example": {"cfg": "no token here"}})
    msg = str(e.value)
    assert "chat-d: no cookie d of chat.example" in msg and "chat-xoxc: no localStorage cfg" in msg
    assert "open in a tab" in msg and "no token here" not in msg
    two = [*COOKIES, {**COOKIES[-1], "value": "xoxd-other", "path": "/x"}]
    with pytest.raises(lg.LoginError, match="2 different cookies d"):
        lg.captures(spec.captures[:1], two, {})
    with pytest.raises(lg.LoginError, match="not one ASCII line"):
        lg.captures(spec.captures[:1], [{**COOKIES[-1], "value": "a\nb"}], {})


def test_expiry():
    state = lg.export_state(COOKIES, {}, ("*.corp.example", "corp.example", "tracker.example")).state
    assert lg.expiry(state) == (3, 1, 1_900_000_000)
    assert lg.expiry({"cookies": []}) == (0, 0, None)


# --- the CDP pipe --------------------------------------------------------------------

# A stand-in browser: CDP on fds 3/4, NUL-delimited, as Chrome's
# --remote-debugging-pipe. Records its argv; an event before each reply.
FAKE_CHROME = r'''
import json, os, sys
inp, out = os.fdopen(3, "rb"), os.fdopen(4, "wb")
buf = b""
while True:
    chunk = inp.read1(65536)
    if not chunk:
        break
    buf += chunk
    while b"\0" in buf:
        line, buf = buf.split(b"\0", 1)
        m = json.loads(line)
        out.write(json.dumps({"method": "Target.event", "params": {}}).encode() + b"\0")
        if m["method"] == "Storage.getCookies":
            r = {"result": {"cookies": [{"name": "sso", "value": "S1", "domain": "a.example"}]}}
        elif m["method"] == "Target.getTargets":
            r = {"result": {"targetInfos": [{"type": "page", "targetId": "T1", "url": "https://a.example/x"},
                                            {"type": "page", "targetId": "T2", "url": "chrome://newtab/"},
                                            {"type": "service_worker", "targetId": "T3", "url": "https://a.example/"}]}}
        elif m["method"] == "Target.attachToTarget":
            r = {"result": {"sessionId": "S-" + m["params"]["targetId"]}}
        elif m["method"] == "Runtime.evaluate":
            r = {"result": {"result": {"value": ["https://a.example", [["k", "v"]]]}}}
        elif m["method"] == "Browser.close":
            out.write(json.dumps({"id": m["id"], "result": {}}).encode() + b"\0"); out.flush()
            sys.exit(0)
        elif m["method"] == "Boom":
            r = {"error": {"message": "no such method"}}
        else:
            r = {"result": {}}
        out.write(json.dumps({"id": m["id"], **r}).encode() + b"\0")
        out.flush()
'''


@pytest.fixture
def fake_chrome(tmp_path):
    exe = tmp_path / "chrome"
    exe.write_text(f"#!{sys.executable}\n{FAKE_CHROME}")
    exe.chmod(0o755)
    return str(exe)


def test_the_pipe_reads_cookies_and_open_tabs_storage(fake_chrome):
    chrome = cdp.PipeChrome(fake_chrome, ["--user-data-dir=/x", "https://a.example/"])
    try:
        assert cdp.cookies(chrome) == [{"name": "sso", "value": "S1", "domain": "a.example"}]
        assert cdp.local_storage(chrome, lambda o: True) == {"https://a.example": {"k": "v"}}  # http(s) pages only
        assert cdp.local_storage(chrome, lambda o: False) == {}  # an unwanted tab is never attached
        with pytest.raises(cdp.CDPError, match="no such method"):
            chrome.call("Boom")
    finally:
        chrome.close()
    assert chrome.proc.returncode == 0
    # the browser speaks CDP on the pipe: no debugging port is ever opened
    assert "--remote-debugging-pipe" in chrome.proc.args and not any("port" in a for a in chrome.proc.args)


# --- the sidecar's seeding ----------------------------------------------------------------


_plan = plan_pw


def test_storage_state_reaches_the_sidecar_packed_at_launch_only(tmp_path, monkeypatch):
    state = {"cookies": [{"name": "sso", "value": "S1", "domain": "a.example", "path": "/"}], "origins": []}
    monkeypatch.setenv("PW_STATE", json.dumps(state))
    plan = _plan(tmp_path, storage_state="env:PW_STATE")  # stored some other way than `login`
    pw, text = pw_service(tmp_path, plan)
    assert "S1" not in text  # declared without a value; filled at `compose up`
    assert pw["environment"]["PW_STORAGE_STATE"] is None
    env = launch_env(plan.composition)
    assert json.loads(gzip.decompress(base64.b64decode(env["PW_STORAGE_STATE"]))) == state
    src = (PW / "image" / "glove-pw-start").read_text()
    assert "unset PW_STORAGE_STATE" in src and 'args+=(--storage-state "$STATE")' in src
    assert "umask 077" in src.split("seed_storage_state() {")[1].split("\n}")[0]


def test_without_storage_state_nothing_is_seeded(tmp_path):
    plan = _plan(tmp_path)
    _, text = pw_service(tmp_path, plan)
    assert "PW_STORAGE_STATE" not in text and launch_env(plan.composition) == {}
    assert "signed in as the operator" not in dict(plan.composition.rendered_briefs())["playwright"]


def test_check_warns_when_corporate_does_not_admit_the_signed_in_hosts(tmp_path):
    from glove.doctor import extension_checks

    def egress_check(allow, **pw):
        requested = {"llm": {"provider": "llama.cpp", "location": "host", "endpoint": "127.0.0.1:1"},
                     "corporate": {"allow_domains": allow}, "playwright": pw}
        return [c for c in extension_checks(requested, harness="pi", session_dir=tmp_path)
                if c.name == "playwright egress"]

    login = {"start_url": "https://wiki.corp.example/", "domains": ["corp.example", "*.corp.example"]}
    c, = egress_check(["*.corp.example"], storage_state="keychain:s", login=login)
    assert c.status == "warn" and "add 'corp.example' to" in c.detail  # the parent domain's cookies
    c, = egress_check(["corp.example", "*.corp.example"], storage_state="keychain:s", login=login)
    assert c.status == "ok" and c.detail.startswith("corporate admits *.corp.example, corp.example, wiki.corp.example")
    assert egress_check([], login={"start_url": "https://wiki.corp.example/", "capture": {
        "x": {"cookie": {"domain": "corp.example", "name": "d"}}}}) == []  # no stored session: nothing to reach


def test_the_brief_says_the_browser_is_signed_in_and_how_to_renew(tmp_path):
    brief = dict(_plan(tmp_path, storage_state="keychain:pw-state").composition.rendered_briefs())["playwright"]
    assert "signed in as the operator" in brief and "`glove playwright login`" in brief
    assert "pw-state" not in brief  # not even the reference


@pytest.mark.parametrize(("value", "match"), [
    ("not json", "holds no storage state"),
    ('{"origins": []}', "holds no storage state"),
])
def test_a_value_that_is_not_a_state_is_refused_at_launch(value, match):
    with pytest.raises(ValueError, match=match):
        hooks.state_env("keychain:x", lambda ref: value)


def test_a_state_too_large_for_an_env_string_is_refused(monkeypatch):
    import os

    big = {"cookies": [{"name": f"c{i}", "value": base64.b64encode(os.urandom(600)).decode()} for i in range(200)]}
    with pytest.raises(ValueError, match="too large"):
        hooks.state_env("keychain:x", lambda ref: json.dumps(big))


@pytest.mark.parametrize(("settings", "match"), [
    ({"mode": "host", "port": 18931, "cdp_port": 19222}, "mode host runs your own Chrome"),
    ({"profile": "session"}, "needs profile: ephemeral"),
    ({"uploads": "work"}, "uploads: work could send the stored session"),
    ({"tools": ["browser_navigate", "browser_cookie_list"]}, "browser_cookie_list"),
    ({"tools": ["browser_evaluate"]}, "browser_evaluate"),
    ({"tools": ["browser_network_requests", "browser_network_request"]}, r": browser_network_request would"),
    ({"tools": ["browser_start_tracing"]}, "browser_start_tracing"),
    ({"tools": ["browser_navigate", "browser_route"]}, ": browser_route would"),
    ({"tools": ["browser_localstorage_get", "browser_storage_state"]}, "browser_localstorage_get, browser_storage"),
])
def test_storage_state_refusals(tmp_path, settings, match):
    with pytest.raises(ExtensionError, match=match):
        _plan(tmp_path, storage_state="keychain:corp-browser", **settings)


def test_a_bad_login_fails_at_plan_time(tmp_path):
    with pytest.raises(ExtensionError, match="domains: required"):
        _plan(tmp_path, storage_state="keychain:s", login={"start_url": "https://a.example/"})


# --- `glove playwright login` ----------------------------------------------------------------

class _Chrome:
    """The login browser: signed in only from the second look on."""

    looks = 0

    def __init__(self, exe, args):
        self.args = args
        self.closed = False

    def close(self):
        self.closed = True


def _session(tmp_path, login, state="keychain:corp-browser"):
    (tmp_path / "work").mkdir()
    pw = {"storage_state": state, "login": login} if state else {"login": login}
    (tmp_path / "glove-session.yml").write_text(yaml.safe_dump(
        {"glove": 3, "harness": "pi", "extensions": {"direct": {}, "playwright": pw}}))
    return tmp_path


def test_login_stores_the_filtered_state_and_captures(tmp_path, monkeypatch, capsys):
    d = _session(tmp_path, LOGIN)
    made, stored = [], {}

    def cookies(chrome):
        _Chrome.looks += 1
        return COOKIES if _Chrome.looks > 1 else COOKIES[:1]

    monkeypatch.setattr(_Chrome, "looks", 0)
    monkeypatch.setattr(cdp, "PipeChrome", lambda exe, args: made.append(_Chrome(exe, args)) or made[-1])
    monkeypatch.setattr(cdp, "cookies", cookies)
    monkeypatch.setattr(cdp, "local_storage", lambda chrome, wanted: {o: v for o, v in STORAGE.items() if wanted(o)})
    monkeypatch.setattr(hooks.host_module("chrome"), "chrome_executable", lambda: "/bin/chrome")
    monkeypatch.setattr("glove.config.keychain_set", lambda svc, v=None: stored.update({svc: v}) or 0)
    presses = iter(["", "", ""])  # then StopIteration: a regression fails, never hangs
    monkeypatch.setattr("builtins.input", lambda prompt="": next(presses))
    cli.login(directory=d, keep_profile=False, no_reload=True, headless=True, chrome_args=[])
    out = capsys.readouterr()
    # the first look lacked the chat cookie: told what is missing, then the second look stored all
    assert "not yet:" in out.err and "chat-d: no cookie d of chat.example" in out.err.replace("\n", " ")
    assert stored["chat-d"] == "xoxd-123" and stored["chat-xoxc"] == "xoxc-ab-12"
    state = json.loads(stored["corp-browser"])
    assert {c["name"] for c in state["cookies"]} == {"sso", "wiki"} and state["cookies"][0]["value"] == "S1"
    assert all(v not in out.out + out.err for v in ("S1", "W1", "xoxd-123", "xoxc-ab-12"))
    assert "tracker.example (1)" in out.out  # what was left out, by host
    (chrome,) = made
    assert chrome.closed and chrome.args[-1] == LOGIN["start_url"] and "--headless=new" in chrome.args
    profile = next(a for a in chrome.args if a.startswith("--user-data-dir=")).split("=", 1)[1]
    assert profile.startswith(str(d / ".glove")) and not (d / ".glove" / "playwright-login").exists()


def test_login_stopped_stores_nothing(tmp_path, monkeypatch, capsys):
    d = _session(tmp_path, LOGIN)
    made, stored = [], {}
    monkeypatch.setattr(cdp, "PipeChrome", lambda exe, args: made.append(_Chrome(exe, args)) or made[-1])
    monkeypatch.setattr(hooks.host_module("chrome"), "chrome_executable", lambda: "/bin/chrome")
    monkeypatch.setattr("glove.config.keychain_set", lambda svc, v=None: stored.update({svc: v}) or 0)

    def interrupt(prompt=""):
        raise KeyboardInterrupt

    monkeypatch.setattr("builtins.input", interrupt)
    with pytest.raises(typer.Exit):
        cli.login(directory=d, keep_profile=False, no_reload=True, headless=False, chrome_args=[])
    assert "nothing stored" in capsys.readouterr().err and not stored and made[0].closed


@pytest.mark.parametrize(("login", "state", "match"), [
    (None, None, "set playwright.login"),
    (LOGIN, "env:X", "must be keychain"),
])
def test_login_refusals(tmp_path, capsys, login, state, match):
    d = _session(tmp_path, login, state)
    with pytest.raises(typer.Exit):
        cli.login(directory=d, keep_profile=False, no_reload=True, headless=True, chrome_args=[])
    assert match in " ".join(capsys.readouterr().err.split())  # rich wraps at 80 columns


def test_status_shows_expiry_never_values(tmp_path, monkeypatch):
    soon = time.time() + 7200
    state = {"cookies": [{"name": "sso", "value": "S1", "expires": soon}, {"name": "w", "value": "W1",
                                                                         "expires": -1}]}
    monkeypatch.setattr("glove.config.resolve_secret", lambda ref: json.dumps(state))
    line = cli._state_status("keychain:corp-browser")
    assert "2 cookie(s), 1 for the browser session only" in line and "(in 2.0 h)" in line
    assert "S1" not in line and "W1" not in line
    state["cookies"][0]["expires"] = time.time() - 60
    assert "expired" in cli._state_status("keychain:corp-browser")
    monkeypatch.setattr("glove.config.resolve_secret", lambda ref: "junk")
    assert "unreadable" in cli._state_status("keychain:corp-browser")


# Every tool the pinned MCP defines, sorted by what it can do with a stored
# session. A new pin with a new tool fails here until it is placed: refused
# (STATE_TOOLS) or listed below.
ALLOWED_WITH_A_SESSION = {
    "browser_annotate", "browser_check", "browser_click", "browser_close", "browser_console_clear",
    "browser_console_messages", "browser_drag", "browser_drop", "browser_file_upload", "browser_fill_form",
    "browser_find", "browser_generate_locator", "browser_get_config", "browser_handle_dialog",
    "browser_hide_highlight", "browser_highlight", "browser_hover", "browser_keydown", "browser_keyup",
    "browser_mouse_click_xy", "browser_mouse_down", "browser_mouse_drag_xy", "browser_mouse_move_xy",
    "browser_mouse_up", "browser_mouse_wheel", "browser_navigate", "browser_navigate_back",
    "browser_navigate_forward", "browser_network_clear", "browser_network_requests", "browser_network_state_set",
    "browser_pdf_save", "browser_press_key", "browser_press_sequentially", "browser_reload", "browser_resize",
    "browser_resume", "browser_select_option", "browser_snapshot", "browser_start_recording", "browser_start_video",
    "browser_stop_recording", "browser_stop_tracing", "browser_stop_video", "browser_tabs",
    "browser_take_screenshot", "browser_type", "browser_uncheck", "browser_verify_element_visible",
    "browser_verify_list_visible", "browser_verify_text_visible", "browser_verify_value", "browser_video_chapter",
    "browser_video_hide_actions", "browser_video_show_actions", "browser_wait_for",
}


def test_every_pinned_tool_is_placed_for_a_stored_session():
    manifest = yaml.safe_load((PW / "extension.yml").read_text())
    tools = {t.strip() for t in manifest["harness"]["mcp"][0]["all_tools"].split(",")}
    refused = {t for t in tools if hooks.STATE_TOOLS.fullmatch(t)}
    assert refused.isdisjoint(ALLOWED_WITH_A_SESSION)
    assert tools - refused == ALLOWED_WITH_A_SESSION, "place each new tool: refused (STATE_TOOLS) or allowed"


def test_javascript_urls_are_blocked_unless_evaluate_is_allowed(tmp_path):
    from glove.extensions import materialize

    plan = _plan(tmp_path)
    materialize(plan.composition)
    policy = json.loads((tmp_path / "ext" / "playwright" / "chromium-policy.json").read_text())
    assert policy == {"URLBlocklist": ["javascript://*"]}
    assert hooks.chromium_policy({"tools": ["browser_navigate", "browser_evaluate"]}) == {}
