"""netgate M3: rules.json validation, evaluation, reload, enforcement, CLI."""

from __future__ import annotations

import asyncio
import contextlib
import gc
import json
import os
import warnings

import pytest

from extensions.gate.netgate.collector import Collector
from extensions.gate.netgate.forward import Forwarder, ForwardSpec
from extensions.gate.netgate.policy import PolicyError, PolicyWatcher, RuleSet, validate
from extensions.gate.tests.contract import CONTRACT
from extensions.gate.tests.test_netgate_proxy import Captured, StubUpstreamProxy, _exchange, _origin, client_hello, run

ENV = SESSION = "pi-search"
CLI_ID = "pi-search-0a0b0c"  # the CLI tests' session id (rules env == session == id)


def doc(*rules, default="allow", **top) -> dict:
    return {"v": 1, "env": ENV, "session": SESSION, "updated_at": "t", "updated_by": "test",
            "default": default, "rules": list(rules), **top}


def rule(rid="r_1", action="block", **match) -> dict:
    return {"id": rid, "action": action, "match": match}


# --- validation ----------------------------------------------------------------


def test_handoff_example_validates():
    rs = validate(CONTRACT["rules"], env="pi-search", session="pi-search")
    assert [r.action for r in rs.rules] == ["block", "block", "allow"]


@pytest.mark.parametrize(
    ("data", "match"),
    [
        (doc(path="/etc"), "unknown top-level keys"),
        (doc(rule(command="rm -rf /")), "unknown keys"),  # a match key outside the schema
        (doc({"id": "r_1", "action": "block", "match": {"host": "x"}, "mount": "/"}), "unknown keys"),
        (doc(rule(action="drop", host="x")), "action"),
        (doc(rule(host="x", port=0)), "port"),
        (doc(rule(host="x", port="443-80")), "port"),
        (doc(rule(host="x", port=True)), "port"),
        (doc(rule(ip="300.1.1.1")), "match.ip"),
        (doc(rule(host="evil[.]com")), "match.host"),
        (doc(rule(scope="everywhere")), "scope"),
        (doc(rule()), "non-empty"),
        (doc(rule(rid="r_1\n", host="x")), "id"),
        (doc(rule(rid="rule1", host="x")), "id"),
        (doc(rule(host="a"), rule(host="b")), "duplicate"),
        (doc(default="deny"), "default"),
        ({**doc(), "v": 2}, "v:"),
        ({**doc(), "env": "other"}, "file is for 'other'"),
        ([], "top level"),
    ],
)
def test_validation_rejects_the_whole_file(data, match):
    with pytest.raises(PolicyError, match=match):
        validate(data, env=ENV, session=SESSION)


def test_evaluation_first_match_then_default():
    rs = validate(doc(
        rule("r_a", "allow", host="api.example.com"),
        rule("r_b", "block", host="*.example.com", port="400-500"),
        rule("r_c", "block", ip="203.0.113.0/24"),
        rule("r_d", "block", tool="web_fetch", scope="direct"),
    ))
    f = {"service": "proxy", "tool": "web_fetch", "scope": "tunnelled", "ip": None}
    assert rs.evaluate({**f, "host": "api.example.com", "port": 443}) == ("allow", "r_a", False)
    assert rs.evaluate({**f, "host": "cdn.example.com", "port": 443}) == ("block", "r_b", False)
    assert rs.evaluate({**f, "host": "cdn.example.com", "port": 80}) == ("allow", None, False)
    assert rs.evaluate({**f, "host": "EXAMPLE.com", "port": 443}) == ("allow", None, False)  # glob needs a label
    assert rs.evaluate({**f, "host": "203.0.113.9", "ip": "203.0.113.9", "port": 1}) == ("block", "r_c", False)
    assert rs.evaluate({**f, "host": "x.org", "port": 1, "scope": "direct"}) == ("block", "r_d", False)
    assert validate(doc(default="block")).evaluate({**f, "host": "x.org", "port": 1}) == ("block", None, False)


# --- watcher: last known-good ----------------------------------------------------


def test_watcher_keeps_last_known_good(tmp_path):
    path = tmp_path / "rules.json"
    w = PolicyWatcher(path, env=ENV, session=SESSION)
    assert w.poll() is False and w.rules == RuleSet() and w.ok  # no file: default allow

    path.write_text(json.dumps(doc(rule(host="bad.example"))))
    assert w.poll() is True and len(w.rules.rules) == 1 and w.ok
    good = w.rules

    path.write_text('{"v": 1, "env": "pi-search", "session": "pi-search", "rules": [{"oops"')  # torn / malformed
    assert w.poll() is False
    assert w.rules == good and w.ok is False and "not valid JSON" in w.error

    path.write_text(json.dumps(doc(rule(host="x", tool="t"), path="/")))  # schema violation
    os.utime(path, ns=(1, 1))
    assert w.poll() is False and w.rules == good and "unknown top-level" in w.error

    path.write_text(json.dumps(doc(rule(host="bad.example"), rule("r_2", host="worse.example"))))
    assert w.poll() is True and len(w.rules.rules) == 2 and w.ok and w.error is None
    status = w.status()
    assert status["active_count"] == 2 and status["loaded_at"] and status["source_mtime"]

    path.unlink()
    assert w.poll() is True and w.rules == RuleSet()


def test_collector_reports_rule_load_result(tmp_path):
    (tmp_path / "rules.json").write_text("not json")
    (tmp_path / "session.json").write_text(json.dumps({"env": ENV, "session": SESSION}))
    c = Collector(tmp_path, "/tmp/unused.sock", rules_path=tmp_path / "rules.json")
    c.write_status("running")
    st = json.loads((tmp_path / "status.json").read_text())["rules"]
    assert st["ok"] is False and "not valid JSON" in st["error"] and st["active_count"] == 0


# --- enforcement ------------------------------------------------------------------


def _proxy(tmp_path, rules_doc: dict | None, scenario):
    path = tmp_path / "rules.json"
    if rules_doc is not None:
        path.write_text(json.dumps(rules_doc))

    async def main():
        origin, oport = await _origin(b"B" * 100)
        up = StubUpstreamProxy({"good.example": oport, "bad.example": oport, "cdn.bad.example": oport})
        await up.start()
        sink = Captured()
        spec = ForwardSpec(service="proxy", listen_port=0, upstream_host="127.0.0.1", upstream_port=up.port,
                           env=ENV, session=SESSION, tool="web_fetch", listen_host="127.0.0.1",
                           mode="http-proxy", route_kind="vpn")
        fwd = Forwarder(spec, sink, policy=PolicyWatcher(path, env=ENV, session=SESSION), policy_poll=0.05)
        await fwd.start()
        result = await scenario(fwd, path)
        await asyncio.sleep(0.05)
        await fwd.stop()
        origin.close()
        up.server.close()
        return result, sink.records, up.heads

    return run(main())


def _connect(host):
    return f"CONNECT {host}:443 HTTP/1.1\r\n\r\n".encode()


def test_blocked_host_fails_but_the_attempt_is_recorded(tmp_path):
    rules = doc(rule("r_bad", host="*.bad.example"), rule("r_bad2", host="bad.example"))

    async def scenario(fwd, _):
        return [await _exchange(fwd.port, _connect(h) + b"x") for h in ("cdn.bad.example", "good.example")]

    (blocked, allowed), recs, heads = _proxy(tmp_path, rules, scenario)
    assert blocked.startswith(b"HTTP/1.1 403") and b"r_bad" in blocked
    assert allowed.startswith(b"HTTP/1.1 200")
    assert heads == [b"CONNECT good.example:443 HTTP/1.1\r\nHost: good.example:443\r\n\r\n"]
    bad = [r for r in recs if r["dest"]["host"] == "cdn.bad.example"]
    assert [r["phase"] for r in bad] == ["open", "close"]
    assert all(r["verdict"] == "block" and r["rule"] == "r_bad" for r in bad)
    assert bad[-1]["close_reason"] == "blocked"


def test_default_block_with_allow_rule(tmp_path):
    rules = doc(rule("r_ok", "allow", host="good.example"), default="block")

    async def scenario(fwd, _):
        return [await _exchange(fwd.port, _connect(h) + b"x") for h in ("good.example", "bad.example")]

    (ok, no), recs, _ = _proxy(tmp_path, rules, scenario)
    assert ok.startswith(b"HTTP/1.1 200") and no.startswith(b"HTTP/1.1 403")
    close = next(r for r in recs if r["phase"] == "close" and r["dest"]["host"] == "bad.example")
    assert close["verdict"] == "block" and close["rule"] is None  # the default decided it


def test_builtin_guard_cannot_be_overridden_by_an_allow_rule(tmp_path):
    rules = doc(rule("r_meta", "allow", ip="169.254.0.0/16"), rule("r_g", "allow", host="gluetun"))

    async def scenario(fwd, _):
        return [await _exchange(fwd.port, _connect(h)) for h in ("169.254.169.254", "gluetun")]

    outs, recs, heads = _proxy(tmp_path, rules, scenario)
    assert all(o.startswith(b"HTTP/1.1 403") for o in outs) and heads == []
    assert {r["rule"] for r in recs if r["phase"] == "close"} == {"builtin:ssrf-guard"}


def test_malformed_rules_file_keeps_the_previous_set(tmp_path):
    async def scenario(fwd, path):
        first = await _exchange(fwd.port, _connect("bad.example"))
        path.write_text("{ this is not json")
        await asyncio.sleep(0.2)
        second = await _exchange(fwd.port, _connect("bad.example"))
        return first, second, fwd.policy.status()

    (first, second, status), _, heads = _proxy(tmp_path, doc(rule(host="bad.example")), scenario)
    assert first.startswith(b"HTTP/1.1 403") and second.startswith(b"HTTP/1.1 403")
    assert status["ok"] is False and status["active_count"] == 1
    assert heads == []


def test_reload_applies_to_new_connections_without_restart(tmp_path):
    async def scenario(fwd, path):
        before = await _exchange(fwd.port, _connect("bad.example") + b"x")
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(doc(rule(host="bad.example"))))
        os.replace(tmp, path)  # atomic rename, as Layman and the CLI write it
        await asyncio.sleep(0.2)
        after = await _exchange(fwd.port, _connect("bad.example"))
        return before, after

    (before, after), _, _ = _proxy(tmp_path, None, scenario)
    assert before.startswith(b"HTTP/1.1 200") and after.startswith(b"HTTP/1.1 403")


@pytest.mark.parametrize("terminate", [True, False])
def test_terminate_cuts_established_flows_only_when_asked(tmp_path, terminate):
    async def scenario(fwd, path):
        r, w = await asyncio.open_connection("127.0.0.1", fwd.port)
        w.write(_connect("bad.example"))
        await w.drain()
        await r.readuntil(b"\r\n\r\n")  # tunnel established
        blocking = rule(host="bad.example")
        blocking["terminate"] = terminate
        path.write_text(json.dumps(doc(blocking)))
        await asyncio.sleep(0.3)
        try:
            cut = await asyncio.wait_for(r.read(), 0.3) == b""
        except TimeoutError:
            cut = False
        w.close()
        return cut

    cut, recs, _ = _proxy(tmp_path, None, scenario)
    close = [r for r in recs if r["phase"] == "close"][-1]
    if terminate:
        assert cut and close["close_reason"] == "blocked" and close["verdict"] == "block" and close["rule"] == "r_1"
    else:
        assert not cut and close["verdict"] == "allow"



@pytest.mark.parametrize("mode", ["tcp", "http-proxy"])
def test_a_cut_flow_closes_its_upstream_too(tmp_path, mode):
    """Cancelling a live flow (a `terminate` rule, the gate stopping) must close
    the upstream socket itself, not leave it to the garbage collector (which
    closes an abandoned StreamWriter late, with a ResourceWarning)."""

    async def main():
        upstream_eof = asyncio.Event()

        async def upstream(r, w):
            if mode == "http-proxy":
                await r.readuntil(b"\r\n\r\n")
                w.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
                await w.drain()
            while await r.read(65536):
                pass
            upstream_eof.set()
            w.close()

        server = await asyncio.start_server(upstream, "127.0.0.1", 0)
        spec = ForwardSpec(service="proxy", listen_port=0, upstream_host="127.0.0.1",
                           upstream_port=server.sockets[0].getsockname()[1], env=ENV, session=SESSION,
                           listen_host="127.0.0.1", mode=mode)
        fwd = Forwarder(spec, Captured())
        await fwd.start()
        r, w = await asyncio.open_connection("127.0.0.1", fwd.port)
        w.write(_connect("good.example") if mode == "http-proxy" else b"hello")
        await w.drain()
        if mode == "http-proxy":
            await r.readuntil(b"\r\n\r\n")
        await asyncio.sleep(0.1)
        await fwd.stop()  # cancels the flow task mid-relay; the client stays open
        gc.collect()
        await asyncio.wait_for(upstream_eof.wait(), 1)
        w.close()
        server.close()

    # Earlier tests' garbage (their unclosed sockets) is collected first, so
    # only a socket this flow leaked can warn inside the capture.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", ResourceWarning)
        gc.collect()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", ResourceWarning)
        run(main())
    assert not [x for x in caught if "unclosed" in str(x.message)]

def test_tcp_mode_sni_rule_blocks_before_any_byte_is_forwarded(tmp_path):
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(doc(rule(host="tracker.example"))))
    hello = client_hello("tracker.example")

    async def main():
        got = bytearray()

        async def upstream(r, w):
            got.extend(await r.read())
            w.close()

        server = await asyncio.start_server(upstream, "127.0.0.1", 0)
        sink = Captured()
        spec = ForwardSpec(service="llm", listen_port=0, upstream_host="127.0.0.1",
                           upstream_port=server.sockets[0].getsockname()[1], env=ENV, session=SESSION,
                           listen_host="127.0.0.1")
        fwd = Forwarder(spec, sink, policy=PolicyWatcher(path, env=ENV, session=SESSION))
        await fwd.start()
        r, w = await asyncio.open_connection("127.0.0.1", fwd.port)
        w.write(hello)
        await w.drain()
        with contextlib.suppress(ConnectionError, OSError):  # the gate closes on us
            await asyncio.wait_for(r.read(), 2)
        w.close()
        await asyncio.sleep(0.1)
        await fwd.stop()
        server.close()
        return bytes(got), sink.records

    got, recs = run(main())
    assert got == b""  # not one byte of the ClientHello reached the upstream
    close = recs[-1]
    assert close["dest"]["host"] == "tracker.example" and close["verdict"] == "block"
    assert close["rule"] == "r_1" and close["close_reason"] == "blocked"


# --- an unreadable rules.json fails closed (followup item 1) ---------------------------

needs_non_root = pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file modes")


def _loaded(tmp_path):
    ctl = tmp_path / "ctl"
    ctl.mkdir()
    path = ctl / "rules.json"
    path.write_text(json.dumps(doc(rule(host="bad.example"))))
    w = PolicyWatcher(path, env=ENV, session=SESSION)
    assert w.poll() is True and w.ok
    return ctl, path, w


@needs_non_root
def test_untraversable_control_dir_is_a_rejection_not_an_absence(tmp_path):
    ctl, _, w = _loaded(tmp_path)
    good, loaded_at = w.rules, w.loaded_at
    ctl.chmod(0o000)  # the gate can no longer stat rules.json
    try:
        assert w.poll() is False
        assert w.rules == good and len(w.rules.rules) == 1  # still enforced
        assert w.ok is False and w.error == "cannot read rules.json: permission denied"
        assert w.status()["active_count"] == 1 and w.loaded_at == loaded_at
        assert w.poll() is False and w.ok is False  # stays rejected, not "removed"
    finally:
        ctl.chmod(0o700)
    assert w.poll() is False and w.ok and w.error is None  # readable again: same file, re-accepted


@needs_non_root
def test_unreadable_file_is_a_rejection_and_a_chmod_repair_is_picked_up(tmp_path):
    _, path, w = _loaded(tmp_path)
    path.write_text(json.dumps(doc(rule(host="bad.example"), rule("r_2", host="worse.example"))))
    path.chmod(0o000)
    assert w.poll() is False and len(w.rules.rules) == 1
    assert w.ok is False and w.error == "cannot read rules.json: permission denied"
    path.chmod(0o600)  # no rewrite: mode is part of the signature
    assert w.poll() is True and w.ok and len(w.rules.rules) == 2


def test_other_stat_errors_fail_closed_too(tmp_path, monkeypatch):
    import errno

    _, path, w = _loaded(tmp_path)
    real_stat = os.stat

    def eio(p, *a, **k):
        if str(p) == str(path):
            raise OSError(errno.EIO, "Input/output error")
        return real_stat(p, *a, **k)

    monkeypatch.setattr(os, "stat", eio)
    assert w.poll() is False and len(w.rules.rules) == 1
    assert w.ok is False and w.error == "cannot read rules.json: input/output error"


def test_only_a_missing_file_or_path_means_no_rules(tmp_path):
    _, path, w = _loaded(tmp_path)
    path.unlink()
    assert w.poll() is True and w.ok and w.rules == RuleSet()
    blocker = tmp_path / "afile"
    blocker.write_text("")
    w2 = PolicyWatcher(blocker / "rules.json", env=ENV, session=SESSION)  # ENOTDIR
    assert w2.poll() is False and w2.ok and w2.rules == RuleSet()


def test_a_directory_named_rules_json_is_a_rejection(tmp_path):
    (tmp_path / "rules.json").mkdir()
    w = PolicyWatcher(tmp_path / "rules.json", env=ENV, session=SESSION)
    w.poll()
    assert w.ok is False and w.error.startswith("cannot read rules.json:")


@needs_non_root
def test_collector_status_reports_an_unreadable_file(tmp_path):
    ctl, path, _ = _loaded(tmp_path)
    (tmp_path / "session.json").write_text(json.dumps({"env": ENV, "session": SESSION}))
    c = Collector(tmp_path, "/tmp/unused.sock", rules_path=path)
    c.write_status("running")
    ctl.chmod(0o000)
    try:
        c.write_status("running")
    finally:
        ctl.chmod(0o700)
    st = json.loads((tmp_path / "status.json").read_text())["rules"]
    assert st["ok"] is False and st["error"] == "cannot read rules.json: permission denied"
    assert st["active_count"] == 1


# --- confirming a specific write (followup item 3) ---------------------------------------


def test_status_names_the_enforced_file_and_the_last_rejected_one_by_hash(tmp_path):
    import hashlib

    path = tmp_path / "rules.json"
    w = PolicyWatcher(path, env=ENV, session=SESSION)
    w.poll()
    assert w.status()["sha256"] is None and w.status()["last_rejected"] is None  # no file

    good = (json.dumps(doc(rule(host="a.example"))) + "\n").encode()
    path.write_bytes(good)
    w.poll()
    st = w.status()
    assert st["sha256"] == hashlib.sha256(good).hexdigest() and st["ok"] and st["last_rejected"] is None
    loaded_at, source_mtime = st["loaded_at"], st["source_mtime"]

    bad = json.dumps(doc(rule(host="a.example"), exec="x")).encode()
    path.write_bytes(bad)
    os.utime(path, ns=(1_800_000_000_123_456_789,) * 2)
    w.poll()
    st = w.status()
    # the frozen v1 fields are unchanged in meaning: they still describe the last ACCEPTED file
    assert st["ok"] is False and "unknown top-level" in st["error"]
    assert (st["loaded_at"], st["source_mtime"], st["active_count"]) == (loaded_at, source_mtime, 1)
    assert st["sha256"] == hashlib.sha256(good).hexdigest()  # still enforced
    rej = st["last_rejected"]
    assert set(rej) == {"checked_at", "source_mtime", "sha256", "error"}
    assert rej["sha256"] == hashlib.sha256(bad).hexdigest() and rej["error"] == st["error"]
    assert rej["source_mtime"] == "2027-01-15T08:00:00.123Z" and rej["checked_at"]

    newer = json.dumps(doc(rule(host="b.example"))).encode()
    path.write_bytes(newer)
    w.poll()
    st = w.status()
    assert st["ok"] and st["error"] is None and st["sha256"] == hashlib.sha256(newer).hexdigest()
    assert st["last_rejected"] == rej  # kept: the most recent rejection, not the current state


@needs_non_root
def test_an_unreadable_file_is_rejected_with_no_hash(tmp_path):
    ctl, _, w = _loaded(tmp_path)
    enforced = w.sha256
    ctl.chmod(0o000)
    try:
        w.poll()
    finally:
        ctl.chmod(0o700)
    rej = w.status()["last_rejected"]
    assert rej["sha256"] is None and rej["source_mtime"] is None
    assert rej["error"] == "cannot read rules.json: permission denied" and w.sha256 == enforced


def test_status_json_carries_the_confirmation_fields(tmp_path):
    (tmp_path / "session.json").write_text(json.dumps({"env": ENV, "session": SESSION}))
    (tmp_path / "rules.json").write_text(json.dumps(doc(rule(host="a.example"))))
    Collector(tmp_path, "/tmp/unused.sock", rules_path=tmp_path / "rules.json").write_status("running")
    st = json.loads((tmp_path / "status.json").read_text())["rules"]
    assert list(st) == ["loaded_at", "source_mtime", "ok", "error", "active_count", "sha256", "last_rejected"]
    assert len(st["sha256"]) == 64 and st["last_rejected"] is None


# --- the ownership contract, glove's side (followup item 2) -----------------------------


def test_a_control_dir_glove_cannot_chmod_is_refused_with_the_fix(tmp_path, monkeypatch):
    from glove.exports import ensure_dir as ensure_net_dir
    from glove.hardening import HardeningError

    d = tmp_path / "control" / "e" / "s"
    d.mkdir(parents=True)

    def eperm(*a, **k):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(os, "chmod", eperm)
    with pytest.raises(HardeningError, match=r"not by you .* sudo chown"):
        ensure_net_dir(d)


def test_ensure_net_dir_is_0700_for_the_invoking_user(tmp_path):
    from glove.exports import ensure_dir as ensure_net_dir

    d = ensure_net_dir(tmp_path / "control" / "e" / "s")
    assert d.stat().st_mode & 0o777 == 0o700 and d.stat().st_uid == os.getuid()


@needs_non_root
def test_launch_warns_about_an_unreadable_rules_file(tmp_path):
    from extensions.gate.gatelib import rules_file_problem

    assert rules_file_problem(tmp_path) is None  # absent: fine
    (tmp_path / "rules.json").write_text("{}")
    assert rules_file_problem(tmp_path) is None  # invalid is the gate's report, not a launch warning
    (tmp_path / "rules.json").chmod(0o000)
    try:
        assert rules_file_problem(tmp_path) == "cannot read rules.json: permission denied"
    finally:
        (tmp_path / "rules.json").chmod(0o600)

