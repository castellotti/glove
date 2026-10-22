"""`exitcheck`: vpn's and tor's exit check, end to end through core's `hook`
verify kind (each egress imports its `verify` hook)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from helpers import make_cfg

import extensions.exitcheck.exitcheck as exitcheck
from glove import verify
from glove.plan import build_session_plan
from glove.verify import VerifyError, run_check


def _plan(tmp_path, exts=None):
    cfg = make_cfg(name="s", workdir=str(tmp_path), extensions=exts or {"tor": {}})
    return build_session_plan(cfg, home_dir=str(tmp_path / "h"), state_dir=str(tmp_path / "x"))


def _quiet(_msg: str) -> None:
    pass


TOR = {"name": "exit-confirmed", "kind": "hook", "source": "url", "url": "https://check.example/api/ip",
       "ip_field": "IP", "expect": {"IsTor": True}, "retries": 2}
GLUETUN = {"name": "exit-confirmed", "kind": "hook", "source": "exec", "service": "gluetun",
           "argv": ["cat", "/run/glove-exit/ip"], "retries": 2}


def _no_host_lookup(url):
    raise AssertionError(f"looked up the host's IP at {url} without host_check_url")


def test_exit_confirmed_from_a_url_through_the_egress_proxy(tmp_path, monkeypatch):
    plan = _plan(tmp_path)
    seen = {}

    def probe(provider, p, network, script, env, **kw):
        seen.update(network=network, **env)
        return 0, '{"IsTor":true,"IP":"198.51.100.7"}'

    monkeypatch.setattr(verify, "probe", probe)
    monkeypatch.setattr(exitcheck, "host_public_ip", _no_host_lookup)
    out = run_check("docker", plan, "tor", TOR, _quiet, sleep_scale=0)
    assert out == "198.51.100.7 (via http://glove-s-privoxy:8118)"
    # probed from the egress network, through the slot's proxy
    assert seen == {"network": "egress", "U": "https://check.example/api/ip", "X": "http://glove-s-privoxy:8118"}


@pytest.mark.parametrize(("rc", "body", "match", "tries"), [
    # a JSON answer is final
    (0, '{"IsTor":false,"IP":"198.51.100.7"}', "NOT leaving through the egress", 1),
    (0, '{"IsTor":1,"IP":"198.51.100.7"}', "NOT leaving through the egress", 1),  # 1 is not true
    (0, '{"IP":"198.51.100.7"}', "NOT leaving through the egress", 1),
    (0, '{"IsTor":true,"IP":"<html>"}', "no IP address in 'IP'", 1),
    (0, '{"IsTor":true}', "no IP address in 'IP'", 1),
    # no answer, or not JSON (a fresh circuit's interstitial page): retried
    (0, "<html><body>blocked</body></html>", "did not answer JSON", 2),
    (0, "", "did not answer JSON", 2),
    (0, '["198.51.100.7"]', "did not answer JSON", 2),
    (7, "", "not passing traffic", 2),
])
def test_exit_confirmed_from_a_url_fails_closed(tmp_path, monkeypatch, rc, body, match, tries):
    plan = _plan(tmp_path)
    seen = []
    monkeypatch.setattr(verify, "probe", lambda *a, **k: seen.append(1) or (rc, body))
    with pytest.raises(VerifyError, match=match):
        run_check("docker", plan, "tor", TOR, _quiet, sleep_scale=0)
    assert len(seen) == tries


def test_exit_confirmed_from_a_url_retries_a_bad_answer(tmp_path, monkeypatch):
    plan = _plan(tmp_path)
    answers = iter([(0, "<html>connecting…</html>"), (0, '{"IsTor":true,"IP":"198.51.100.7"}')])
    monkeypatch.setattr(verify, "probe", lambda *a, **k: next(answers))
    assert run_check("docker", plan, "tor", TOR, _quiet, sleep_scale=0).startswith("198.51.100.7 ")


def _exec(monkeypatch, outs):
    calls, outs = [], iter(outs)

    def fake(cmd, **kw):
        calls.append(cmd)
        rc, out = next(outs)
        return SimpleNamespace(returncode=rc, stdout=out if isinstance(out, bytes) else out.encode(), stderr=b"")

    monkeypatch.setattr(verify.subprocess, "run", fake)
    return calls


def test_exit_confirmed_from_the_sidecar_retries_until_it_prints_an_ip(tmp_path, monkeypatch):
    plan = _plan(tmp_path, {"vpn": {"provider": "custom", "wireguard_key": "keychain:k"}})
    monkeypatch.setattr(exitcheck, "host_public_ip", _no_host_lookup)
    calls = _exec(monkeypatch, [(0, ""), (0, "2001:db8::7\n")])  # gluetun's file is empty until its lookup
    out = run_check("docker", plan, "vpn", GLUETUN, _quiet, sleep_scale=0)
    assert out == "2001:db8::7 (from gluetun)"
    assert calls[-1] == ["docker", "exec", "glove-s-gluetun", "cat", "/run/glove-exit/ip"]


@pytest.mark.parametrize("out", [
    (0, ""),                                   # an empty gluetun file: the tunnel is down
    (0, "198.51.100.7\n198.51.100.8\n"),       # two endpoints in the kill switch
    (0, "<html>secret-account-id</html>"),     # not an IP (and withheld)
    (0, "198.51.100.7:51820"),
    (1, "198.51.100.7"),                       # the command failed
    (0, b"\xff\xfesecret-account-id"),          # not UTF-8: still a VerifyError, still withheld
])
def test_exit_confirmed_from_the_sidecar_fails_closed(tmp_path, monkeypatch, out):
    plan = _plan(tmp_path, {"vpn": {"provider": "custom", "wireguard_key": "keychain:k"}})
    _exec(monkeypatch, [out, out])
    with pytest.raises(VerifyError, match=r"`cat /run/glove-exit/ip` in gluetun did not print one IP address") as e:
        run_check("docker", plan, "vpn", GLUETUN, _quiet, sleep_scale=0)
    assert "secret-account-id" not in str(e.value) and e.value.service == "gluetun"


@pytest.mark.parametrize(("host", "seen", "match"), [
    ("203.0.113.1", "198.51.100.8", None),
    ("203.0.113.1", "203.0.113.1", "NOT going through the tunnel"),
    (None, "198.51.100.8", "cannot be ruled out"),       # no answer from the host, or not an IP
    ("203.0.113.1", "<html>", "named no IP address through the egress proxy"),
])
def test_host_check_url_is_opt_in_and_asks_from_both_sides(tmp_path, monkeypatch, host, seen, match):
    plan = _plan(tmp_path, {"vpn": {"provider": "custom", "wireguard_key": "keychain:k"}})
    _exec(monkeypatch, [(0, "198.51.100.7")])  # the endpoint: never compared with the host
    asked, probed = [], []
    monkeypatch.setattr(exitcheck, "host_public_ip", lambda url: asked.append(url) or host)
    monkeypatch.setattr(verify, "probe", lambda p, pl, net, script, env, **k: probed.append(env) or (0, seen))
    item = {**GLUETUN, "host_check_url": "https://mine.example/ip"}
    if match:
        with pytest.raises(VerifyError, match=match):
            run_check("docker", plan, "vpn", item, _quiet, sleep_scale=0)
    else:
        assert run_check("docker", plan, "vpn", item, _quiet, sleep_scale=0) == (
            "198.51.100.7 (from gluetun); https://mine.example/ip: host 203.0.113.1 ≠ egress 198.51.100.8")
    assert asked == ["https://mine.example/ip"]
    assert probed in ([], [{"U": "https://mine.example/ip", "X": "http://glove-s-gluetun:8888"}])


@pytest.mark.parametrize(("body", "want"), [
    (b"203.0.113.1\n", "203.0.113.1"), (b" 2001:db8::1 ", "2001:db8::1"), (b"<html>", None), (b"", None),
])
def test_host_public_ip_must_be_an_ip(monkeypatch, body, want):
    import io

    monkeypatch.setattr(exitcheck.urllib.request, "urlopen", lambda url, timeout: io.BytesIO(body))
    assert exitcheck.host_public_ip("https://mine.example/ip") == want


def test_the_egresses_check_their_exit_through_the_library(tmp_path):
    for ext, settings in (("tor", {}), ("vpn", {"provider": "custom", "wireguard_key": "keychain:k"})):
        comp = _plan(tmp_path, {ext: settings}).composition
        assert "exitcheck" in [a.name for a in comp.active]
        check = next(v for e, v in comp.verify if v.get("name") == "exit-confirmed")
        assert check["kind"] == "hook" and "verify" in comp.by_name(ext).hooks
        exitcheck.check_item(check)  # the in-tree checks are well formed (glove itself checks them at `up`)


@pytest.mark.parametrize(("item", "match"), [
    ({"source": "ping"}, "needs `source`"),
    ({"source": "exec", "service": "gluetun"}, "needs `service` and `argv`"),
    ({"source": "url", "url": "https://x/"}, "needs `url`, `ip_field`"),
    ({"source": "url", "url": "https://x/", "ip_field": "IP", "expect": ["IsTor"]}, "needs `url`, `ip_field`"),
])
def test_a_malformed_check_is_refused(tmp_path, item, match):
    with pytest.raises(VerifyError, match=match):
        run_check("docker", _plan(tmp_path), "tor", {"name": "x", "kind": "hook", **item}, _quiet, sleep_scale=0)
