"""`corporate` (v3 M5): a default-block netgate egress for corporate resources."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from helpers import make_cfg, render

from glove.extensions import ExtensionError, load_module

HOOKS = load_module(Path(__file__).parents[1] / "hooks.py", "corporate")
CORP = {"allow_domains": ["*.corp.example", "git.example.internal"], "allow_cidrs": ["10.20.0.0/16"]}

NETSTAT = """Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.1.1        UGScg                 en0
default            link#22            UCSIg               utun4
10.20/16           10.99.0.1          UGSc                utun4
10.30.40           10.99.0.1          UGSc                utun4
10.99.0.1          10.99.0.2          UH                  utun4
127                127.0.0.1          UCS                   lo0
169.254            link#12            UCS                 utun4
192.168.1          link#12            UCS                   en0
224.0.0/4          link#22            UmCSI               utun4
"""


def _render(tmp_path, corp=None, exts=None):
    work = tmp_path / "w"
    work.mkdir(parents=True, exist_ok=True)
    cfg = make_cfg(harness="pi", name="s", workdir=str(work), subnet="172.31.3.0/24",
                   extensions={"corporate": {**CORP, **(corp or {})},
                               **(exts if exts is not None else {"webfetch": {}})})
    plan, text = render(cfg, tmp_path)
    return plan, yaml.safe_load(text)


def _flags(cmd, name):
    return [cmd[i + 1] for i, x in enumerate(cmd) if x == name]


def test_parse_netstat_macos_abbreviations():
    assert HOOKS.parse_netstat(NETSTAT, "utun4") == ["10.20.0.0/16", "10.30.40.0/24", "10.99.0.1/32"]
    assert HOOKS.parse_netstat(NETSTAT, "en0") == ["192.168.1.0/24"]  # default route never included


def test_from_interface_adds_the_routes_and_records_them(tmp_path, monkeypatch):
    monkeypatch.setattr(HOOKS, "interface_routes", lambda iface: HOOKS.parse_netstat(NETSTAT, iface))
    import glove.extensions as ext

    real = ext.load_module
    monkeypatch.setattr(ext, "load_module", lambda path, name: HOOKS if name == "corporate" else real(path, name))
    plan, doc = _render(tmp_path, {"allow_cidrs": [], "from_interface": "utun4"})
    corp = plan.composition.by_name("corporate")
    assert corp.exports["guard_cidrs"] == ["10.20.0.0/16", "10.30.40.0/24", "10.99.0.1/32"]
    assert corp.exports["resolved"] == {"routes via utun4": ["10.20.0.0/16", "10.30.40.0/24", "10.99.0.1/32"]}
    cmd = doc["services"]["glove-s-corporate-proxy"]["command"]
    assert _flags(cmd, "--guard-allow-cidr") == ["10.20.0.0/16", "10.30.40.0/24", "10.99.0.1/32"]


def test_the_egress_gate(tmp_path):
    plan, doc = _render(tmp_path)
    gate = doc["services"]["glove-s-corporate-proxy"]
    assert gate["image"].startswith("glove/ext-gate-netgate:")
    assert set(gate["networks"]) == {"glove-s-egress", "glove-s-wan"}
    assert gate["user"] == "501:20" and gate["cap_drop"] == ["ALL"] and "cap_add" not in gate
    cmd = gate["command"]
    assert (_flags(cmd, "--upstream"), _flags(cmd, "--route"), _flags(cmd, "--resolver")) == \
        (["direct"], ["corporate"], ["system"])
    assert _flags(cmd, "--guard-allow-host") == ["*.corp.example", "git.example.internal"]
    assert _flags(cmd, "--guard-allow-cidr") == ["10.20.0.0/16"]
    assert _flags(cmd, "--deny-cidr") == ["172.31.3.0/24"]  # the session's own network
    assert "--rules" not in cmd and not any("control" in str(v) for v in gate.get("volumes") or [])
    assert plan.composition.slot_exports("egress")["route"] == "corporate"


def test_verify_is_fail_closed_both_ways(tmp_path):
    plan, _ = _render(tmp_path, {"probe_url": "https://wiki.corp.example/"})
    checks = {c["name"]: c for _, c in plan.composition.verify}
    assert checks["internet-refused"]["kind"] == "http-refused"
    assert checks["internet-refused"]["url"] == "https://example.com/"
    assert checks["probe"]["kind"] == "http-ok" and checks["probe"]["proxy"].endswith("corporate-proxy:8888")
    plan2, _ = _render(tmp_path / "b")
    assert "probe" not in {c["name"] for _, c in plan2.composition.verify}


def test_tcp_endpoints_dial_over_wan(tmp_path):
    _, doc = _render(tmp_path, {"tcp": [{"name": "git-ssh", "to": "git.example.internal:22"}]})
    fwd = doc["services"]["glove-s-git-ssh"]
    assert fwd["command"] == "TCP4-LISTEN:22,fork,reuseaddr TCP4:git.example.internal:22"
    assert set(fwd["networks"]) == {"glove-s-net", "glove-s-wan"}


def test_webfetch_gets_the_allowlist_and_the_observed_proxy_the_exceptions(tmp_path):
    plan, doc = _render(tmp_path, exts={"webfetch": {}, "observe": {}})
    assert plan.environment["GLOVE_FETCH_ALLOW"] == "*.corp.example,git.example.internal,10.20.0.0/16"
    cmd = doc["services"]["glove-s-proxy"]["command"]
    assert _flags(cmd, "--upstream") == ["chain:http://glove-s-corporate-proxy:8888"]
    assert _flags(cmd, "--guard-allow-host") == ["*.corp.example", "git.example.internal"]
    assert "--resolver" not in cmd  # the corporate gate resolves; no in-tunnel resolver


def test_other_egress_routes_give_webfetch_no_allowlist(tmp_path):
    work = tmp_path / "w"
    work.mkdir()
    cfg = make_cfg(harness="pi", name="s", workdir=str(work), extensions={"direct": {}, "webfetch": {}})
    plan, _ = render(cfg, tmp_path)
    assert "GLOVE_FETCH_ALLOW" not in plan.environment


@pytest.mark.parametrize(("corp", "match"), [
    ({"allow_domains": [], "allow_cidrs": []}, "needs an allowlist"),
    ({"allow_domains": ["*"]}, "not a host glob"),
    ({"allow_cidrs": ["127.0.0.0/8"]}, "loopback"),
    ({"allow_cidrs": ["0.0.0.0/0"]}, "loopback"),
    ({"allow_cidrs": ["169.254.0.0/16"]}, "link-local"),
    ({"allow_cidrs": ["fd00::/8"]}, "IPv4"),
    ({"dns": "resolver.corp"}, "IPv4 address"),
    ({"tcp": [{"name": "Bad", "to": "x:22"}]}, "bad entry"),
    ({"tcp": [{"name": "ssh", "to": "x"}]}, "bad entry"),
    ({"probe_url": "ftp://x"}, "http"),
])
def test_bad_settings_fail_at_plan_time(tmp_path, corp, match):
    with pytest.raises(ExtensionError, match=match):
        _render(tmp_path, corp)


def test_corporate_and_another_egress_are_exclusive(tmp_path):
    with pytest.raises(ExtensionError, match="both provide the exclusive 'egress' slot"):
        _render(tmp_path, exts={"direct": {}})


def test_low_port_forwarders_may_bind_as_non_root(tmp_path):
    """podman does not default ip_unprivileged_port_start=0 (docker does): a
    forwarder on port 22 sets it in its own network namespace only."""
    _, doc = _render(tmp_path, {"tcp": [{"name": "git-ssh", "to": "git.example.internal:22"}]},
                     exts={"webfetch": {}, "observe": {}})
    assert doc["services"]["glove-s-git-ssh"]["sysctls"] == {"net.ipv4.ip_unprivileged_port_start": 0}
    assert "sysctls" not in doc["services"]["glove-s-proxy"]  # 8888
    assert "sysctls" not in doc["services"]["glove-s-harness"]
    _, plain = _render(tmp_path / "p", {"tcp": [{"name": "git-ssh", "to": "git.example.internal:22"}]})
    assert plain["services"]["glove-s-git-ssh"]["sysctls"] == {"net.ipv4.ip_unprivileged_port_start": 0}
