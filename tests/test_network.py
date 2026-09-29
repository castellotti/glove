"""Network-plan tests: extension endpoints → forwarder sidecars."""

from __future__ import annotations

from helpers import make_cfg

from glove.plan import build_session_plan


def _plan(tmp_path, exts=None):
    cfg = make_cfg(harness="pi", name="s", workdir=str(tmp_path), extensions=exts or {}, subnet="172.31.4.0/24")
    return build_session_plan(cfg, env_id="s", home_dir=str(tmp_path / "h"), state_dir=str(tmp_path / "x"))


def test_the_inference_endpoint_is_the_only_forwarder_by_default(tmp_path):
    net = _plan(tmp_path).network
    assert [s.role for s in net.sidecars] == ["llm"]
    assert net.hostgw_network == "glove-s-hostgw" and net.sidecars[0].host_gateway


def test_endpoints_join_their_target_networks_and_sessions_get_slices(tmp_path):
    net = _plan(tmp_path, {"direct": {}, "search": {}}).network
    search = next(s for s in net.sidecars if s.role == "search")
    assert search.networks == ("glove-s-searchnet",) and search.impl is None
    assert list(net.subnets) == ["glove-s-net", "glove-s-hostgw", "glove-s-egress", "glove-s-searchnet",
                                 "glove-s-wan"]
    assert net.subnets["glove-s-net"] == "172.31.4.0/27"


def test_an_uninterposed_hop_renders_no_forwarder(tmp_path):
    net = _plan(tmp_path, {"direct": {}, "search": {}}).network
    assert "searxng-egress" not in {s.role for s in net.sidecars}
