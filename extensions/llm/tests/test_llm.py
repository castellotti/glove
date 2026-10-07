"""`llm` extension: provider catalog, routing by location, model descriptor,
`model: auto` / `capabilities: auto` resolution, and the network invariants."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
import yaml
from helpers import STUB_LLM, make_cfg, render

from glove.config import ConfigError
from glove.extensions import IN_TREE_DIR, ExtensionError, load_module

HERE = Path(__file__).resolve().parent
GOLDEN = HERE / "golden"
hooks = load_module(IN_TREE_DIR / "llm" / "hooks.py", "llm")
REGEN = os.environ.get("GLOVE_REGEN_GOLDEN") == "1"


# --- catalog -----------------------------------------------------------------------


@pytest.mark.parametrize("path", sorted((IN_TREE_DIR / "llm" / "providers").glob("*.yml")), ids=lambda p: p.stem)
def test_every_catalog_entry_is_valid(path):
    cat = hooks.load_provider(path.stem)
    assert cat["name"] == path.stem
    assert cat["api"] in ("openai-completions", "anthropic-messages", "mistral-conversations")
    assert set(cat["locations"]) <= {"host", "lan", "internet"}
    # a dedicated entry must offer what openai-compatible cannot (see its header)
    if cat["name"] != "openai-compatible" and "internet" not in cat["locations"]:
        probe = (cat.get("probes") or {}).get("capabilities") or {}
        assert probe and probe["path"] != "/v1/models", f"{cat['name']} adds nothing over openai-compatible"
    assert isinstance(cat.get("base_path", ""), str)
    assert set(cat.get("defaults") or {}) <= set(hooks.CAPABILITY_KEYS)
    if cat["locations"] == ["internet"]:
        assert cat.get("host") and cat["auth"]["required"] is True
    else:
        assert isinstance(cat.get("default_port"), int)
    for key, spec in ((cat.get("probes") or {}).get("capabilities") or {}).items():
        if key in hooks.CAPABILITY_KEYS:
            assert (spec if isinstance(spec, str) else spec["path"]).startswith("$")


def test_catalog_names_match_the_settings_enum():
    manifest = yaml.safe_load((IN_TREE_DIR / "llm" / "extension.yml").read_text())
    names = sorted(p.stem for p in (IN_TREE_DIR / "llm" / "providers").glob("*.yml"))
    assert sorted(manifest["settings"]["provider"]["values"]) == names


# --- routing -----------------------------------------------------------------------------


def _llm(**s):
    return {"llm": {**STUB_LLM, **s}}


def _plan(tmp_path, harness="pi", **s):
    work = tmp_path / "work"
    work.mkdir(parents=True, exist_ok=True)
    cfg = make_cfg(harness=harness, name="s", workdir=str(work))
    cfg.extensions = _llm(**s)
    plan, text = render(cfg, tmp_path)
    return plan, yaml.safe_load(text), text


def _normalise(text: str, tmp_path: Path) -> str:
    from glove.runtimes.seccomp import SECCOMP_DIR

    return text.replace(str(tmp_path), "<tmp>").replace(str(SECCOMP_DIR), "<seccomp>")


ANTHROPIC = {"provider": "anthropic", "location": "internet", "endpoint": None, "api_key": "keychain:test-cc"}
SCENARIOS = {
    "host": {"location": "host", "endpoint": "127.0.0.1:8080"},
    "lan": {"location": "lan", "endpoint": "192.168.1.50:8080"},
    "internet": {"provider": "openai", "location": "internet", "endpoint": None, "api_key": "keychain:test-llm"},
}


@pytest.mark.parametrize("scenario", sorted(SCENARIOS))
def test_golden_compose_per_location(tmp_path, scenario):
    _, _, text = _plan(tmp_path, **SCENARIOS[scenario])
    got = _normalise(text, tmp_path)
    golden = GOLDEN / f"compose-{scenario}.yml"
    if REGEN:
        golden.parent.mkdir(exist_ok=True)
        golden.write_text(got)
    assert got == golden.read_text()


def test_host_location_forwards_to_the_host_gateway(tmp_path):
    plan, doc, _ = _plan(tmp_path, **SCENARIOS["host"])
    llm = doc["services"]["glove-s-llm"]
    assert llm["command"] == "TCP4-LISTEN:8080,fork,reuseaddr TCP4:host.docker.internal:8080"
    assert set(llm["networks"]) == {"glove-s-net", "glove-s-hostgw"}
    assert plan.model.base_url == "http://glove-s-llm:8080/v1"


def test_lan_location_dials_exactly_the_configured_address(tmp_path):
    _, doc, _ = _plan(tmp_path, **SCENARIOS["lan"])
    llm = doc["services"]["glove-s-llm"]
    assert llm["command"].endswith("TCP4:192.168.1.50:8080")
    assert set(llm["networks"]) == {"glove-s-net", "glove-s-llm"}
    assert doc["networks"]["glove-s-llm"].get("internal") in (None, False)  # routes to the LAN
    assert "extra_hosts" not in llm


def test_lan_never_gives_the_harness_a_lan_route(tmp_path):
    for scenario in SCENARIOS:
        _, doc, _ = _plan(tmp_path / scenario, **SCENARIOS[scenario])
        h = doc["services"]["glove-s-harness"]
        assert h["networks"] == ["glove-s-net"]
        assert doc["networks"]["glove-s-net"]["internal"] is True
        assert "extra_hosts" not in h


def test_internet_without_a_key_aliases_the_provider_host_onto_the_forwarder(tmp_path):
    plan, doc, _ = _plan(tmp_path, provider="openai-compatible", location="internet",
                         endpoint="https://llm.example.com/v1")
    llm = doc["services"]["glove-s-llm"]
    assert llm["networks"]["glove-s-net"]["aliases"] == ["llm.example.com"]
    # the aliased forwarder would resolve its own alias: it dials a hop off the
    # harness network, which dials the real name
    assert llm["command"].endswith("TCP4:glove-s-llm-out:443")
    out = doc["services"]["glove-s-llm-out"]
    assert out["command"].endswith("TCP4:llm.example.com:443")
    assert set(out["networks"]) == {"glove-s-llm"}
    assert plan.model.base_url == "https://llm.example.com/v1"  # TLS end to end, real SNI
    assert plan.passthrough_env == [] and "glove-s-llm-auth" not in doc["services"]


def test_a_subscription_token_goes_to_llm_auth_which_serves_the_providers_name(tmp_path):
    plan, doc, _ = _plan(tmp_path, harness="claude-code", **ANTHROPIC, auth="oauth")
    svc = doc["services"]
    # harness → api.anthropic.com:443 (the llm forwarder's alias) → llm-auth, serving TLS as that name
    assert svc["glove-s-llm"]["networks"]["glove-s-net"]["aliases"] == ["api.anthropic.com"]
    assert svc["glove-s-llm"]["command"] == "TCP4-LISTEN:443,fork,reuseaddr TCP4:glove-s-llm-auth:8080"
    assert svc["glove-s-llm-upstream"]["command"].endswith("TCP4:api.anthropic.com:443")
    assert plan.model.base_url == "https://api.anthropic.com" and plan.model.api_key_injected
    assert plan.passthrough_env == [] and plan.environment["CLAUDE_CODE_OAUTH_TOKEN"] == "glove-injected"
    env = svc["glove-s-llm-auth"]["environment"]
    assert (env["LLM_AUTH_SERVE_TLS"], env["LLM_AUTH_TLS_NAME"], env["LLM_AUTH_CA_DIR"]) == \
        ("1", "api.anthropic.com", "/run/glove/llm-ca")
    assert (env["LLM_AUTH_HEADER"], env["LLM_AUTH_SCHEME"]) == ("Authorization", "Bearer")
    allow = json.loads(env["LLM_AUTH_ALLOW"])
    assert ["POST", "/v1/messages"] in allow
    assert all(p in allow for p in hooks.load_provider("anthropic")["auth"]["oauth"]["paths"])
    # the CA certificate: written by llm-auth, read-only for the harness, trusted by it
    vols = {v["target"]: v for v in svc["glove-s-harness"]["volumes"] if v.get("type") == "volume"}
    assert vols["/run/glove/llm-ca"]["read_only"] is True
    assert {"target": "/run/glove/llm-ca", "type": "volume", "source": "glove-s-chan-llm-ca"} in \
        svc["glove-s-llm-auth"]["volumes"]
    assert plan.trusted_cas == ["/run/glove/llm-ca/ca.pem"] == [plan.environment["NODE_EXTRA_CA_CERTS"]]
    assert "/run/glove/llm-ca" not in plan.composition.channel_paths  # never writable by the harness
    assert svc["glove-s-llm-auth"]["restart"] == "no"  # a restart's new CA would be untrusted


def test_an_api_key_session_has_no_ca(tmp_path):
    plan, doc, _ = _plan(tmp_path, harness="claude-code", **ANTHROPIC, auth="api-key")
    assert "NODE_EXTRA_CA_CERTS" not in plan.environment and not plan.composition.channels
    assert "LLM_AUTH_SERVE_TLS" not in doc["services"]["glove-s-llm-auth"]["environment"]
    assert doc["services"]["glove-s-llm-auth"]["restart"] == "unless-stopped"


def test_a_subscription_needs_https(tmp_path):
    with pytest.raises(ExtensionError, match="needs the provider over https"):
        _plan(tmp_path, harness="claude-code", **{**ANTHROPIC, "endpoint": "http://gw.example.com:8080"},
              auth="oauth")


def test_corporate_ca_and_the_session_ca_are_refused_together(tmp_path):
    pem = tmp_path / "corp.pem"
    pem.write_text("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
    work = tmp_path / "work"
    work.mkdir()
    cfg = make_cfg(harness="claude-code", name="s", workdir=str(work), corporate_ca=str(pem))
    cfg.extensions = _llm(**ANTHROPIC, auth="oauth")
    with pytest.raises(ConfigError, match="would trust 2 extra CAs"):
        render(cfg, tmp_path)


def test_internet_with_a_key_goes_through_llm_auth(tmp_path):
    plan, doc, _ = _plan(tmp_path, **SCENARIOS["internet"])
    svc = doc["services"]
    # harness → llm → llm-auth → llm-upstream → the provider; no alias, no -out hop
    assert svc["glove-s-llm"]["command"].endswith("TCP4:glove-s-llm-auth:8080")
    assert "aliases" not in str(svc["glove-s-llm"]["networks"]) and "glove-s-llm-out" not in svc
    assert set(svc["glove-s-llm"]["networks"]) == {"glove-s-net", "glove-s-llmauth"}
    assert svc["glove-s-llm-auth"]["networks"] == {"glove-s-llmauth": {}}
    up = svc["glove-s-llm-upstream"]
    assert up["command"].endswith("TCP4:api.openai.com:443") and set(up["networks"]) == {"glove-s-llmauth",
                                                                                        "glove-s-llm"}
    env = svc["glove-s-llm-auth"]["environment"]
    assert env["LLM_AUTH_KEY"] is None  # filled at `compose up`
    assert (env["LLM_AUTH_UPSTREAM"], env["LLM_AUTH_TLS_NAME"], env["LLM_AUTH_HOST"]) == \
        ("glove-s-llm-upstream:443", "api.openai.com", "api.openai.com")
    assert (env["LLM_AUTH_HEADER"], env["LLM_AUTH_SCHEME"]) == ("Authorization", "Bearer")
    assert json.loads(env["LLM_AUTH_ALLOW"]) == [["POST", "/v1/chat/completions"], ["GET", "/v1/models"]]
    assert plan.model.base_url == "http://glove-s-llm:8080/v1"
    assert plan.passthrough_env == [] and plan.environment["GLOVE_LLM_API_KEY"] == "glove-injected"
    assert doc["networks"]["glove-s-llmauth"]["internal"] is True


@pytest.mark.parametrize(("harness", "settings"), [
    ("pi", {}), ("pi", {"api_key": "env:K"}),
    ("claude-code", {**ANTHROPIC, "auth": "api-key"}), ("claude-code", {**ANTHROPIC, "auth": "oauth"}),
])
def test_the_manifest_and_the_hooks_agree_on_injection(tmp_path, harness, settings):
    # extension.yml's `when:` (network, image, sidecar, verify) and hooks.injected()
    plan, doc, _ = _plan(tmp_path, harness=harness, **{**SCENARIOS["lan"], **settings})
    from glove.extensions import when_context, when_matches

    a = plan.composition.slots["inference"]
    want = hooks.injected(a.settings)
    assert plan.model.api_key_injected is want
    assert ("glove-s-llm-auth" in doc["services"]) is want and ("glove-s-llmauth" in doc["networks"]) is want
    assert when_matches(a.manifest.raw["images"]["auth"].get("when"), when_context(a.settings, harness)) is want
    assert any(v["name"] == "llm-auth-up" for _, v in plan.composition.verify) is want


def test_the_key_reaches_llm_auth_only_at_launch(tmp_path, monkeypatch):
    from glove.plan import secret_env

    monkeypatch.setenv("MY_KEY", "sk-real")
    plan, _, _ = _plan(tmp_path, **{**SCENARIOS["lan"], "api_key": "env:MY_KEY"})
    assert secret_env(plan) == {"LLM_AUTH_KEY": "sk-real"}
    with pytest.raises(hooks.LlmError, match="empty"):
        hooks.launch_env({"settings": {"api_key": "env:E", "auth": "api-key"}}, lambda ref: " ")


@pytest.mark.parametrize(("provider", "endpoint", "want"), [
    ("anthropic", None, [["POST", "/v1/messages"], ["POST", "/v1/messages/count_tokens"], ["HEAD", "/api/hello"],
                         ["GET", "/v1/models"]]),
    ("openrouter", None, [["POST", "/api/v1/chat/completions"], ["GET", "/api/v1/models"]]),
    ("mistral", None, [["POST", "/v1/chat/completions"], ["POST", "/v1/conversations"], ["GET", "/v1/models"]]),
    ("llama.cpp", "127.0.0.1:8080", [["POST", "/v1/chat/completions"], ["GET", "/v1/models"], ["GET", "/props"]]),
    # a server under a path: the API's paths under it, the model list under its root
    ("openai-compatible", "https://gw.example.com/team/v1", [["POST", "/team/v1/chat/completions"],
                                                             ["GET", "/team/v1/models"]]),
])
def test_allowed_paths_per_provider(provider, endpoint, want):
    cat = hooks.load_provider(provider)
    settings = {"provider": provider, "location": "host" if endpoint and "://" not in endpoint else "internet",
                "endpoint": endpoint}
    assert hooks.allowed_paths(cat, hooks.route(settings, cat)["base_path"]) == want


def test_oauth_paths_join_the_allowlist_under_the_server_root():
    cat = hooks.load_provider("anthropic")
    got = hooks.allowed_paths(cat, "", cat["auth"]["oauth"]["paths"])
    assert ["GET", "/api/oauth/profile"] in got and got.index(["POST", "/v1/messages"]) == 0


def test_a_bad_oauth_path_is_refused(tmp_path, monkeypatch):
    (tmp_path / "x.yml").write_text("name: x\napi: anthropic-messages\nlocations: [internet]\n"
                                    "auth: {oauth: {paths: [[GET, api/no-slash]]}}\n")
    monkeypatch.setattr(hooks, "PROVIDERS", tmp_path)
    with pytest.raises(hooks.LlmError, match="bad oauth path"):
        hooks.load_provider("x")


def test_observe_labels_the_llm_forwarder(tmp_path):
    for scenario, scope in (("host", "local"), ("lan", "lan"), ("internet", "cloud")):
        work = tmp_path / scenario / "w"
        work.mkdir(parents=True)
        cfg = make_cfg(harness="pi", name="s", workdir=str(work))
        cfg.extensions = {**_llm(**SCENARIOS[scenario]), "observe": {}}
        from glove.plan import build_session_plan

        plan = build_session_plan(cfg, home_dir=str(tmp_path / scenario / "h"),
                                  state_dir=str(tmp_path / scenario / "ext"))
        facts = next(s.facts for s in plan.network.sidecars if s.role == "llm")
        assert (facts["tool"], facts["scope"]) == ("llm", scope)


@pytest.mark.parametrize("settings,match", [
    ({"location": "host", "endpoint": "192.168.1.5:8080"}, "location host means a server on this Mac"),
    ({"location": "lan", "endpoint": "127.0.0.1:8080"}, "is location: host, not lan"),
    ({"location": "lan", "endpoint": None}, "set `endpoint`"),
    ({"location": "internet"}, "supports location"),
    ({"provider": "openai", "location": "internet", "endpoint": None}, "needs `api_key"),
    ({"location": "lan", "endpoint": "https://x.example:8443"}, "needs location: internet"),
    ({"provider": "openai", "location": "internet", "endpoint": None, "api_key": "env:X", "route": "egress"},
     "not implemented"),
])
def test_routing_refusals(tmp_path, settings, match):
    with pytest.raises((ExtensionError, ValueError), match=match):
        _plan(tmp_path, **settings)


# --- descriptor / Pi models.json --------------------------------------------------------------


def test_pi_models_json_from_the_descriptor(tmp_path):
    from glove.harnessconfig import render_home

    plan, _, _ = _plan(tmp_path, capabilities={"vision": True, "context_window": 131072})
    cfg = make_cfg(harness="pi", name="s")
    render_home(cfg, plan, tmp_path / "home")
    models = json.loads((tmp_path / "home/.pi/agent/models.json").read_text())["providers"]["glove"]
    assert models["models"][0]["input"] == ["text", "image"]
    assert models["models"][0]["contextWindow"] == 131072


# --- model: auto / capabilities: auto ---------------------------------------------------------


class FakeServer:
    """Answers probes the way llama-server does (`/v1/models`, `/props`)."""

    def __init__(self, models, props=None, status=200):
        self.models, self.props, self.status, self.calls = models, props, status, []

    def __call__(self, url, method="GET", body=None, auth=False):
        self.calls.append((method, url, auth))
        if self.status != 200:
            return self.status, "down"
        if url.endswith("/v1/models"):
            return 200, json.dumps({"object": "list", "data": [{"id": m} for m in self.models]})
        if url.endswith("/props") and self.props is not None:
            return 200, json.dumps(self.props)
        return 404, "not found"


PROPS = {"default_generation_settings": {"n_ctx": 65536}, "modalities": {"vision": True, "audio": False},
         "chat_template_caps": {"supports_preserve_reasoning": True}}


def _resolve(tmp_path, server, **s):
    plan, _, _ = _plan(tmp_path, **s)
    a = plan.composition.slots["inference"]
    from glove.extensions import base_context

    return hooks.resolve(base_context(plan.composition, a), a.exports, server)


def test_model_auto_with_one_model_and_capability_probe(tmp_path):
    server = FakeServer(["qwen3.7-27b"], PROPS)
    ex, notes = _resolve(tmp_path, server, model="auto", capabilities="auto")
    assert ex["model"] == "qwen3.7-27b"
    assert ex["capabilities"]["vision"] is True
    assert ex["capabilities"]["context_window"] == 65536
    assert ex["capabilities"]["reasoning"] is True
    assert any("model: auto → qwen3.7-27b" in n for n in notes)
    assert [c[1] for c in server.calls] == ["http://glove-s-llm:8080/v1/models", "http://glove-s-llm:8080/props"]


def test_model_auto_with_several_models_lists_them(tmp_path):
    with pytest.raises(hooks.LlmError, match=r"found \['a', 'b'\]"):
        _resolve(tmp_path, FakeServer(["a", "b"]), model="auto")


def test_model_auto_with_no_models(tmp_path):
    with pytest.raises(hooks.LlmError, match="found none"):
        _resolve(tmp_path, FakeServer([]), model="auto")


def test_explicit_model_must_be_served(tmp_path):
    with pytest.raises(hooks.LlmError, match="is not served"):
        _resolve(tmp_path, FakeServer(["other"]), model="test-model")


def test_server_down_fails_with_a_hint(tmp_path):
    with pytest.raises(hooks.LlmError, match="is the server running"):
        _resolve(tmp_path, FakeServer([], status=502), model="auto")


def test_explicit_vision_wins_over_probe_with_a_warning(tmp_path):
    props = {**PROPS, "modalities": {"vision": False}}
    ex, notes = _resolve(tmp_path, FakeServer(["test-model"], props), capabilities={"vision": True})
    assert ex["capabilities"]["vision"] is True
    assert any("warning" in n and "vision" in n for n in notes)


def test_the_probe_never_holds_an_injected_key(tmp_path):
    server = FakeServer(["m"], PROPS)
    _resolve(tmp_path, server, model="auto", api_key="env:X")  # llm-auth adds it on the way
    assert server.calls and not any(auth for _, _, auth in server.calls)


def test_the_probe_never_holds_a_subscription_token(tmp_path):
    server = PagedServer(["claude-x"])
    _resolve(tmp_path, server, harness="claude-code", **ANTHROPIC, auth="oauth", model="claude-x")
    assert server.auth == [False]  # llm-auth adds it on the way


def test_json_path():
    doc = {"a": {"b": [{"c": 1}]}}
    assert hooks.json_path(doc, "$.a.b[0].c") == 1
    assert hooks.json_path(doc, "$.a.x") is None
    assert hooks.json_path(doc, "$.a.b[3].c") is None



def _models_only(ids_and_len):
    models = {"object": "list", "data": [{"id": i, "object": "model", "max_model_len": n} for i, n in ids_and_len]}

    def server(url, method="GET", body=None, auth=False):
        return (200, json.dumps(models)) if url.endswith("/v1/models") else (404, "not found")

    return server


GENERIC = {"provider": "openai-compatible", "location": "lan", "endpoint": "llm.example:8080", "model": "auto"}


def test_generic_provider_probes_max_model_len(tmp_path):
    # vLLM / NInfer / llama.cpp all put max_model_len on the model object.
    ex, notes = _resolve(tmp_path, _models_only([("qwen3.8-27b-5090", 131072)]), **GENERIC, capabilities="auto")
    assert ex["model"] == "qwen3.8-27b-5090"
    assert ex["capabilities"]["context_window"] == 131072
    assert ex["capabilities"]["vision"] is False  # not discoverable via the OpenAI API
    assert any("context_window=131072" in n for n in notes)


def test_explicit_capabilities_merge_with_the_probe(tmp_path):
    ex, _ = _resolve(tmp_path, _models_only([("m", 65536)]), **GENERIC, capabilities={"vision": True})
    assert ex["capabilities"]["vision"] is True  # explicit
    assert ex["capabilities"]["context_window"] == 65536  # probed


def test_explicit_capability_wins_over_a_conflicting_probe(tmp_path):
    ex, notes = _resolve(tmp_path, _models_only([("m", 65536)]), **GENERIC, capabilities={"context_window": 8192})
    assert ex["capabilities"]["context_window"] == 8192
    assert any("warning: capabilities.context_window" in n for n in notes)


def test_generic_provider_without_max_model_len_keeps_the_default(tmp_path):
    def server(url, method="GET", body=None, auth=False):
        return 200, json.dumps({"data": [{"id": "m"}]})

    ex, notes = _resolve(tmp_path, server, **GENERIC, capabilities="auto")
    assert ex["capabilities"]["context_window"] == 32768
    assert any("did not report context_window; using the default 32768" in n for n in notes)


# --- auth: oauth and paginated model lists ----------------------------------------------------



def test_oauth_is_for_the_harnesses_the_catalog_names(tmp_path):
    with pytest.raises(ExtensionError, match="for claude-code only, not harness 'pi'"):
        _plan(tmp_path, **ANTHROPIC, auth="oauth")


def test_oauth_needs_a_catalog_oauth_block(tmp_path):
    with pytest.raises(ExtensionError, match="takes no `auth: oauth`"):
        _plan(tmp_path, harness="claude-code", provider="openai", location="internet", endpoint=None,
              api_key="keychain:k", auth="oauth")


def test_oauth_exports_bearer_auth_and_the_beta_header(tmp_path):
    plan, _, _ = _plan(tmp_path, harness="claude-code", **ANTHROPIC, auth="oauth")
    ex = plan.composition.slots["inference"].exports
    assert (ex["auth_header"], ex["auth_scheme"], ex["api_key_kind"]) == ("Authorization", "Bearer", "oauth")
    assert ex["probe_headers"] == {"anthropic-version": "2023-06-01", "anthropic-beta": "oauth-2025-04-20"}
    assert plan.model.api_key_kind == "oauth"


def test_api_key_auth_keeps_x_api_key(tmp_path):
    plan, _, _ = _plan(tmp_path, **ANTHROPIC)
    ex = plan.composition.slots["inference"].exports
    assert (ex["auth_header"], ex["auth_scheme"], ex["api_key_kind"]) == ("x-api-key", "", "api-key")
    assert ex["probe_headers"] == {"anthropic-version": "2023-06-01"}


class PagedServer:
    """Anthropic's `/v1/models`: pages of two, `has_more` + `last_id`, `after_id` cursor."""

    def __init__(self, models):
        self.models, self.calls, self.auth = models, [], []

    def __call__(self, url, method="GET", body=None, auth=False):
        self.calls.append(url)
        self.auth.append(auth)
        after = url.partition("after_id=")[2]
        start = self.models.index(after) + 1 if after else 0
        page = self.models[start:start + 2]
        more = start + 2 < len(self.models)
        return 200, json.dumps({"data": [{"id": m} for m in page], "has_more": more, "last_id": page[-1]})


def test_a_paginated_model_list_is_followed_to_the_end(tmp_path):
    server = PagedServer(["a", "b", "c", "d", "claude-x"])
    ex, _ = _resolve(tmp_path, server, **ANTHROPIC, model="claude-x")
    assert ex["model"] == "claude-x"
    assert server.calls == ["http://glove-s-llm:8080/v1/models?limit=1000",  # through llm-auth
                            "http://glove-s-llm:8080/v1/models?limit=1000&after_id=b",
                            "http://glove-s-llm:8080/v1/models?limit=1000&after_id=d"]


def test_a_model_on_no_page_is_not_served(tmp_path):
    with pytest.raises(hooks.LlmError, match="is not served"):
        _resolve(tmp_path, PagedServer(["a", "b", "c"]), **ANTHROPIC, model="claude-x")


def test_an_alias_matches_its_dated_snapshot(tmp_path):
    ex, _ = _resolve(tmp_path, PagedServer(["claude-x-20251001"]), **ANTHROPIC, model="claude-x")
    assert ex["model"] == "claude-x"
    (tmp_path / "b").mkdir()
    with pytest.raises(hooks.LlmError, match="is not served"):
        _resolve(tmp_path / "b", PagedServer(["claude-x-2-20251001"]), **ANTHROPIC, model="claude-x")
