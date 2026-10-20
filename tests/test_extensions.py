"""Extension API (api: 2): manifests, settings, slots, composition and the
§3.4 invariants core enforces on every extension fragment."""

from __future__ import annotations

import json
import re
import textwrap
from pathlib import Path

import pytest
import yaml
from helpers import PEM, STUB_LLM, make_cfg, render

from glove.config import ConfigError
from glove.extensions import IN_TREE_DIR, ExtensionError, compose, discover, select, when_matches
from glove.harness import base_image

DIGEST = "alpine@sha256:" + "0" * 64


def _ext(root: Path, name: str, manifest: str, files: dict[str, str] | None = None) -> Path:
    d = root / name
    d.mkdir(parents=True)
    (d / "extension.yml").write_text(textwrap.dedent(manifest))
    for rel, text in (files or {}).items():
        (d / rel).parent.mkdir(parents=True, exist_ok=True)
        (d / rel).write_text(textwrap.dedent(text))
    return d


@pytest.fixture
def ghome(tmp_path, monkeypatch):
    monkeypatch.setenv("GLOVE_HOME", str(tmp_path / "gh"))
    return tmp_path / "gh"


@pytest.fixture
def tree(tmp_path, ghome):
    """A private extension tree: the real llm plus test manifests."""
    import shutil

    root = tmp_path / "exts"
    root.mkdir()
    shutil.copytree(IN_TREE_DIR / "llm", root / "llm", ignore=shutil.ignore_patterns("tests", "__pycache__"))
    return root


def _svc_ext(root, name="side", service: str = "", extra: str = "", provides: str = "[]"):
    body = service or f"""\
        services:
          worker:
            image: {DIGEST}
            networks: [egress]
        """
    manifest = f"api: 2\nname: {name}\nsummary: test\nprovides: {provides}\nservices: services.yml\n{extra}\n"
    return _ext(root, name, manifest, {"services.yml": body})


def _egress(root, name="egress-a"):
    return _ext(root, name, f"""\
        api: 2
        name: {name}
        summary: test egress
        provides: [egress]
        exports: {{ proxy_host: "glove-{{{{ session.id }}}}-tunnel", proxy_port: 8888, route: direct, network: egress,
                   proxy_url: "http://glove-{{{{ session.id }}}}-tunnel:8888" }}
        services: services.yml
        """, {"services.yml": f"""\
        services:
          tunnel:
            image: {DIGEST}
            networks: [egress, wan]
        """})


def _render(tmp_path, root, extensions, **kw):
    cfg = make_cfg(harness="pi", name="s", workdir=str(_work(tmp_path)), extensions=extensions, **kw)
    import glove.extensions as ext_mod

    real = ext_mod.discover
    ext_mod.discover = lambda in_tree=None: real(root)
    try:
        plan, text = render(cfg, tmp_path)
    finally:
        ext_mod.discover = real
    return plan, yaml.safe_load(text)


def _work(tmp_path):
    w = tmp_path / "work"
    w.mkdir(exist_ok=True)
    return w


# --- discovery, manifests, settings ------------------------------------------------


def test_in_tree_extensions_load():
    found = discover()
    assert {"llm", "media", "search", "playwright"} <= set(found)
    assert all(m.taint == "in-tree" for m in found.values())


def test_manifest_rejects_unknown_keys_and_bad_api(tree):
    _ext(tree, "bad", "api: 2\nname: bad\nsummary: x\nprivileged: true\n")
    with pytest.raises(ExtensionError, match="unknown manifest keys"):
        discover(tree)


@pytest.mark.parametrize("api", [1, 3])
def test_manifest_rejects_wrong_api(tree, api):
    _ext(tree, "old", f"api: {api}\nname: old\nsummary: x\n")
    with pytest.raises(ExtensionError, match=f"'old' is written for api {api}; glove speaks api 2"):
        discover(tree)


@pytest.mark.parametrize("key", ["conflicts: [b]", "trust_corporate_ca: [x]", "host_services: []", "vars: {}"])
def test_dropped_renamed_and_hook_only_keys_are_unknown_in_a_manifest(tree, key):
    _ext(tree, "a", f"api: 2\nname: a\nsummary: x\n{key}\n")
    with pytest.raises(ExtensionError, match="unknown manifest keys"):
        discover(tree)


def test_a_manifest_key_has_its_type(tree):
    _ext(tree, "a", "api: 2\nname: a\nsummary: x\ntrust: worker\n")
    with pytest.raises(ExtensionError, match="`trust` must be a list"):
        discover(tree)


def test_settings_unknown_placeholder_and_types(tree):
    m = discover(tree)
    with pytest.raises(ExtensionError, match="unknown setting"):
        select({"llm": {**STUB_LLM, "nope": 1}}, harness="pi", manifests=m)
    with pytest.raises(ExtensionError, match="still '<set-me>'"):
        select({"llm": {**STUB_LLM, "endpoint": "<set-me>"}}, harness="pi", manifests=m)
    with pytest.raises(ExtensionError, match="must be one of"):
        select({"llm": {**STUB_LLM, "location": "moon"}}, harness="pi", manifests=m)
    with pytest.raises(ExtensionError, match="is required"):
        select({"llm": {"location": "host"}}, harness="pi", manifests=m)


def test_secret_settings_must_be_references(tree):
    m = discover(tree)
    with pytest.raises(ExtensionError, match="use a reference"):
        select({"llm": {**STUB_LLM, "api_key": "sk-literal"}}, harness="pi", manifests=m)
    for ref in ("keychain:svc", "env:VAR"):
        select({"llm": {**STUB_LLM, "api_key": ref}}, harness="pi", manifests=m)


def test_when_predicates():
    ctx = {"settings": {"mode": "host", "n": 1}, "harness": "vibe", "slot": {"egress": {"route": "tor"}}}
    assert when_matches({"mode": ["host", "novnc"]}, ctx)
    assert not when_matches({"mode": "headless"}, ctx)
    assert when_matches({"harness": "vibe", "n": 1}, ctx)
    assert when_matches({"slot.egress.route": "tor"}, ctx)
    assert not when_matches({"slot.egress.route": "vpn"}, ctx)
    assert when_matches(None, ctx)
    # any-of across keys, ANDed with the rest
    assert when_matches({"any": [{"harness": "pi"}, {"mode": "host"}]}, ctx)
    assert not when_matches({"any": [{"harness": "pi"}, {"mode": "headless"}]}, ctx)
    assert not when_matches({"any": [{"harness": "vibe"}], "n": 2}, ctx)
    assert not when_matches({"any": []}, ctx) and not when_matches({"any": {"harness": "vibe"}}, ctx)


def test_when_a_star_matches_any_key_and_gives_what_it_found():
    ctx = {"settings": {"plugins": {"a": {"relay": {"commands": {}}}, "b": {"path": "x"}, "c": {"relay": None}}}}
    assert when_matches({"settings.plugins.*.relay": {"set": True}}, ctx)
    assert not when_matches({"settings.plugins.*.mcp": {"set": True}}, ctx)
    assert when_matches({"settings.plugins.*.mcp": {"set": False}}, ctx)
    assert when_matches({"settings.plugins.*.path": "x"}, ctx)
    assert not when_matches({"settings.plugins.*.path": "y"}, ctx)
    assert not when_matches({"settings.plugins.*.relay": {"set": True}}, {"settings": {"plugins": {}}})
    assert not when_matches({"settings.plugins.*.relay": {"set": True}}, {"settings": {}})


@pytest.mark.parametrize("harness", ["pi", "vibe", "claude-code"])
def test_when_renders_follows_the_harness_contributions(harness):
    from glove.extensions import when_context

    ctx = when_context({"dir": "", "n": 0}, harness)
    assert when_matches({"renders": "mcp"}, ctx)  # every in-tree harness renders MCP
    assert when_matches({"renders": ["mcp", "skills"]}, ctx)  # every harness renders skills
    assert when_matches({"dir": {"set": False}, "n": {"set": True}}, ctx)  # 0 is a value; "" is not


# --- slots, requires, conflicts, auto ----------------------------------------------------


def test_inference_slot_is_required(tree):
    with pytest.raises(ExtensionError, match="required 'inference' slot"):
        select({}, harness="pi", manifests=discover(tree))


def test_two_providers_of_one_slot_are_refused(tree):
    _egress(tree, "egress-a")
    _egress(tree, "egress-b")
    with pytest.raises(ExtensionError, match="both provide the exclusive 'egress' slot"):
        select({"llm": STUB_LLM, "egress-a": {}, "egress-b": {}}, harness="pi", manifests=discover(tree))


def test_requires_slot_and_extension(tree):
    _ext(tree, "needs-egress", "api: 2\nname: needs-egress\nsummary: x\nrequires: [egress]\n")
    _ext(tree, "needs-lib", "api: 2\nname: needs-lib\nsummary: x\nrequires: [lib]\n")
    _ext(tree, "lib", "api: 2\nname: lib\nsummary: x\nauto: true\nselectable: false\n")
    _ext(tree, "plain", "api: 2\nname: plain\nsummary: x\n")
    _ext(tree, "needs-plain", "api: 2\nname: needs-plain\nsummary: x\nrequires: [plain]\n")
    m = discover(tree)
    with pytest.raises(ExtensionError, match="requires the 'egress' slot"):
        select({"llm": STUB_LLM, "needs-egress": {}}, harness="pi", manifests=m)
    # an `auto` library is added; a normal one must be listed
    active = select({"llm": STUB_LLM, "needs-lib": {}}, harness="pi", manifests=m)
    names = [a.name for a in active]
    assert names.index("lib") < names.index("needs-lib")
    assert next(a for a in active if a.name == "lib").auto_added
    with pytest.raises(ExtensionError, match=re.escape("add `plain: {}`")):
        select({"llm": STUB_LLM, "needs-plain": {}}, harness="pi", manifests=m)
    with pytest.raises(ExtensionError, match="library extension"):
        select({"llm": STUB_LLM, "lib": {}}, harness="pi", manifests=m)


def test_unknown_extension(tree):
    with pytest.raises(ExtensionError, match="unknown extension 'nope'"):
        select({"llm": STUB_LLM, "nope": {}}, harness="pi", manifests=discover(tree))


def test_playwright_host_refuses_vibe_without_ack():
    host = {"mode": "host"}
    with pytest.raises(ExtensionError, match="browser_run_code_unsafe"):
        select({"llm": STUB_LLM, "playwright": host}, harness="vibe")
    select({"llm": STUB_LLM, "playwright": {**host, "i_accept_host_rce": True}}, harness="vibe")
    select({"llm": STUB_LLM, "playwright": host}, harness="pi")


# --- out-of-tree taint -----------------------------------------------------------------


def test_out_of_tree_is_tainted_and_cannot_take_privileges(tmp_path, ghome):
    oot = tmp_path / "oot"
    _svc_ext(oot, "vpnish", provides="[egress]", extra="privileges: { worker: { cap_add: [NET_ADMIN] } }\n"
             "exports: { proxy_host: x, proxy_port: 1, proxy_url: 'http://x:1', network: egress }")
    ghome.mkdir(parents=True, exist_ok=True)
    (ghome / "config.yml").write_text(f"extension_paths: [{oot}]\n")
    m = discover()
    assert m["vpnish"].taint == "out-of-tree"
    with pytest.raises(ExtensionError, match="out-of-tree and not in `trusted_extensions`"):
        _render_with(tmp_path, {"vpnish": {}})
    (ghome / "config.yml").write_text(f"extension_paths: [{oot}]\ntrusted_extensions: [vpnish]\n")
    assert discover()["vpnish"].taint == "out-of-tree (trusted)"
    _, doc = _render_with(tmp_path / "t2", {"vpnish": {}})
    assert doc["services"]["glove-s-worker"]["cap_add"] == ["NET_ADMIN"]


def _render_with(tmp_path, extensions, **kw):
    tmp_path.mkdir(parents=True, exist_ok=True)
    cfg = make_cfg(harness="pi", name="s", workdir=str(_work(tmp_path)), extensions=extensions)
    plan, text = render(cfg, tmp_path, **kw)
    return plan, yaml.safe_load(text)


def test_out_of_tree_cannot_shadow_in_tree(tmp_path, ghome):
    oot = tmp_path / "oot"
    _ext(oot, "llm", "api: 2\nname: llm\nsummary: evil\nprovides: [inference]\n")
    ghome.mkdir(parents=True, exist_ok=True)
    (ghome / "config.yml").write_text(f"extension_paths: [{oot}]\n")
    with pytest.raises(ExtensionError, match="shadows an existing extension"):
        discover()


# --- §3.4 fragment invariants --------------------------------------------------------------


@pytest.mark.parametrize("service,match", [
    (f"services:\n  worker: {{image: {DIGEST}, privileged: true, networks: [egress]}}\n", "not allowed"),
    (f"services:\n  worker: {{image: {DIGEST}, ports: ['8080:8080'], networks: [egress]}}\n", "not allowed"),
    (f"services:\n  worker: {{image: {DIGEST}, cap_add: [SYS_ADMIN], networks: [egress]}}\n", "not allowed"),
    (f"services:\n  worker: {{image: {DIGEST}, user: root, networks: [egress]}}\n", "not allowed"),
    (f"services:\n  worker: {{image: {DIGEST}, security_opt: [seccomp=unconfined], networks: [egress]}}\n",
     "not allowed"),
    (f"services:\n  worker: {{image: {DIGEST}, network_mode: host}}\n", "may only be `none`"),
    (f"services:\n  worker: {{image: {DIGEST}, networks: [net]}}\n", "never joins the harness network"),
    (f"services:\n  worker: {{image: {DIGEST}, networks: [wan]}}\n", "may not join network 'wan'"),
    (f"services:\n  worker: {{image: {DIGEST}, networks: [somewhere]}}\n", "may not join network"),
    ("services:\n  worker: {image: 'alpine:latest', networks: [egress]}\n", "pinned by digest"),
    (f"services:\n  worker:\n    image: {DIGEST}\n    networks: [egress]\n    volumes:\n"
     "      - {type: bind, source: /var/run/docker.sock, target: /s}\n", "docker socket"),
    (f"services:\n  worker:\n    image: {DIGEST}\n    networks: [egress]\n    volumes:\n"
     "      - {type: bind, source: /Users, target: /u}\n", "may bind only its state dir"),
    (f"services:\n  worker:\n    image: {DIGEST}\n    networks: [egress]\n    volumes: ['/etc:/etc']\n",
     "long syntax"),
    (f"networks: {{x: {{}}}}\nservices:\n  worker: {{image: {DIGEST}, networks: [egress]}}\n", "only services/volumes"),
], ids=["privileged", "ports", "cap_add", "user", "security_opt", "host-net", "harness-net", "wan", "unknown-net",
        "unpinned", "docker.sock", "host-bind", "short-volume", "top-level"])
def test_fragment_invariants(tmp_path, tree, service, match):
    _egress(tree)
    _svc_ext(tree, service=service)
    with pytest.raises(ExtensionError, match=match):
        _render(tmp_path, tree, {"llm": STUB_LLM, "egress-a": {}, "side": {}})


@pytest.mark.parametrize("privs,match", [
    ("{ worker: { cap_add: [SYS_ADMIN] } }", "not in the allowlist"),
    ("{ worker: { devices: [/dev/kvm] } }", "not in the allowlist"),
    ("{ worker: { seccomp: unconfined } }", "not a core profile"),
    ("{ worker: { seccomp: nested-userns } }", "not a core profile"),
    ("{ worker: { privileged: true } }", "unknown privilege"),
])
def test_privilege_exceptions_come_only_from_the_allowlist(tmp_path, tree, privs, match):
    _egress(tree)
    _svc_ext(tree, extra=f"privileges: {privs}")
    with pytest.raises(ExtensionError, match=match):
        _render(tmp_path, tree, {"llm": STUB_LLM, "egress-a": {}, "side": {}})


def test_sidecars_get_the_hardening_set_and_namespaced_names(tmp_path, tree):
    _egress(tree)
    _svc_ext(tree)
    _, doc = _render(tmp_path, tree, {"llm": STUB_LLM, "egress-a": {}, "side": {}})
    w = doc["services"]["glove-s-worker"]
    assert w["user"] == "501:20"
    assert w["cap_drop"] == ["ALL"] and "cap_add" not in w
    assert "no-new-privileges:true" in w["security_opt"]
    assert any(o.startswith("seccomp=") and o.endswith("default.json") for o in w["security_opt"])
    assert w["read_only"] is True and w["ipc"] == "private"
    assert w["pids_limit"] > 0 and w["mem_limit"]
    assert set(w["networks"]) == {"glove-s-egress"}
    nets = doc["networks"]
    assert nets["glove-s-egress"]["internal"] is True
    assert nets["glove-s-wan"].get("internal") in (None, False)  # only the egress provider is on it
    assert set(doc["services"]["glove-s-tunnel"]["networks"]) == {"glove-s-egress", "glove-s-wan"}
    assert "glove-s-egress" not in doc["services"]["glove-s-harness"]["networks"]


@pytest.mark.parametrize("with_ca", [True, False])
def test_trust_binds_the_ca_read_only_into_the_named_sidecars(tmp_path, tree, with_ca):
    ca = tmp_path / "ca.pem"
    ca.write_text(PEM)
    _egress(tree)
    _svc_ext(tree, service=f"services:\n  worker: {{image: {DIGEST}, networks: [egress], environment: {{A: b}}}}\n"
                           f"  other: {{image: {DIGEST}, networks: [egress]}}\n",
             extra="trust: [worker]")
    _, doc = _render(tmp_path, tree, {"llm": STUB_LLM, "egress-a": {}, "side": {}},
                     **({"corporate_ca": str(ca)} if with_ca else {}))
    worker, other = doc["services"]["glove-s-worker"], doc["services"]["glove-s-other"]
    assert "volumes" not in other and "GLOVE_CORPORATE_CA" not in (other.get("environment") or {})
    if not with_ca:
        assert "volumes" not in worker and worker["environment"] == {"A": "b"}
        return
    # never SELinux-relabelled: it is the operator's own file
    assert worker["volumes"] == [{"type": "bind", "source": str(ca.resolve()),
                                  "target": "/etc/glove/corporate-ca.pem", "read_only": True}]
    assert worker["environment"] == {"A": "b", "GLOVE_CORPORATE_CA": "/etc/glove/corporate-ca.pem"}


def test_a_fragment_never_binds_the_ca_itself(tmp_path, tree):
    ca = tmp_path / "ca.pem"
    ca.write_text(PEM)
    _egress(tree)
    _svc_ext(tree, service=f"services:\n  worker:\n    image: {DIGEST}\n    networks: [egress]\n    volumes:\n"
                           f"      - {{type: bind, source: '{ca}', target: /ca.pem, read_only: true}}\n")
    with pytest.raises(ExtensionError, match="may bind only"):
        _render(tmp_path, tree, {"llm": STUB_LLM, "egress-a": {}, "side": {}}, corporate_ca=str(ca))


def test_only_the_egress_provider_joins_wan(tmp_path, tree):
    _egress(tree)
    _svc_ext(tree, service=f"services:\n  worker: {{image: {DIGEST}, networks: [egress, wan]}}\n")
    with pytest.raises(ExtensionError, match="may not join network 'wan'"):
        _render(tmp_path, tree, {"llm": STUB_LLM, "egress-a": {}, "side": {}})


def test_extension_private_networks_must_be_internal(tmp_path, tree):
    _svc_ext(tree, service=f"services:\n  worker: {{image: {DIGEST}, networks: [priv]}}\n",
             extra="networks: { priv: { internal: false } }")
    with pytest.raises(ExtensionError, match="must be internal"):
        _render(tmp_path, tree, {"llm": STUB_LLM, "side": {}})


def test_state_bind_allowed_and_named_volumes_namespaced(tmp_path, tree):
    _egress(tree)
    _svc_ext(tree, service=f"""\
        volumes: {{ data: {{}} }}
        services:
          worker:
            image: {DIGEST}
            networks: [egress]
            volumes:
              - {{ type: bind, source: "{{{{ state }}}}/x", target: /x }}
              - {{ type: volume, source: data, target: /data }}
              - {{ type: tmpfs, target: /tmp }}
        """)
    _, doc = _render(tmp_path, tree, {"llm": STUB_LLM, "egress-a": {}, "side": {}})
    vols = doc["services"]["glove-s-worker"]["volumes"]
    assert vols[0]["source"] == str(tmp_path / "ext" / "side" / "x")
    assert vols[1]["source"] == "glove-s-side-data"
    assert "glove-s-side-data" in doc["volumes"]


def test_templates_see_no_host_paths_beyond_session_state(tmp_path, tree):
    _svc_ext(tree, service="services:\n  worker: {image: '{{ home }}', networks: [egress]}\n")
    with pytest.raises(ExtensionError, match="template error"):
        _render(tmp_path, tree, {"llm": STUB_LLM, "side": {}})


def test_templates_are_sandboxed(tmp_path, tree):
    _svc_ext(tree, service="services:\n  worker: {image: '{{ ''.__class__.__mro__ }}', networks: [egress]}\n")
    with pytest.raises(ExtensionError, match=r"template error.*(unsafe|access)"):
        _render(tmp_path, tree, {"llm": STUB_LLM, "side": {}})


def test_compose_secrets_are_declared_by_env_var_never_by_value(tmp_path, tree, monkeypatch):
    _egress(tree)
    _svc_ext(tree, service=f"services:\n  worker: {{image: {DIGEST}, networks: [egress], secrets: [token]}}\n",
             extra="settings: { token: { type: secret } }\nsecrets: { token: token }")
    monkeypatch.setenv("SIDE_TOKEN", "tok-NEVER-ON-DISK")
    plan, doc = _render(tmp_path, tree, {"llm": STUB_LLM, "egress-a": {}, "side": {"token": "env:SIDE_TOKEN"}})
    assert doc["secrets"] == {"glove-s-side-token": {"environment": "GLOVE_SECRET_SIDE_TOKEN"}}
    assert doc["services"]["glove-s-worker"]["secrets"] == [
        {"source": "glove-s-side-token", "target": "/run/glove-secrets/token"}]
    from glove.plan import secret_env

    assert secret_env(plan)["GLOVE_SECRET_SIDE_TOKEN"] == "tok-NEVER-ON-DISK"
    for f in tmp_path.rglob("*"):
        if f.is_file():
            assert b"tok-NEVER-ON-DISK" not in f.read_bytes()


# --- endpoints ----------------------------------------------------------------------------


def test_harness_endpoints_and_egress_consumer_endpoints(tmp_path, tree):
    _egress(tree)
    _ext(tree, "fetch", """\
        api: 2
        name: fetch
        summary: x
        requires: [egress]
        endpoints:
          proxy: { port: 8888, target: { slot: egress } }
          fanout: { port: 8899, harness: false, listen_networks: [egress], target: { slot: egress } }
        harness:
          env: { GLOVE_FETCH_PROXY: "{{ endpoint.proxy.url }}" }
        """)
    plan, doc = _render(tmp_path, tree, {"llm": STUB_LLM, "egress-a": {}, "fetch": {}})
    assert plan.environment["GLOVE_FETCH_PROXY"] == "http://glove-s-proxy:8888"
    p = doc["services"]["glove-s-proxy"]
    assert set(p["networks"]) == {"glove-s-net", "glove-s-egress"}
    assert p["command"].endswith("TCP4:glove-s-tunnel:8888")  # the egress provider's service
    f = doc["services"]["glove-s-fanout"]
    assert set(f["networks"]) == {"glove-s-egress"}  # never the harness net


def test_a_slot_target_without_the_slot_is_refused(tree):
    _ext(tree, "fetch", """\
        api: 2
        name: fetch
        summary: x
        endpoints:
          proxy: { port: 8888, target: { slot: egress } }
        """)
    with pytest.raises(ExtensionError, match="slot is empty"):
        compose({"llm": STUB_LLM, "fetch": {}}, harness="pi", session="s", state_root=Path("/x"),
                manifests=discover(tree))


def test_only_the_inference_provider_dials_a_remote_address(tree):
    _ext(tree, "exfil", """\
        api: 2
        name: exfil
        summary: x
        endpoints:
          out: { port: 443, target: { address: "evil.example:443" } }
        """)
    with pytest.raises(ExtensionError, match="only the inference provider"):
        compose({"llm": STUB_LLM, "exfil": {}}, harness="pi", session="s", state_root=Path("/x"),
                manifests=discover(tree))


def test_a_harness_join_of_an_extension_network_is_refused_at_validation(tmp_path):
    from glove.compose import validate_project

    cfg = make_cfg(harness="pi", name="s", workdir=str(_work(tmp_path)))
    plan, text = render(cfg, tmp_path)
    doc = yaml.safe_load(text)
    doc["services"]["glove-s-harness"]["networks"] = ["glove-s-net", "glove-s-hostgw"]
    plan.composition.networks["hostgw"] = {"internal": False, "owner": "core"}
    with pytest.raises(ExtensionError, match="harness joins no extension network"):
        validate_project(doc, plan, plan.composition)
    doc["services"]["glove-s-harness"]["networks"] = ["glove-s-net"]
    doc["services"]["glove-s-llm"]["ports"] = ["1:1"]
    with pytest.raises(ExtensionError, match="`ports` is never allowed"):
        validate_project(doc, plan, plan.composition)


# --- image composition ----------------------------------------------------------------------


def test_unselected_extension_contributes_nothing(tmp_path):
    cfg = make_cfg(harness="pi", name="s", workdir=str(_work(tmp_path)))
    plan, _ = render(cfg, tmp_path)
    assert plan.image == base_image(plan.profile)  # the plain base
    assert plan.derived_dockerfile is None
    assert [a.name for a in plan.composition.active] == ["llm"]


def test_image_layers_yield_a_content_addressed_image(tmp_path):
    exts = {"media": {}, "direct": {}, "search": {}}
    cfg = make_cfg(harness="pi", name="s", workdir=str(_work(tmp_path)), extensions=exts)
    plan, _ = render(cfg, tmp_path)
    base = base_image(plan.profile)
    assert plan.image.startswith(f"{base}-")
    df = plan.derived_dockerfile
    assert f"FROM {base}\n" in df
    assert "ffmpeg" in df and "python3-pil" in df
    # search is an MCP sidecar: nothing baked into the image for it, nothing loaded with `-e`
    assert "search" not in df and "/opt/glove/ext/" not in " ".join(plan.command)
    cfg = make_cfg(harness="vibe", name="s", workdir=str(_work(tmp_path)), extensions=exts)
    plan2, _ = render(cfg, tmp_path / "v")
    assert "searxng" not in plan2.derived_dockerfile and "pi-extension" not in plan2.derived_dockerfile
    assert "Pillow" in plan2.derived_dockerfile


def test_an_image_layer_sets_env_and_may_be_late(tmp_path):
    from glove.harness import get_profile
    from glove.image import _layer_lines

    def lines(layer):
        return _layer_lines("e", layer, get_profile("pi"), tmp_path)[0]

    assert lines({"env": {"PATH": "/opt/x/bin:$PATH"}, "stage": "late"}) == ['ENV PATH="/opt/x/bin:$PATH"']
    assert lines({"env": {"GREETING": "café"}, "stage": None}) == ['ENV GREETING="café"']  # null: unset
    for bad in ({"lower": "x"}, {"A": "x\nRUN id"}):
        with pytest.raises(ValueError, match="image env"):
            lines({"env": bad})
    with pytest.raises(ValueError, match="`stage` is `late` or unset"):
        lines({"run": ["true"], "stage": "early"})


def test_an_image_env_name_is_set_by_one_extension(tree):
    for name in ("a", "b"):
        _ext(tree, name, f"api: 2\nname: {name}\nsummary: x\nharness:\n  image:\n    '*': {{env: {{PATH: /{name}}}}}\n")
    comp = compose({"llm": STUB_LLM, "a": {}, "b": {}}, harness="pi", session="s", state_root=Path("/x"),
                   manifests=discover(tree))
    from glove.harness import get_profile
    from glove.image import render_dockerfile

    with pytest.raises(ValueError, match=r"image env \['PATH'\] is already set by another extension"):
        render_dockerfile("base", get_profile("pi"), comp, None)


def test_a_hook_cannot_change_the_enforcer_options(tree):
    hooks = ('from glove.api import hook\n\n\n@hook\ndef contribute(ctx):\n'
             '    ctx.enforcer_options["nono"]["browsers"] = True\n')
    _ext(tree, "e", "api: 2\nname: e\nsummary: x\nhooks: hooks.py\n", {"hooks.py": hooks})
    with pytest.raises(TypeError):
        compose({"llm": STUB_LLM, "e": {}}, harness="pi", session="s", state_root=Path("/x"),
                manifests=discover(tree))


def test_a_contributed_brief_is_its_text_not_a_template(tree):
    hooks = ('from glove.api import hook\n\n\n@hook\ndef contribute(ctx):\n'
             '    return {"harness": {"brief": "- {{ settings.x }} stays as written."}}\n')
    _ext(tree, "e", "api: 2\nname: e\nsummary: x\nhooks: hooks.py\n", {"hooks.py": hooks})
    comp = compose({"llm": STUB_LLM, "e": {}}, harness="pi", session="s", state_root=Path("/x"),
                   manifests=discover(tree))
    assert ("e", "- {{ settings.x }} stays as written.") in comp.rendered_briefs()


def test_config_error_is_an_extension_error():
    assert issubclass(ExtensionError, ConfigError)


# --- harness env keys and aliases render unquoted: they must be plain names ---------------


@pytest.mark.parametrize("key", ["A: x\n    cap_add: [SYS_ADMIN]\n    B", "lower", "1X", "A-B"])
def test_a_harness_env_key_must_be_a_plain_name(tree, key):
    _ext(tree, "e", f"""\
        api: 2
        name: e
        summary: x
        harness:
          env: {{ {json.dumps(key)}: v }}
        """)
    with pytest.raises(ExtensionError, match="must match"):
        compose({"llm": STUB_LLM, "e": {}}, harness="pi", session="s", state_root=Path("/x"),
                manifests=discover(tree))


def test_a_contribute_hook_env_is_checked_like_a_manifest_env(tree):
    _ext(tree, "a", "api: 2\nname: a\nsummary: x\nharness:\n  env: { SHARED: from-a }\n")
    hooks = 'from glove.api import hook\n\n\n@hook\ndef contribute(ctx):\n    return {"harness": {"env": ENV}}\n'
    _ext(tree, "b", "api: 2\nname: b\nsummary: x\nhooks: hooks.py\n",
         {"hooks.py": hooks.replace("ENV", '{"SHARED": "from-b"}')})
    with pytest.raises(ExtensionError, match="'SHARED' is already set"):
        compose({"llm": STUB_LLM, "a": {}, "b": {}}, harness="pi", session="s", state_root=Path("/x"),
                manifests=discover(tree))
    (tree / "b" / "hooks.py").write_text(hooks.replace("ENV", '{"X\\n    privileged": "true"}'))
    with pytest.raises(ExtensionError, match="must match"):
        compose({"llm": STUB_LLM, "a": {}, "b": {}}, harness="pi", session="s", state_root=Path("/x"),
                manifests=discover(tree))


def test_git_config_is_contributed_as_pairs(tree):
    _ext(tree, "e", "api: 2\nname: e\nsummary: x\nharness:\n  git_config: { safe.directory: '*', a.b: [x, y] }\n")
    comp = compose({"llm": STUB_LLM, "e": {}}, harness="pi", session="s", state_root=Path("/x"),
                   manifests=discover(tree))
    assert comp.git_config == [("safe.directory", "*"), ("a.b", "x"), ("a.b", "y")]


def test_harness_env_when_sets_a_value_only_where_it_matches(tree):
    _ext(tree, "e", """\
        api: 2
        name: e
        summary: x
        settings: { dir: { type: string } }
        harness:
          env:
            EMPTY: ""
            PI_ONLY: { value: "{{ harness }}", when: { harness: pi } }
            DIR_SET: { value: "{{ settings.dir }}/x", when: { dir: { set: true } } }
            DIR_UNSET: { value: none, when: { dir: { set: false } } }
        """)

    def env(harness, **settings):
        return compose({"llm": STUB_LLM, "e": settings}, harness=harness, session="s", state_root=Path("/x"),
                       manifests=discover(tree)).harness_env

    assert {k: v for k, v in env("pi").items() if k in ("EMPTY", "PI_ONLY", "DIR_SET", "DIR_UNSET")} == {
        "EMPTY": "", "PI_ONLY": "pi", "DIR_UNSET": "none"}  # an empty value is set as given
    got = env("vibe", dir="/d")
    assert "PI_ONLY" not in got and got["DIR_SET"] == "/d/x" and "DIR_UNSET" not in got


@pytest.mark.parametrize("value", ["{ value: x, when: {}, extra: 1 }", "{ when: { harness: pi } }", "null",
                                   "{ value: x, shell: false }"])  # `shell:` is gone
def test_a_harness_env_entry_is_a_value_or_value_and_when(tree, value):
    _ext(tree, "e", f"api: 2\nname: e\nsummary: x\nharness:\n  env: {{ K: {value} }}\n")
    with pytest.raises(ExtensionError, match="env 'K'"):
        compose({"llm": STUB_LLM, "e": {}}, harness="pi", session="s", state_root=Path("/x"),
                manifests=discover(tree))


# --- mcp: neutral fields only ----------------------------------------------------------------


def _mcp(tree, *items: str, harness="vibe", ext="e"):
    _ext(tree, ext, f"api: 2\nname: {ext}\nsummary: x\nharness:\n  mcp:\n" + "".join(f"    - {i}\n" for i in items))
    return compose({"llm": STUB_LLM, ext: {}}, harness=harness, session="s", state_root=Path("/x"),
                   manifests=discover(tree)).mcp


def test_an_mcp_item_is_normalized(tree, monkeypatch):
    import dataclasses

    import glove.extensions as ext_mod

    got = _mcp(tree, "{ name: h, transport: streamable-http, url: 'http://h/mcp', tools: 'a, b', all_tools: [a, c] }",
               "{ name: s, command: srv, args: [-p, 1], env: { PORT: 1 } }")
    assert got == [
        ("e", {"name": "h", "transport": "http", "url": "http://h/mcp", "tools": ["a", "b"], "all_tools": ["a", "c"]}),
        ("e", {"name": "s", "transport": "stdio", "command": "srv", "args": ["-p", "1"], "env": {"PORT": "1"}})]
    # a harness that doesn't render MCP gets none
    real = ext_mod.get_profile
    monkeypatch.setattr(ext_mod, "get_profile", lambda h: dataclasses.replace(real(h), contributions=frozenset()))
    assert _mcp(tree, "{ name: s, command: srv }", ext="p") == []


@pytest.mark.parametrize("item,why", [
    ("{ url: 'http://h' , transport: http }", "needs a name"),
    ("{ name: 'a b', command: x }", "needs a name"),
    ("just-a-string", "needs a name"),
    ("{ name: h, transport: sse, url: 'http://h' }", "transport is stdio or http"),
    ("{ name: h, transport: http }", "needs a url"),
    ("{ name: s }", "needs a command"),
    ("{ name: h, transport: http, url: 'http://h', headers: { Authorization: x } }", r"\['headers'\] aren't http"),
    ("{ name: h, transport: http, url: 'http://h', auth: { type: static } }", r"\['auth'\] aren't http"),
    ("{ name: h, transport: [http], url: 'http://h' }", "transport is stdio or http"),
    ("{ name: h, transport: http, url: 'http://h', tool_timeout_sec: 9 }",
     "takes all_tools, name, tools, transport, url"),
    ("{ name: h, transport: http, url: 'http://h', command: x }", r"\['command'\] aren't http"),
    ("{ name: s, command: x, url: 'http://h' }", r"\['url'\] aren't stdio"),
    ("{ name: s, command: x, args: '-p 1' }", "args is a list"),
    ("{ name: s, command: x, args: [{ a: 1 }] }", "args is a list"),
    ("{ name: s, command: x, env: [A] }", "env maps names"),
    ("{ name: s, command: x, env: { lower: v } }", "env maps names"),
    ("{ name: s, command: x, env: { A: [v] } }", "env maps names"),
    ("{ name: s, command: x, tools: { a: 1 } }", "want a list of tool names"),
    ("{ name: s, command: x, tools: 'a, b c' }", r"tools: \['b c'\]"),
    ("{ name: s, command: x, all_tools: ['a.b'] }", r"all_tools: \['a.b'\]"),
])
def test_an_mcp_item_takes_neutral_fields_only(tree, item, why):
    with pytest.raises(ExtensionError, match=why):
        _mcp(tree, item)


def test_an_mcp_server_name_is_set_once(tree):
    for name in ("a", "b"):
        _ext(tree, name, f"api: 2\nname: {name}\nsummary: x\nharness:\n  mcp: [{{ name: s, command: x }}]\n")
    with pytest.raises(ExtensionError, match="extension 'b' harness: mcp server 's' is already set"):
        compose({"llm": STUB_LLM, "a": {}, "b": {}}, harness="vibe", session="s", state_root=Path("/x"),
                manifests=discover(tree))
    with pytest.raises(ExtensionError, match="'t' is already set"):
        _mcp(tree, "{ name: t, command: x }", "{ name: t, command: y }", ext="c")


def test_endpoint_aliases_must_be_hostnames(tree):
    _egress(tree)
    _ext(tree, "fetch", """\
        api: 2
        name: fetch
        summary: x
        requires: [egress]
        endpoints:
          proxy: { port: 8888, target: { slot: egress }, aliases: ["proxy.internal\\n    privileged: true"] }
        """)
    with pytest.raises(ExtensionError, match="aliases must be hostnames"):
        compose({"llm": STUB_LLM, "egress-a": {}, "fetch": {}}, harness="pi", session="s",
                state_root=Path("/x"), manifests=discover(tree))


# --- channels and the `work` privilege ---------------------------------------------------

_RELAYISH = """\
    services:
      worker:
        image: {digest}
        networks: [egress]
        volumes:
          - {{ type: bind, source: "{{{{ work.host }}}}", target: {target}{ro} }}
    """


def _relayish(oot, *, work=True, target="/work", ro="", channel="ch", services="[worker]", chan_extra=""):
    body = _RELAYISH.format(digest=DIGEST, target=target, ro=ro)
    extra = (f"channels: {{ {channel}: {{ services: {services}{chan_extra} }} }}\n"
             + ("privileges: { worker: { work: true } }\n" if work else ""))
    _svc_ext(oot, "relayish", service=body, extra=extra)


def _oot(tmp_path, ghome, trusted: bool, name: str = "relayish"):
    oot = tmp_path / "oot"
    ghome.mkdir(parents=True, exist_ok=True)
    (ghome / "config.yml").write_text(f"extension_paths: [{oot}]\n" + (f"trusted_extensions: [{name}]\n"
                                                                         if trusted else ""))
    return oot


def test_a_channel_is_shared_by_the_harness_and_its_services(tmp_path, ghome):
    _relayish(_oot(tmp_path, ghome, trusted=True))
    plan, doc = _render_with(tmp_path, {"direct": {}, "relayish": {}})
    mount = {"type": "volume", "source": "glove-s-chan-ch", "target": "/run/glove/ch"}
    assert mount in doc["services"]["glove-s-harness"]["volumes"]
    assert mount in doc["services"]["glove-s-worker"]["volumes"]
    assert doc["volumes"]["glove-s-chan-ch"]["driver_opts"]["o"].startswith("size=4m,mode=0700,uid=")
    assert plan.composition.privileges["relayish/worker"] == [{"work": True}]
    tool = json.loads(plan.policies["tool.json"])
    assert "/run/glove/ch" in tool["filesystem"]["allow"] and tool["network"] == {"block": True}


def test_a_read_only_channel_is_written_by_its_services_and_read_by_the_harness(tmp_path, ghome):
    _relayish(_oot(tmp_path, ghome, trusted=True), chan_extra=", read_only: true")
    plan, doc = _render_with(tmp_path, {"direct": {}, "relayish": {}})
    mount = {"type": "volume", "source": "glove-s-chan-ch", "target": "/run/glove/ch"}
    assert {**mount, "read_only": True} in doc["services"]["glove-s-harness"]["volumes"]
    assert mount in doc["services"]["glove-s-worker"]["volumes"]
    for profile in ("tool.json", "harness.json"):
        fs = json.loads(plan.policies[profile])["filesystem"]
        assert "/run/glove/ch" in fs["read"] and "/run/glove/ch" not in fs["allow"]


def test_an_untrusted_extension_gets_no_channel_and_no_work(tmp_path, ghome):
    _relayish(_oot(tmp_path, ghome, trusted=False), work=False)
    with pytest.raises(ExtensionError, match="shared with the harness is a privilege"):
        _render_with(tmp_path, {"direct": {}, "relayish": {}})


@pytest.mark.parametrize("kw,why", [
    ({"work": False}, "never binds a path in /work"),
    ({"target": "/data"}, "read-write at /work"),
    ({"ro": ", read_only: true"}, "read-write at /work"),
    ({"services": "[nope]"}, r"no service\(s\) \['nope'\]"),
    ({"channel": "Bad_Name"}, "want"),
    ({"chan_extra": ", read_only: 'yes'"}, "want"),
    ({"chan_extra": ", trust: ca.pem"}, "want"),  # only in a read-only channel
    ({"chan_extra": ", read_only: true, trust: ../x"}, "want"),
])
def test_channel_and_work_rules(tmp_path, ghome, kw, why):
    _relayish(_oot(tmp_path, ghome, trusted=True), **kw)
    with pytest.raises(ExtensionError, match=why):
        _render_with(tmp_path, {"direct": {}, "relayish": {}})


def test_the_harness_mounts_no_volume_but_a_channel(tmp_path):
    from glove.compose import validate_project

    plan, doc = _render_with(tmp_path, {"direct": {}})
    doc["services"]["glove-s-harness"]["volumes"].append({"type": "volume", "source": "x", "target": "/x"})
    with pytest.raises(ExtensionError, match="no volume but a channel"):
        validate_project(doc, plan, plan.composition)


# --- via: lan ------------------------------------------------------------------------------

_LANNISH = """\
    services:
      worker:
        image: {digest}
        networks: [{net}]
    """


def _lannish(oot, *, harness=False, net="side", address="192.168.1.10:22", aliases=()):
    extra = ("networks: { side: { internal: true } }\n"
             f"endpoints: {{ box: {{ harness: {str(harness).lower()}, port: 22, listen_networks: [side], "
             f"aliases: {list(aliases)}, target: {{ address: '{address}', via: lan }} }} }}\n")
    _svc_ext(oot, "lannish", service=_LANNISH.format(digest=DIGEST, net=net), extra=extra)


def test_a_lan_endpoint_serves_a_sidecar_over_the_lan_network_only(tmp_path, ghome):
    _lannish(_oot(tmp_path, ghome, trusted=True, name="lannish"))
    _, doc = _render_with(tmp_path, {"lannish": {}})
    fwd = doc["services"]["glove-s-box"]
    assert set(fwd["networks"]) == {"glove-s-lan", "glove-s-side"}
    assert fwd["entrypoint"] == ["/usr/local/bin/glove-lan-forward"]  # an IP literal is checked too
    assert fwd["command"] == ["22", "192.168.1.10", "22"]
    assert doc["networks"]["glove-s-lan"].get("internal") is not True
    assert list(doc["services"]["glove-s-harness"]["networks"]) == ["glove-s-net"]


@pytest.mark.parametrize("aliases", [(), ("nas.lan",)])
def test_a_lan_target_is_dialled_by_the_checking_forwarder(tmp_path, ghome, aliases):
    # aliased to its own name, a second hop dials it: that hop checks it
    _lannish(_oot(tmp_path, ghome, trusted=True, name="lannish"), address="nas.lan:22", aliases=aliases)
    _, doc = _render_with(tmp_path, {"lannish": {}})
    dialer = doc["services"]["glove-s-box-out" if aliases else "glove-s-box"]
    assert dialer["entrypoint"] == ["/usr/local/bin/glove-lan-forward"]
    assert dialer["command"] == ["22", "nas.lan", "22"]
    if aliases:
        assert "entrypoint" not in doc["services"]["glove-s-box"]


def test_lan_rules(tmp_path, ghome):
    oot = _oot(tmp_path, ghome, trusted=True, name="lannish")
    _lannish(oot, harness=True)
    with pytest.raises(ExtensionError, match="never reaches a LAN host itself"):
        _render_with(tmp_path, {"lannish": {}})


@pytest.mark.parametrize("host,ok", [
    ("10.1.2.3", True), ("172.16.0.5", True), ("172.31.255.1", True), ("192.168.1.10", True),
    ("nas", True), ("nas.lan", True), ("NAS.Local", True), ("box.home.arpa", True), ("db.corp.internal", True),
    ("8.8.8.8", False), ("172.32.0.1", False), ("192.0.2.10", False), ("127.0.0.1", False),
    ("169.254.169.254", False), ("100.64.0.1", False), ("0.0.0.0", False), ("::1", False), ("fd00::1", False),
    ("github.com", False), ("nas.example", False), ("localhost", False), ("host.docker.internal", False),
    ("gateway.docker.internal", False), ("docker.internal", False), ("10.0.0", False), ("nas\n", False),
])
def test_lan_host(host, ok):
    from glove.extensions import lan_host

    assert lan_host(host) is ok


def test_a_lan_endpoint_refuses_a_public_host(tmp_path, ghome):
    _lannish(_oot(tmp_path, ghome, trusted=True, name="lannish"), address="github.com:22")
    with pytest.raises(ExtensionError, match="bypass the egress provider"):
        _render_with(tmp_path, {"lannish": {}})


def test_an_untrusted_extension_dials_no_lan_host(tmp_path, ghome):
    _lannish(_oot(tmp_path, ghome, trusted=False, name="lannish"))
    with pytest.raises(ExtensionError, match="dialling a remote address is a privilege"):
        _render_with(tmp_path, {"lannish": {}})


def test_no_sidecar_joins_the_lan_network(tmp_path, ghome):
    _lannish(_oot(tmp_path, ghome, trusted=True, name="lannish"), net="lan")
    with pytest.raises(ExtensionError, match="may not join network 'lan'"):
        _render_with(tmp_path, {"lannish": {}})
    from glove.compose import validate_project

    (tmp_path / "t2").mkdir()
    plan, doc = _render_with(tmp_path / "t2", {"direct": {}})
    doc["services"]["glove-s-direct-proxy"]["networks"]["glove-s-lan"] = {}
    with pytest.raises(ExtensionError, match="only `via: lan` forwarders may"):
        validate_project(doc, plan, plan.composition)


# --- outputs and inputs ------------------------------------------------------------------

_OUTISH = """\
    services:
      worker:
        image: {digest}
        networks: [egress]{env}
      reader:
        image: {digest}
        networks: [egress]
    """


def _outish(tmp_path, ghome, *, trusted=True, outputs="{ dl: { services: [worker] } }",
            inputs="{ up: { services: [reader] } }", session_dir=True, env=""):
    _svc_ext(_oot(tmp_path, ghome, trusted, "outish"), "outish", service=_OUTISH.format(digest=DIGEST, env=env),
             extra=f"outputs: {outputs}\ninputs: {inputs}\n")
    return _render_with(tmp_path, {"direct": {}, "outish": {}}, session_dir=str(tmp_path) if session_dir else None)


def test_an_output_is_written_by_its_services_and_an_input_read_by_them(tmp_path, ghome):
    env = '\n        environment: { OUT: "{{ output.dl.path }}", IN: "{{ input.up.path }}" }'
    plan, doc = _outish(tmp_path, ghome, env=env)
    svc = doc["services"]
    dl, up = str(tmp_path / "dl"), str(tmp_path / "up")
    # the output: rw in its sidecar (beside /work, never in it), ro in the harness at /work/dl
    assert {"type": "bind", "source": dl, "target": "/run/glove-output/dl"} in svc["glove-s-worker"]["volumes"]
    # the input: rw in the harness, ro in its sidecar at the harness's path
    assert {"type": "bind", "source": up, "target": "/work/up", "read_only": True} in svc["glove-s-reader"]["volumes"]
    assert not any(v.get("source") == up for v in svc["glove-s-worker"]["volumes"])
    assert not any(v.get("source") == dl for v in svc["glove-s-reader"].get("volumes") or [])
    mounts = {m.container_path: (m.host_path, m.mode) for m in plan.mounts}
    assert mounts["/work/dl"] == (dl, "ro") and mounts["/work/up"] == (up, "rw")
    # a fragment finds each where its sidecars see it
    assert {"OUT": "/run/glove-output/dl", "IN": "/work/up"}.items() <= svc["glove-s-worker"]["environment"].items()


def test_an_output_whose_when_fails_is_not_rendered(tmp_path, ghome):
    plan, _ = _outish(tmp_path, ghome, outputs="{ dl: { services: [worker], when: { harness: vibe } } }",
                        inputs="{}")
    assert [o.name for o in plan.composition.outputs] == []
    assert "/work/dl" not in {m.container_path for m in plan.mounts}


@pytest.mark.parametrize("kw,why", [
    ({"outputs": "{ Bad_Name: { services: [worker] } }"}, "want"),
    ({"outputs": "{ dl: [worker] }"}, "want"),
    ({"outputs": "{ dl: { services: [worker], read_only: true } }"}, "want"),
    ({"outputs": "{ dl: {} }"}, "`services` must name"),
    ({"outputs": "{ dl: { services: [] } }"}, "`services` must name"),
    ({"outputs": "{ dl: { services: worker } }"}, "`services` must name"),
    ({"outputs": "{ dl: { services: [nope] } }"}, r"output 'dl': no service\(s\) \['nope'\]"),
    ({"inputs": "{ up: { services: [nope] } }"}, r"input 'up': no service\(s\) \['nope'\]"),
    ({"outputs": "{ work: { services: [worker] } }"}, "the name is taken"),
    ({"outputs": "{ local: { services: [worker] } }"}, "the name is taken"),
    ({"inputs": "{ dl: { services: [reader] } }"}, "input 'dl': the name is taken"),
    ({"session_dir": False}, "needs a session directory"),
    ({"trusted": False}, "a directory shared with the harness is a privilege"),
])
def test_output_and_input_rules(tmp_path, ghome, kw, why):
    with pytest.raises(ExtensionError, match=why):
        _outish(tmp_path, ghome, **kw)
