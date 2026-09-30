"""Extension API (api: 1): manifests, settings, slots, composition and the
§3.4 invariants core enforces on every extension fragment."""

from __future__ import annotations

import json
import re
import textwrap
from pathlib import Path

import pytest
import yaml
from helpers import STUB_LLM, make_cfg, render

from glove.config import ConfigError
from glove.extensions import IN_TREE_DIR, ExtensionError, compose, discover, select, when_matches

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
    manifest = f"api: 1\nname: {name}\nsummary: test\nprovides: {provides}\nservices: services.yml\n{extra}\n"
    return _ext(root, name, manifest, {"services.yml": body})


def _egress(root, name="egress-a"):
    return _ext(root, name, f"""\
        api: 1
        name: {name}
        summary: test egress
        provides: [egress]
        exports: {{ proxy_host: "glove-{{{{ session.id }}}}-tunnel", proxy_port: 8888, route: direct, network: egress }}
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
    _ext(tree, "bad", "api: 1\nname: bad\nsummary: x\nprivileged: true\n")
    with pytest.raises(ExtensionError, match="unknown manifest keys"):
        discover(tree)


def test_manifest_rejects_wrong_api(tree):
    _ext(tree, "old", "api: 2\nname: old\nsummary: x\n")
    with pytest.raises(ExtensionError, match="api must be 1"):
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
    _ext(tree, "needs-egress", "api: 1\nname: needs-egress\nsummary: x\nrequires: [egress]\n")
    _ext(tree, "needs-lib", "api: 1\nname: needs-lib\nsummary: x\nrequires: [lib]\n")
    _ext(tree, "lib", "api: 1\nname: lib\nsummary: x\nauto: true\nselectable: false\n")
    _ext(tree, "plain", "api: 1\nname: plain\nsummary: x\n")
    _ext(tree, "needs-plain", "api: 1\nname: needs-plain\nsummary: x\nrequires: [plain]\n")
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


def test_conflicts_and_validate_rules(tree):
    _ext(tree, "a", "api: 1\nname: a\nsummary: x\nconflicts: [b]\n")
    _ext(tree, "b", "api: 1\nname: b\nsummary: x\n")
    m = discover(tree)
    with pytest.raises(ExtensionError, match="conflicts with 'b'"):
        select({"llm": STUB_LLM, "a": {}, "b": {}}, harness="pi", manifests=m)


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
             "exports: { proxy_host: x, proxy_port: 1, network: egress }")
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


def _render_with(tmp_path, extensions):
    tmp_path.mkdir(parents=True, exist_ok=True)
    cfg = make_cfg(harness="pi", name="s", workdir=str(_work(tmp_path)), extensions=extensions)
    plan, text = render(cfg, tmp_path)
    return plan, yaml.safe_load(text)


def test_out_of_tree_cannot_shadow_in_tree(tmp_path, ghome):
    oot = tmp_path / "oot"
    _ext(oot, "llm", "api: 1\nname: llm\nsummary: evil\nprovides: [inference]\n")
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
        api: 1
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
        api: 1
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
        api: 1
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
    assert plan.image == "glove/pi:0.5.0"  # the plain base
    assert plan.derived_dockerfile is None
    assert [a.name for a in plan.composition.active] == ["llm"]


def test_image_layers_and_pi_extensions_yield_a_content_addressed_image(tmp_path):
    exts = {"media": {}, "direct": {}, "search": {}}
    cfg = make_cfg(harness="pi", name="s", workdir=str(_work(tmp_path)), extensions=exts)
    plan, _ = render(cfg, tmp_path)
    assert plan.image.startswith("glove/pi:0.5.0-") and plan.image != "glove/pi:0.5.0"
    df = plan.derived_dockerfile
    assert "FROM glove/pi:0.5.0" in df
    assert "ffmpeg" in df and "python3-pil" in df
    assert "COPY search/pi-extension /opt/glove/ext/search/pi-extension" in df
    assert "-e" in plan.command and "/opt/glove/ext/search/pi-extension" in plan.command
    # vibe gets the MCP server + pip layer, not the Pi extension
    cfg = make_cfg(harness="vibe", name="s", workdir=str(_work(tmp_path)), extensions=exts)
    plan2, _ = render(cfg, tmp_path / "v")
    assert "mcp<2" in plan2.derived_dockerfile and "pi-extension" not in plan2.derived_dockerfile
    assert "Pillow" in plan2.derived_dockerfile


def test_config_error_is_an_extension_error():
    assert issubclass(ExtensionError, ConfigError)


# --- harness env keys and aliases render unquoted: they must be plain names ---------------


@pytest.mark.parametrize("key", ["A: x\n    cap_add: [SYS_ADMIN]\n    B", "lower", "1X", "A-B"])
def test_a_harness_env_key_must_be_a_plain_name(tree, key):
    _ext(tree, "e", f"""\
        api: 1
        name: e
        summary: x
        harness:
          env: {{ {json.dumps(key)}: v }}
        """)
    with pytest.raises(ExtensionError, match="must match"):
        compose({"llm": STUB_LLM, "e": {}}, harness="pi", session="s", state_root=Path("/x"),
                manifests=discover(tree))


def test_a_contribute_hook_env_is_checked_like_a_manifest_env(tree):
    _ext(tree, "a", "api: 1\nname: a\nsummary: x\nharness:\n  env: { SHARED: from-a }\n")
    hooks = 'def contribute(ctx):\n    return {"env": ENV}\n'
    _ext(tree, "b", "api: 1\nname: b\nsummary: x\nhooks: hooks.py\n",
         {"hooks.py": hooks.replace("ENV", '{"SHARED": "from-b"}')})
    with pytest.raises(ExtensionError, match="'SHARED' is already set"):
        compose({"llm": STUB_LLM, "a": {}, "b": {}}, harness="pi", session="s", state_root=Path("/x"),
                manifests=discover(tree))
    (tree / "b" / "hooks.py").write_text(hooks.replace("ENV", '{"X\\n    privileged": "true"}'))
    with pytest.raises(ExtensionError, match="must match"):
        compose({"llm": STUB_LLM, "a": {}, "b": {}}, harness="pi", session="s", state_root=Path("/x"),
                manifests=discover(tree))


def test_endpoint_aliases_must_be_hostnames(tree):
    _egress(tree)
    _ext(tree, "fetch", """\
        api: 1
        name: fetch
        summary: x
        requires: [egress]
        endpoints:
          proxy: { port: 8888, target: { slot: egress }, aliases: ["proxy.internal\\n    privileged: true"] }
        """)
    with pytest.raises(ExtensionError, match="aliases must be hostnames"):
        compose({"llm": STUB_LLM, "egress-a": {}, "fetch": {}}, harness="pi", session="s",
                state_root=Path("/x"), manifests=discover(tree))
