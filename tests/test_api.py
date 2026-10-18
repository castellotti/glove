"""The `api: 2` extension interface: `@hook` and `call_hook` (glove/hooks.py),
what a hook may return and see, the slot-export schemas (glove/manifest.py),
`ext_session`/`reload_sidecar` (glove/extsession.py), and that
docs/extensions.md names each of them."""

from __future__ import annotations

import dataclasses
import shutil
import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from helpers import STUB_LLM, make_session

import glove.api
from glove.api import ExtSession, ext_session, hook, reload_sidecar
from glove.extensions import (
    IN_TREE_DIR,
    Active,
    Manifest,
    call_hook,
    compose,
    declares_host_paths,
    discover,
    hook_context,
    load_module,
)
from glove.hooks import HOOKS, validate_result
from glove.manifest import KEYS, SLOT_EXPORTS, ExtensionError, check_slot_exports

MARKED = "from glove.api import hook\n\n\n@hook\n"


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "exts"
    root.mkdir()
    shutil.copytree(IN_TREE_DIR / "llm", root / "llm", ignore=shutil.ignore_patterns("tests", "__pycache__"))
    return root


def _ext(tree: Path, name: str, manifest: str = "", hooks: str | None = None) -> None:
    d = tree / name
    d.mkdir()
    head = f"api: 2\nname: {name}\nsummary: x\n" + ("hooks: hooks.py\n" if hooks is not None else "")
    (d / "extension.yml").write_text(head + textwrap.dedent(manifest))
    if hooks is not None:
        (d / "hooks.py").write_text(textwrap.dedent(hooks))


def _compose(tree: Path, *names: str, harness: str = "pi", **kw):
    return compose({"llm": STUB_LLM, **{n: {} for n in names}}, harness=harness, session="s",
                   state_root=Path("/x"), manifests=discover(tree), **kw)


# --- @hook and call_hook ----------------------------------------------------------


def test_hook_on_an_unknown_name_fails_at_import():
    def contribte(ctx):
        return {}

    with pytest.raises(TypeError, match="'contribte' is not a hook glove calls"):
        hook(contribte)


def test_a_hook_without_its_mark_is_refused(tree):
    _ext(tree, "h", hooks="def contribute(ctx):\n    return {}\n")
    with pytest.raises(ExtensionError, match=r"\['contribute'\] not marked @hook"):
        _compose(tree, "h")


def test_one_marked_hook_does_not_excuse_another_unmarked_one(tree):
    _ext(tree, "h", hooks=MARKED + "def contribute(ctx):\n    return {}\n\n\ndef launch_env(ctx, r):\n    return {}\n")
    with pytest.raises(ExtensionError, match=r"\['launch_env'\] not marked @hook"):
        _compose(tree, "h")
    (tree / "h" / "hooks.py").write_text(MARKED + "def contribute(ctx):\n    return {}\n\n\ndef helper():\n    1 / 0\n")
    assert set(_compose(tree, "h").by_name("h").hooks) == {"contribute"}


def test_an_unselected_extensions_hook_never_runs(tree):
    comp = _compose(tree)
    called = []
    stranger = Active(discover(tree)["llm"], {}, hooks={"contribute": lambda ctx: called.append(ctx) or {}})
    with pytest.raises(ExtensionError, match="'llm' is not selected"):
        call_hook(comp, stranger, "contribute")
    assert not called


def test_a_hooks_value_error_names_the_extension_and_hook_and_a_bug_says_where(tree):
    _ext(tree, "h", hooks=MARKED + "def contribute(ctx):\n    raise ValueError('boom')\n")
    with pytest.raises(ExtensionError, match=r"^extension 'h': contribute: boom$"):
        _compose(tree, "h")
    (tree / "h" / "hooks.py").write_text(MARKED + "def contribute(ctx):\n    return {}[1]\n")
    with pytest.raises(KeyError) as e:
        _compose(tree, "h")
    assert "(in the contribute hook of extension 'h')" in e.value.__notes__


# --- results ------------------------------------------------------------------------


@pytest.mark.parametrize(("out", "match"), [
    ("{'bogus': 1}", "'bogus' is not a key a hook may return"),
    ("{'verify': {}}", "'verify' must be a list"),
    ("{'exports': []}", "'exports' must be a dict"),
    ("{'harness': {'brief': 'b.md'}}", "harness takes"),
    ("[]", "must return a mapping"),
])
def test_a_contribution_has_known_keys_of_their_types(tree, out, match):
    _ext(tree, "h", hooks=MARKED + f"def contribute(ctx):\n    return {out}\n")
    with pytest.raises(ExtensionError, match=match):
        _compose(tree, "h")


def test_a_name_both_the_manifest_and_the_hook_set_is_refused(tree):
    _ext(tree, "h", "exports: { a: 1 }\n", MARKED + "def contribute(ctx):\n    return {'exports': {'a': 2}}\n")
    with pytest.raises(ExtensionError, match=r"exports: \['a'\] set by both the manifest and the contribute hook"):
        _compose(tree, "h")


def test_a_manifest_entry_its_when_excludes_leaves_the_name_to_the_hook(tree):
    # playwright's case: `browser` is the manifest's in sidecar mode, its hook's in host mode
    _ext(tree, "h", "endpoints:\n  e: { target: { host_port: 1 }, when: { harness: vibe } }\n",
         MARKED + "def contribute(ctx):\n    return {'endpoints': {'e': {'target': {'host_port': 2}}}}\n")
    assert next(e for e in _compose(tree, "h").endpoints if e.name == "e").target.port == 2
    with pytest.raises(ExtensionError, match="set by both"):
        _compose(tree, "h", harness="vibe")


def test_a_privilege_its_when_excludes_leaves_the_service_to_the_hook(tree):
    _ext(tree, "h", "privileges:\n  svc: [{ low_ports: true, when: { harness: vibe } }]\n",
         MARKED + "def contribute(ctx):\n    return {'privileges': {'svc': {'work': True}}}\n")
    a = _compose(tree, "h").by_name("h")
    assert a.spec("privileges", {"harness": "pi"})["svc"] == {"work": True}
    with pytest.raises(ExtensionError, match=r"privileges: \['svc'\] set by both"):
        _compose(tree, "h", harness="vibe")


def test_a_doctor_hook_may_report_what_core_checks_do():
    for status in ("ok", "info", "skip", "warn", "fail"):
        validate_result("doctor", "h", [("x", status, "d")])
    with pytest.raises(ExtensionError, match="status in"):
        validate_result("doctor", "h", [("x", "great", "d")])


def test_an_extension_loaded_from_another_directory_imports_its_own_helpers(tmp_path):
    hooks = {}
    for which in ("one", "two"):
        (tmp_path / which).mkdir()
        _ext(tmp_path / which, "h", hooks="from . import helper\n")
        (tmp_path / which / "h" / "helper.py").write_text(f"WHICH = {which!r}\n")
        hooks[which] = load_module(tmp_path / which / "h" / "hooks.py", "h")
    assert (hooks["one"].helper.WHICH, hooks["two"].helper.WHICH) == ("one", "two")


def test_list_keys_concatenate(tree):
    _ext(tree, "h", "trust: [a]\n", MARKED + "def contribute(ctx):\n    return {'trust': ['b']}\n")
    assert _compose(tree, "h").by_name("h").spec("trust") == ["a", "b"]


@pytest.mark.parametrize(("name", "out", "match"), [
    ("launch_env", ["x"], "want {secrets"),
    ("launch_env", {"env": "X=1"}, "secrets and env are mappings"),
    ("resolve", {}, "want \\(exports, notes\\)"),
    ("doctor", [("x", "bad", "")], "status in"),
    ("forwarder", {"service": {"privileged": True}}, "core owns names"),
    ("diagnose", 1, "want a hint"),
])
def test_each_hooks_result_is_checked(tree, name, out, match):
    comp = _compose(tree)
    a = comp.by_name("llm")
    a.hooks = {name: lambda ctx, *args: out}
    with pytest.raises(ExtensionError, match=f"extension 'llm': {name}: .*{match}"):
        call_hook(comp, a, name, None, None)


# --- the context --------------------------------------------------------------------


def _manifest(raw: dict, *, out_of_tree: bool = False, trusted: bool = True) -> Manifest:
    return Manifest("m", Path("/m"), {"api": 2, "name": "m", **raw}, out_of_tree=out_of_tree, trusted=trusted)


@pytest.mark.parametrize(("raw", "session_dir", "work_dir"), [
    ({}, False, False),
    ({"settings": {"p": {"type": "path"}}}, True, False),
    ({"mounts": {"d": {"setting": "p"}}}, True, False),
    ({"outputs": {"o": {"services": ["s"]}}}, True, True),
    ({"inputs": {"i": {"services": ["s"]}}}, True, True),
    ({"privileges": {"s": {"work": True}}}, False, True),
    ({"privileges": {"s": [{"low_ports": True}, {"work": True}]}}, False, True),
    ({"host_files": True}, True, True),
])
def test_host_paths_reach_a_hook_only_when_declared(raw, session_dir, work_dir):
    # a `work` privilege its contribute hook returned counts for the hooks after it
    assert declares_host_paths(_manifest({}), work=True, privileges=raw.get("privileges", {})) \
        is bool(raw.get("privileges"))
    assert declares_host_paths(_manifest(raw)) is session_dir
    assert declares_host_paths(_manifest(raw), work=True) is work_dir
    # never for an untrusted out-of-tree extension, whatever it declares
    assert not declares_host_paths(_manifest(raw, out_of_tree=True, trusted=False), work=True)
    assert not declares_host_paths(_manifest(raw, out_of_tree=True, trusted=False))


def test_the_context_holds_declared_paths_and_is_read_only(tree, tmp_path):
    _ext(tree, "plain")
    _ext(tree, "files", "host_files: true\n")
    comp = _compose(tree, "plain", "files", session_dir=tmp_path, work_dir=tmp_path / "work")
    plain, files = hook_context(comp, comp.by_name("plain")), hook_context(comp, comp.by_name("files"))
    assert (plain.session_dir, plain.work_dir) == (None, None)
    assert (files.session_dir, files.work_dir) == (tmp_path, tmp_path / "work")
    assert files.state_dir == Path("/x/files") and files.assets == tree / "files"
    assert files.session["id"] == "s" and files.slot["inference"]["api"] == "openai-completions"
    with pytest.raises(TypeError):
        files.settings["x"] = 1  # type: ignore[index]


def test_only_the_forwarder_provider_sees_the_forwarders_and_grants(tree):
    _ext(tree, "fwd", "provides: [forwarder]\n")
    comp = _compose(tree, "fwd")
    comp.forwarders, comp.grants = [{"service": "llm"}], {"filter": False}
    fwd, llm = hook_context(comp, comp.by_name("fwd")), hook_context(comp, comp.by_name("llm"))
    assert (fwd.forwarders, dict(fwd.grants)) == (({"service": "llm"},), {"filter": False})
    assert (llm.forwarders, dict(llm.grants)) == ((), {})
    a = comp.by_name("fwd")
    a.manifest = dataclasses.replace(a.manifest, out_of_tree=True, trusted=False)
    stranger = hook_context(comp, a)
    assert (stranger.forwarders, dict(stranger.grants)) == ((), {})


# --- slot exports -------------------------------------------------------------------

EGRESS = {"proxy_host": "p", "proxy_port": 8888, "proxy_url": "http://p:8888"}


@pytest.mark.parametrize(("exports", "match"), [
    ({k: v for k, v in EGRESS.items() if k != "proxy_url"}, r"need \['proxy_url'\]"),
    ({**EGRESS, "proxy_port": "eighty"}, "proxy_port must be int"),
    ({**EGRESS, "exit_identity": {"url": "https://x/", "file": "ip"}}, "exit_identity is"),
    ({**EGRESS, "exit_identity": {"source": "s", "volume": "exit"}}, "exit_identity is"),
    ({**EGRESS, "exit_identity": "vpn-endpoint"}, "exit_identity must be dict"),
    ({**EGRESS, "shares": "exit"}, "shares must be list"),
    ({**EGRESS, "shares": [1]}, "shares is a list of volume names"),
    ({**EGRESS, "anonymising": "yes"}, "anonymising must be bool"),
])
def test_an_egress_exports_what_core_reads_typed(exports, match):
    with pytest.raises(ExtensionError, match=match):
        check_slot_exports("egress", "e", exports)


def test_a_templated_int_or_bool_export_is_read_back_as_one():
    # `"{{ settings.port }}"` renders as a string
    out = check_slot_exports("egress", "e", {**EGRESS, "proxy_port": "3128", "anonymising": "True",
                                              "proxy_host": "1"})
    assert (out["proxy_port"], out["anonymising"], out["proxy_host"]) == (3128, True, "1")
    out = check_slot_exports("inference", "i", {"base_url": "http://x", "api": "a", "model": "true",
                                                 "api_key_injected": "false"})
    assert (out["model"], out["api_key_injected"]) == ("true", False)


def test_well_formed_exports_and_a_providers_own_keys_pass():
    check_slot_exports("egress", "e", {**EGRESS, "exit_identity": {"source": "s", "volume": "v", "file": "f"},
                                       "shares": ["exit"], "resolver": None, "its_own": object()})
    check_slot_exports("inference", "i", {"base_url": "http://x", "api": "openai-completions", "model": "auto"})
    with pytest.raises(ExtensionError, match=r"need \['model'\]"):
        check_slot_exports("inference", "i", {"base_url": "http://x", "api": "openai-completions"})


# --- ext_session and reload_sidecar -----------------------------------------------------

SID = "s-abc123"


@pytest.fixture
def session(tmp_path):
    d = make_session(tmp_path / "s", "  observe: {}\n  skills: {}\n")
    (d / ".glove").mkdir()
    return d


def test_ext_session_is_refused_before_a_launch_and_for_an_extension_not_enabled(session):
    with pytest.raises(ExtensionError, match="has never been launched"):
        ext_session("observe", session)
    assert ext_session("observe", session, launched=False).id is None
    (session / ".glove" / "id").write_text(SID)
    with pytest.raises(ExtensionError, match="the playwright extension is not enabled"):
        ext_session("playwright", session)
    s = ext_session("skills", session)
    assert (s.id, s.root, s.work, s.settings["python"]) == (SID, session, session / "work", "3.12")
    assert s.hooks is not None and callable(s.hooks.relays)
    assert s.container("skill-x") == f"glove-{SID}-skill-x"


@pytest.mark.parametrize("value", ["true", "x", "[1]"])
def test_ext_session_refuses_settings_that_are_not_a_mapping(tmp_path, value):
    d = make_session(tmp_path / "s", f"  playwright: {value}\n")
    with pytest.raises(ExtensionError, match="'playwright': settings must be a mapping"):
        ext_session("playwright", d, launched=False)


def test_its_state_dir_is_private_in_a_never_launched_session(tmp_path):
    d = make_session(tmp_path / "s", "  skills: {}\n")
    state = ext_session("skills", d, launched=False).state_dir()
    assert state == d / ".glove" / "ext" / "skills" and state.is_dir()
    assert oct((d / ".glove").stat().st_mode & 0o777) == "0o700" and oct(state.stat().st_mode & 0o777) == "0o700"
    assert (d / ".glove" / ".gitignore").read_text().endswith("*\n") and not (d / ".glove" / "id").exists()


def test_rendered_reads_the_last_compose_and_export_dirs_are_the_owners(session, monkeypatch, tmp_path):
    (session / ".glove" / "id").write_text(SID)
    s = ext_session("observe", session)
    assert s.rendered("netgate") == {}
    s.compose_file.write_text(yaml.safe_dump({"services": {f"glove-{SID}-netgate": {"image": "i"}}}))
    assert s.rendered("netgate") == {"image": "i"}
    assert s.export_dir("observe").name == SID
    with pytest.raises(ExtensionError, match="does not own the 'control' export root"):
        s.export_dir("control")
    with pytest.raises(ExtensionError, match="does not own"):
        ext_session("skills", session).export_dir("observe")


def test_reload_sidecar_refuses_a_stopped_service_and_reports_an_unhealthy_one(session, monkeypatch):
    (session / ".glove" / "id").write_text(SID)
    s = ext_session("skills", session)
    calls, health = [], iter(["starting", "healthy"])
    monkeypatch.setattr(ExtSession, "running", lambda self, service: service == "up")
    monkeypatch.setattr("glove.extsession.subprocess.run",
                        lambda argv, **k: calls.append((argv, k["env"])) or SimpleNamespace(returncode=0))
    monkeypatch.setattr("glove.extsession.time.sleep", lambda _: None)
    monkeypatch.setattr("glove.verify._health", lambda rt, container: next(health, "unhealthy"))
    with pytest.raises(ExtensionError, match=f"glove-{SID}-down is not running"):
        reload_sidecar(s, "down", {})
    assert not calls
    reload_sidecar(s, "up", {"K": "v"}, wait=5)
    argv, env = calls[-1]
    assert argv[-5:] == ["up", "-d", "--no-deps", "--force-recreate", f"glove-{SID}-up"] and env["K"] == "v"
    with pytest.raises(ExtensionError, match=f"did not become healthy; `{s.runtime} logs glove-{SID}-up`"):
        reload_sidecar(s, "up", {}, wait=2)
    monkeypatch.setattr("glove.extsession.subprocess.run", lambda argv, **k: SimpleNamespace(returncode=3))
    with pytest.raises(ExtensionError, match="failed \\(exit 3\\)"):
        reload_sidecar(s, "up", {})


# --- docs/extensions.md ---------------------------------------------------------------


def test_the_authors_guide_names_every_key_hook_export_and_api_name():
    doc = (Path(__file__).resolve().parents[1] / "docs" / "extensions.md").read_text()
    names = {*KEYS, *HOOKS, *SLOT_EXPORTS, *(k for ks in SLOT_EXPORTS.values() for k in ks), *glove.api.__all__}
    assert not sorted(n for n in names if f"`{n}`" not in doc and f"`{n}(" not in doc)
