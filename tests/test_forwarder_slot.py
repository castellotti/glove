"""v3 M5 core API: the `forwarder` slot, export roots and grants, interposed
endpoints, `address` targets over `wan`, and extension CLIs."""

from __future__ import annotations

import json
import os
import textwrap
from pathlib import Path

import pytest
from helpers import STUB_LLM
from typer.testing import CliRunner

from glove import exports
from glove.cli import app
from glove.extensions import IN_TREE_DIR, ExtensionError, compose, discover
from glove.hardening import HardeningError

DIGEST = "alpine@sha256:" + "0" * 64


def _ext(root: Path, name: str, manifest: str, files: dict[str, str] | None = None) -> None:
    d = root / name
    d.mkdir(parents=True)
    (d / "extension.yml").write_text(textwrap.dedent(manifest))
    for rel, text in (files or {}).items():
        (d / rel).write_text(textwrap.dedent(text))


@pytest.fixture
def tree(tmp_path):
    import shutil

    root = tmp_path / "exts"
    root.mkdir()
    for name in ("llm", "direct", "webfetch"):
        shutil.copytree(IN_TREE_DIR / name, root / name, ignore=shutil.ignore_patterns("tests", "__pycache__"))
    return root


def _fwd(tree, hook: str) -> None:
    _ext(tree, "fwd", "api: 1\nname: fwd\nsummary: x\nprovides: [forwarder]\nhooks: hooks.py\n",
         {"hooks.py": hook})


def _compose(tree, tmp_path, exts):
    return compose({"llm": STUB_LLM, **exts}, harness="pi", session="s", state_root=tmp_path / "state",
                   manifests=discover(tree), export_dirs=exports.export_dirs("s"))


def _plan_with(tree, tmp_path, exts, monkeypatch):
    from helpers import make_cfg

    import glove.plan as plan_mod

    real = plan_mod.compose
    monkeypatch.setattr(plan_mod, "compose", lambda *a, **k: real(*a, **{**k, "manifests": discover(tree)}))
    cfg = make_cfg(harness="pi", name="s", workdir=str(tmp_path), extensions=exts)
    return plan_mod.build_session_plan(cfg, env_id="s", home_dir=str(tmp_path / "h"), state_dir=str(tmp_path / "x"))


def test_forwarder_hook_replaces_socat_and_gets_hardened(tree, tmp_path, monkeypatch):
    _fwd(tree, f"""\
        def forwarder(ctx, ep):
            return {{"service": {{"image": "{DIGEST}", "command": ["relay", ep["target"]]}},
                     "facts": {{"summary": "relay"}}, "aliases": [ep["container"] + "-in"]}}
        """)
    plan = _plan_with(tree, tmp_path, {"fwd": {}}, monkeypatch)
    llm = plan.network.sidecars[0]
    assert llm.impl == {"image": DIGEST, "command": ["relay", "host.docker.internal:8080"]}
    assert llm.impl_aliases == ("glove-s-llm-in",)
    assert plan.composition.forwarders[0]["observed"] is True
    import yaml

    from glove.runtimes.docker import DockerRuntime
    doc = yaml.safe_load(DockerRuntime().render(plan, tmp_path).compose_yaml)
    svc = doc["services"]["glove-s-llm"]
    assert svc["image"] == DIGEST and svc["cap_drop"] == ["ALL"] and svc["read_only"] is True
    assert svc["networks"]["glove-s-net"] == {"aliases": ["glove-s-llm-in"]}
    assert svc["extra_hosts"] == ["host.docker.internal:host-gateway"]


@pytest.mark.parametrize(("ret", "match"), [
    ('{"service": {"image": IMG, "networks": ["wan"]}}', "core owns names, networks"),
    ('{"service": {"image": IMG, "privileged": True}}', "core owns names, networks"),
    ('{"service": {"image": IMG}, "aliases": ["api.openai.com"]}', "must start with"),
])
def test_forwarder_hook_cannot_pick_networks_privileges_or_foreign_aliases(tree, tmp_path, monkeypatch, ret, match):
    _fwd(tree, f"IMG = {DIGEST!r}\n\n\ndef forwarder(ctx, ep):\n    return {ret}\n")
    with pytest.raises(ExtensionError, match=match):
        _plan_with(tree, tmp_path, {"fwd": {}}, monkeypatch)


def test_forwarder_hook_image_must_be_pinned_or_built(tree, tmp_path, monkeypatch):
    _fwd(tree, 'def forwarder(ctx, ep):\n    return {"service": {"image": "alpine:latest"}}\n')
    plan = _plan_with(tree, tmp_path, {"fwd": {}}, monkeypatch)
    from glove.runtimes.docker import DockerRuntime

    with pytest.raises(ExtensionError, match="pinned by digest"):
        DockerRuntime().render(plan, tmp_path)


def test_export_roots_belong_to_the_in_tree_owners_only(tree, tmp_path):
    comp = _compose(tree, tmp_path, {"direct": {}})
    assert comp.owner("observe") is None and comp.owner("control") is None
    assert all(comp.export_access(a) == {} for a in comp.active)
    # an out-of-tree extension named like an owner would shadow it: refused by discover
    assert exports.grants(comp) == {"observe": None, "filter": None}


def test_grants_and_since(tmp_path):
    from types import SimpleNamespace

    def comp(observe=True, filt=False, transcripts=True):
        a = SimpleNamespace(exports={"transcripts": transcripts})
        return SimpleNamespace(owner=lambda root: {"observe": a if observe else None,
                                                   "control": a if filt else None}[root])

    assert exports.grants(comp(), now="T1") == {"observe": {"net": True, "transcripts": True},
                                                "filter": {"granted": False}}
    g = exports.grants(comp(filt=True), now="T1")
    assert g["filter"] == {"granted": True, "since": "T1"}
    assert exports.grants(comp(filt=True), g, now="T2")["filter"]["since"] == "T1"  # kept
    revoked = exports.grants(comp(), g, now="T3")
    assert revoked["filter"] == {"granted": False}
    assert exports.grants(comp(filt=True), revoked, now="T4")["filter"]["since"] == "T4"  # re-granted


def test_transcripts_bind_must_be_the_observe_exports_own(tmp_path):
    from types import SimpleNamespace

    root = tmp_path / "g" / "observe" / "s"
    comp = SimpleNamespace(export_dirs={"observe": root, "control": tmp_path / "g" / "control" / "s"})
    plan = SimpleNamespace(composition=comp, home_dir=str(tmp_path / "h"), mounts=[], policies_host_dir=None,
                           transcripts_host_dir=str(root / "net"))
    with pytest.raises(HardeningError):
        exports.validate_export_isolation(plan)
    plan.transcripts_host_dir = str(root / "transcripts")
    exports.validate_export_isolation(plan)


def test_address_targets_only_for_the_inference_or_egress_provider(tree, tmp_path):
    _ext(tree, "rogue", """\
        api: 1
        name: rogue
        summary: x
        endpoints:
          out: { target: { address: "db.example:5432", via: wan } }
        """)
    with pytest.raises(ExtensionError, match="only the inference provider"):
        _compose(tree, tmp_path, {"rogue": {}})


def test_interpose_is_only_for_an_egress_consumers_hop(tree, tmp_path):
    _ext(tree, "hop", """\
        api: 1
        name: hop
        summary: x
        requires: [egress]
        endpoints:
          out: { interpose: true, target: { slot: egress } }
        """)
    with pytest.raises(ExtensionError, match="interpose"):
        _compose(tree, tmp_path, {"direct": {}, "hop": {}})


def test_extension_clis_are_mounted_and_listed():
    runner = CliRunner()
    out = runner.invoke(app, ["ext"])
    assert out.exit_code == 0
    assert "observe" in out.output and "cli: glove observe" in out.output and "gate" in out.output
    for group in ("observe", "filter"):
        assert runner.invoke(app, [group, "--help"]).exit_code == 0


def test_prepare_revokes_a_dropped_filter(tmp_path, monkeypatch):
    from types import SimpleNamespace

    monkeypatch.setenv("GLOVE_HOME", str(tmp_path / "g"))
    dirs = exports.export_dirs("s")
    dirs["control"].mkdir(parents=True)
    (dirs["control"] / "rules.json").write_text(json.dumps({"v": 1}))
    comp = SimpleNamespace(export_dirs=dirs, owner=lambda root: None)
    notes = exports.prepare(comp, tmp_path / "state")
    assert not dirs["control"].exists() and len(notes) == 2
    assert json.loads((tmp_path / "state" / "filter" / "rules.revoked.json").read_text()) == {"v": 1}
    assert not dirs["observe"].exists()  # never created for an unobserved session
    assert oct(os.stat(tmp_path / "state" / "filter").st_mode & 0o777) == "0o700"
