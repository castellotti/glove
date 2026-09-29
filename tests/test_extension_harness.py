"""v3 M6 core API: extension harness mounts, Pi skills, list-setting patterns,
package lists expanded from settings, pip layers on Pi, staging collisions."""

from __future__ import annotations

import shutil
import textwrap
from pathlib import Path

import pytest
from helpers import make_cfg

from glove.extensions import IN_TREE_DIR, ExtensionError, discover


def _ext(root: Path, name: str, manifest: str, files: dict[str, str] | None = None) -> Path:
    d = root / name
    d.mkdir(parents=True)
    (d / "extension.yml").write_text(textwrap.dedent(manifest))
    for rel, text in (files or {}).items():
        (d / rel).parent.mkdir(parents=True, exist_ok=True)
        (d / rel).write_text(text)
    return d


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "exts"
    root.mkdir()
    shutil.copytree(IN_TREE_DIR / "llm", root / "llm", ignore=shutil.ignore_patterns("tests", "__pycache__"))
    return root


def _plan(tree, tmp_path, monkeypatch, exts, harness="pi"):
    import glove.plan as plan_mod

    real = plan_mod.compose
    monkeypatch.setattr(plan_mod, "compose", lambda *a, **k: real(*a, **{**k, "manifests": discover(tree)}))
    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    cfg = make_cfg(harness=harness, name="s", workdir=str(work), extensions=exts)
    return plan_mod.build_session_plan(cfg, env_id="s", home_dir=str(tmp_path / "h"), state_dir=str(tmp_path / "x"),
                                       session_dir=str(tmp_path))


MOUNTER = """\
api: 1
name: m
summary: x
settings:
  data: { type: path }
  name: { type: string }
mounts:
  data: { setting: data }
"""


def test_a_mount_is_read_only_at_a_fixed_point(tree, tmp_path, monkeypatch):
    _ext(tree, "m", MOUNTER + "harness:\n  env: { DATA: \"{{ mount.data }}\" }\n")
    (tmp_path / "rel").mkdir()
    plan = _plan(tree, tmp_path, monkeypatch, {"m": {"data": "rel"}})  # relative → the session dir
    m = next(m for m in plan.mounts if m.container_path == "/mnt/m-data")
    assert (m.host_path, m.mode) == (str((tmp_path / "rel").resolve()), "ro")
    assert plan.environment["DATA"] == "/mnt/m-data"


def test_an_unset_mount_setting_mounts_nothing(tree, tmp_path, monkeypatch):
    _ext(tree, "m", MOUNTER)
    plan = _plan(tree, tmp_path, monkeypatch, {"m": {}})
    assert not any(m.container_path.startswith("/mnt/m-") for m in plan.mounts)


@pytest.mark.parametrize(("mounts", "match"), [
    ("mounts:\n  x: { setting: name }\n", "must name one of its `path` settings"),
    ("mounts:\n  x: { setting: data, target: /etc }\n", "want"),
    ("mounts:\n  X: { setting: data }\n", "want"),
    ("  dflt: { type: path, default: ~/.ssh }\nmounts:\n  x: { setting: dflt }\n", "may not have a default"),
])
def test_mount_declarations_are_strict(tree, tmp_path, monkeypatch, mounts, match):
    _ext(tree, "m", MOUNTER.replace("mounts:\n  data: { setting: data }\n", mounts))
    (tmp_path / "d").mkdir()
    with pytest.raises(ExtensionError, match=match):
        _plan(tree, tmp_path, monkeypatch, {"m": {"data": str(tmp_path / "d")}})


@pytest.mark.parametrize("private", [".glove", "local", "."])
def test_a_mount_never_exposes_the_session_state(tree, tmp_path, monkeypatch, private):
    _ext(tree, "m", MOUNTER)
    (tmp_path / private).mkdir(exist_ok=True)
    with pytest.raises(ExtensionError, match="would expose"):
        _plan(tree, tmp_path, monkeypatch, {"m": {"data": str(tmp_path / private)}})


def test_skills_baked_or_from_a_mount(tree, tmp_path, monkeypatch):
    _ext(tree, "m", MOUNTER + """\
        harness:
          pi_skills:
            - skills/mine
            - { mount: data, path: skills/theirs }
        """.replace("        ", ""), {"skills/mine/SKILL.md": "x"})
    (tmp_path / "d" / "skills" / "theirs").mkdir(parents=True)
    (tmp_path / "d" / "skills" / "theirs" / "SKILL.md").write_text("x")
    plan = _plan(tree, tmp_path, monkeypatch, {"m": {"data": str(tmp_path / "d")}})
    assert [d for _, _, d in plan.composition.pi_skills] == ["/opt/glove/skills/m/mine", "/mnt/m-data/skills/theirs"]
    assert "COPY m/mine /opt/glove/skills/m/mine" in plan.derived_dockerfile
    plan = _plan(tree, tmp_path, monkeypatch, {"m": {}})  # the mount is off: its skill is skipped
    assert [d for _, _, d in plan.composition.pi_skills] == ["/opt/glove/skills/m/mine"]


@pytest.mark.parametrize(("item", "match"), [
    ("skills/none", "needs a SKILL.md inside the extension"),
    ("../llm", "needs a SKILL.md inside the extension"),
    ("{ mount: data, path: ../../etc }", "has no SKILL.md in mount"),
])
def test_bad_skills(tree, tmp_path, monkeypatch, item, match):
    _ext(tree, "m", MOUNTER + f"harness:\n  pi_skills: [{item}]\n")
    (tmp_path / "d").mkdir()
    with pytest.raises(ExtensionError, match=match):
        _plan(tree, tmp_path, monkeypatch, {"m": {"data": str(tmp_path / "d")}})


def test_package_lists_expand_from_a_list_setting(tree, tmp_path, monkeypatch):
    _ext(tree, "p", """\
        api: 1
        name: p
        summary: x
        settings:
          extra: { type: list, default: [a, b], pattern: "^[a-z]+$" }
        harness:
          image:
            "*": { apt: [base, "{% for x in settings.extra %}pkg-{{ x }} {% endfor %}"], pip: [requests==2.32.3] }
        """)
    df = _plan(tree, tmp_path, monkeypatch, {"p": {}}).derived_dockerfile
    assert "install -y --no-install-recommends base pkg-a pkg-b" in df
    # Pi's base is node-only: pip3 is bootstrapped before the first pip layer
    assert df.index("python3 python3-pip") < df.index("pip3 install --no-cache-dir --break-system-packages")
    vibe = _plan(tree, tmp_path, monkeypatch, {"p": {}}, harness="vibe").derived_dockerfile
    assert "python3-pip" not in vibe and "uv pip install --system requests==2.32.3" in vibe
    with pytest.raises(ExtensionError, match="must match"):
        _plan(tree, tmp_path, monkeypatch, {"p": {"extra": ["a b"]}})


def test_two_sources_may_not_stage_under_one_name(tree, tmp_path, monkeypatch):
    _ext(tree, "c", """\
        api: 1
        name: c
        summary: x
        harness:
          image:
            "*": { copy: [[tool, /opt/a], [bin/tool, /usr/local/bin/tool]] }
        """, {"tool/x.py": "", "bin/tool": ""})
    with pytest.raises(ValueError, match="would both stage as 'c/tool'"):
        _plan(tree, tmp_path, monkeypatch, {"c": {}})
