"""Harness plugins: core knows no harness by name, loads only the selected
adapter, validates manifests, and keeps the names external monitors rely on."""

from __future__ import annotations

import json
import re
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
from helpers import make_cfg

from glove.config import ConfigError
from glove.harness import HARNESSES_DIR, get_profile, known_harnesses, load_profile
from glove.plan import build_session_plan

ROOT = Path(__file__).resolve().parent.parent


def test_core_names_no_harness():
    # A harness's name, or a harness-prefixed identifier, belongs in harnesses/<name>/.
    pat = re.compile(r"""["'](pi|vibe|claude-code)["']|\b(pi|vibe)_[a-z]""")
    hits = [f"{p.relative_to(ROOT)}:{n}: {line.strip()}"
            for p in sorted((ROOT / "glove").rglob("*.py"))
            for n, line in enumerate(p.read_text().splitlines(), 1) if pat.search(line)]
    assert hits == []


def test_harness_names_are_stable():
    # Layman picks a transcript parser from the registry row's `harness`: these
    # strings are a contract, never renamed.
    assert known_harnesses() == ["claude-code", "pi", "vibe"]
    assert all(get_profile(n).name == n for n in known_harnesses())


@pytest.mark.parametrize("harness", ["pi", "vibe", "claude-code"])
def test_only_the_selected_adapter_is_imported(harness, tmp_path):
    llm = {"provider": "anthropic-compatible", "location": "host", "endpoint": "127.0.0.1:8080", "model": "m"}
    exts = {"llm": llm} if harness == "claude-code" else {}
    code = textwrap.dedent(f"""
        import sys
        from pathlib import Path
        sys.path[:0] = [{str(ROOT)!r}, {str(ROOT / "tests")!r}]
        from glove.runtimes.docker import DockerRuntime
        DockerRuntime.network_subnets = lambda self: {{}}
        from helpers import make_cfg
        from glove.harnessconfig import render_home
        from glove.plan import build_session_plan
        cfg = make_cfg(harness={harness!r}, name="s", workdir={str(tmp_path)!r}, extensions={exts!r})
        plan = build_session_plan(cfg, home_dir={str(tmp_path / "h")!r}, uid=501, gid=20)
        render_home(cfg, plan, Path({str(tmp_path / "h")!r}))
        print(sorted(m for m in sys.modules if m.startswith("glove_harness_")))
    """)
    env = {"GLOVE_HOME": str(tmp_path / "gh"), "PATH": "/usr/bin:/bin"}
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env)
    assert out.returncode == 0, out.stderr[-2000:]
    assert out.stdout.strip() == str([f"glove_harness_{harness.replace('-', '_')}"])


def test_vibe_transcripts_and_resume_share_its_log_dir():
    # Vibe 2.x writes logs/session/session_<ts>_<id>/messages.jsonl, never sessions/.
    vibe = get_profile("vibe")
    assert vibe.sessions_subdir == vibe.transcript_subdir == "logs/session"


def test_every_harness_image_bakes_the_shared_entrypoint():
    for name in known_harnesses():
        image = HARNESSES_DIR / name / "image"
        assert not (image / "entrypoint.sh").exists()
        df = (image / "Dockerfile").read_text()
        if re.search(r"^ENTRYPOINT", df, re.M):
            assert "COPY --chmod=0755 --from=gloveentry entrypoint.sh /opt/glove/entrypoint.sh" in df


def _manifest(tmp_path: Path, name: str, body: str) -> Path:
    d = tmp_path / name
    d.mkdir()
    (d / "harness.yml").write_text(textwrap.dedent(body))
    return d


GOOD = """\
api: 1
name: h
image: glove/h:1
version: 1.0.0
audited_version: 1.0.0
entry: [h]
config_home: { env: H_HOME, path: /home/agent/.h }
context_file: /home/agent/.h/AGENTS.md
"""


def test_a_minimal_manifest_loads(tmp_path):
    p = load_profile(_manifest(tmp_path, "h", GOOD))
    assert (p.name, p.entry, p.contributions, p.transcript_subdir) == ("h", ["h"], frozenset(), "sessions")
    assert p.dockerfile == tmp_path / "h" / "image" / "Dockerfile"


@pytest.mark.parametrize("body,dirname", [
    (GOOD + "extra: 1\n", "h"),                        # unknown key
    (GOOD.replace("image: glove/h:1\n", ""), "h"),     # missing key
    (GOOD.replace("api: 1", "api: 2"), "h"),           # wrong api
    (GOOD, "other"),                                   # name ≠ directory
    (GOOD + "contributions: [tools]\n", "h"),          # unknown contribution
    (GOOD + "masked_files: [../x/]\n", "h"),           # outside the working dir
    (GOOD + "protected_home: [/etc/x]\n", "h"),        # absolute
    (GOOD + "protected_home: [.h/../x]\n", "h"),       # escapes the home
    (GOOD + "protected_home: [./]\n", "h"),            # the home itself
    (GOOD + "protected_home: [.h//x]\n", "h"),         # empty component
    (GOOD + "brief: ../x.md\n", "h"),                  # outside the harness dir
    (GOOD + "brief: missing.md\n", "h"),               # no such file
    (GOOD.replace("version: 1.0.0\n", ""), "h"),      # no release pinned
    (GOOD.replace("audited_version: 1.0.0", "audited_version: 0.9.0"), "h"),  # a release not re-audited
])
def test_bad_manifests_are_refused(tmp_path, body, dirname):
    with pytest.raises(ConfigError):
        load_profile(_manifest(tmp_path, dirname, body))


def test_protected_home_keeps_its_directory_marker(tmp_path):
    p = load_profile(_manifest(tmp_path, "h", GOOD + "protected_home: [.h/settings.json, .h/tools/]\n"))
    assert p.protected_home == (".h/settings.json", ".h/tools/")


def test_pinned_dependency_trees_match_the_harness_version():
    import yaml

    pi = get_profile("pi").path / "image" / "pi-lock"
    lock = json.loads((pi / "package-lock.json").read_text())
    want = get_profile("pi").version
    assert json.loads((pi / "package.json").read_text())["dependencies"]["@earendil-works/pi-coding-agent"] == want
    assert lock["packages"]["node_modules/@earendil-works/pi-coding-agent"]["version"] == want
    assert lock["packages"][""]["dependencies"]["@earendil-works/pi-coding-agent"] == want
    vibe = get_profile("vibe")
    pins = (vibe.path / "image" / "vibe-constraints.txt").read_text().split()
    assert f"mistral-vibe=={vibe.version}" in pins
    assert yaml.safe_load((vibe.path / "harness.yml").read_text())["version"] == vibe.version


def test_a_harness_brief_reaches_its_context_file(tmp_path):
    from glove.harnessconfig import build_environment_context

    d = _manifest(tmp_path, "h", GOOD + "brief: brief.md\n")
    (d / "brief.md").write_text("## H's settings\n\nRead-only.\n")
    assert load_profile(d).brief == "## H's settings\n\nRead-only."
    for name in ("pi", "vibe"):
        cfg = make_cfg(harness=name, name="s", workdir=str(tmp_path))
        plan = build_session_plan(cfg, home_dir=str(tmp_path / "home"))
        assert "never saved" in build_environment_context(plan)


def test_unknown_harness_is_refused():
    with pytest.raises(ValueError, match="unknown harness"):
        get_profile("../extensions")


def _plan_with(tmp_path, monkeypatch, harness_section: str, harness: str = "pi"):
    import shutil

    import glove.plan as plan_mod
    from glove.extensions import IN_TREE_DIR, discover

    tree = tmp_path / "exts"
    shutil.copytree(IN_TREE_DIR / "llm", tree / "llm", ignore=shutil.ignore_patterns("tests", "__pycache__"))
    (tree / "x" / "code").mkdir(parents=True)
    (tree / "x" / "extension.yml").write_text(f"api: 1\nname: x\nsummary: x\nharness:\n{harness_section}")
    real = plan_mod.compose
    monkeypatch.setattr(plan_mod, "compose", lambda *a, **k: real(*a, **{**k, "manifests": discover(tree)}))
    cfg = make_cfg(harness=harness, name="s", workdir=str(tmp_path), extensions={"x": {}})
    return plan_mod.build_session_plan(cfg, home_dir=str(tmp_path / "h"), state_dir=str(tmp_path / "st"),
                                       session_dir=str(tmp_path))


@pytest.mark.parametrize("section", ["  pi_extensions: [code]\n", "  vibe_mcp: []\n", "  tools: []\n"])
def test_unknown_harness_keys_are_refused(tmp_path, monkeypatch, section):
    from glove.extensions import ExtensionError

    with pytest.raises(ExtensionError, match="unknown key"):
        _plan_with(tmp_path, monkeypatch, section)


def test_a_harness_section_reaches_only_its_adapter(tmp_path, monkeypatch):
    section = "  pi: { extensions: [code] }\n  mcp: [{name: m, transport: http, url: 'http://m:1/mcp'}]\n"
    pi = _plan_with(tmp_path, monkeypatch, section)
    assert pi.command[-2:] == ["-e", "/opt/glove/ext/x/code"] and pi.composition.mcp == []
    (tmp_path / "v").mkdir()
    vibe = _plan_with(tmp_path / "v", monkeypatch, section, harness="vibe")
    assert vibe.composition.harness_items == [] and [s["name"] for _, s in vibe.composition.mcp] == ["m"]
    assert "/opt/glove/ext/x/code" not in (vibe.derived_dockerfile or "")


def test_the_pi_section_takes_only_extensions(tmp_path, monkeypatch):
    from glove.extensions import ExtensionError

    with pytest.raises(ExtensionError, match="`pi:` takes"):
        _plan_with(tmp_path, monkeypatch, "  pi: { skills: [code] }\n")
