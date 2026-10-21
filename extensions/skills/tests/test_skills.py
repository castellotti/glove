"""`skills`: Claude Code plugins (and plain skill dirs) baked into the harness
image for every harness — substitution, selection, `bin/`, the offline uv
wheelhouse, opt-in MCP — and what is refused (escaping symlinks, credential
files, agent-writable plugins, secrets in `env`)."""

from __future__ import annotations

import json
import os
import re

import pytest
from helpers import PEM, make_cfg

from glove.config import AddDir, ConfigError
from glove.extensions import ExtensionError, materialize
from glove.harnessconfig import render_home
from glove.image import UV_HOME, run_body, uv_python_steps
from glove.plan import build_session_plan

HELLO = ('#!/usr/bin/env -S uv run --script\n# /// script\n# requires-python = ">=3.11"\n'
         '# dependencies = []\n# ///\nprint("hi")\n')
WITHDEP = HELLO.replace("dependencies = []", 'dependencies = ["six==1.17.0"]')
ANTHROPIC = {"provider": "anthropic", "model": "claude-x", "api_key": "keychain:test-cc"}
MCP = {"mcpServers": {"demo": {"command": "uv", "args": ["run", "--script", "${CLAUDE_PLUGIN_ROOT}/mcp/server.py"],
                               "env": {"DEMO_VAULT": "${CLAUDE_PLUGIN_DATA}/vault"}}}}


def _write(path, text, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(mode)


@pytest.fixture
def plugin(tmp_path):
    root = tmp_path / "skills" / "demo-repo" / "demo"
    _write(root / ".claude-plugin" / "plugin.json", '{"name": "demo"}')
    _write(root / "skills" / "greet" / "SKILL.md",
           "---\nname: greet\n---\nRun `${CLAUDE_PLUGIN_ROOT}/scripts/hello.py` (data: ${CLAUDE_PLUGIN_DATA}).\n")
    _write(root / "skills" / "other" / "SKILL.md", "---\nname: other\n---\n")
    _write(root / "scripts" / "hello.py", HELLO, 0o755)
    _write(root / "scripts" / "withdep.py", WITHDEP, 0o755)
    _write(root / "bin" / "demo", HELLO, 0o755)
    _write(root / "mcp" / "server.py", HELLO)
    _write(root / ".mcp.json", json.dumps(MCP))
    _write(root / ".env.example", "DEMO_URL=https://example.invalid\n")
    return root


def _cfg(tmp_path, harness, plugins, **kw):
    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    llm = {"llm": ANTHROPIC} if harness == "claude-code" else {}
    return make_cfg(harness=harness, name="s", workdir=str(work),
                    extensions={**llm, "skills": {"plugins": plugins}}, **kw)


def _plan(tmp_path, harness="pi", **demo):
    return _plan_of(tmp_path, _cfg(tmp_path, harness, {"demo": {"path": "skills/demo-repo/demo", **demo}}))


def _plan_of(tmp_path, cfg):
    return build_session_plan(cfg, home_dir=str(tmp_path / "h"), state_dir=str(tmp_path / "x"),
                              session_dir=str(tmp_path))


def test_a_plugin_is_baked_with_its_paths_resolved(tmp_path, plugin):
    plan = _plan(tmp_path)
    df = plan.derived_dockerfile
    # the selected skills and the plugin's other top-level entries
    assert ("skills/opt/glove/plugins/demo/skills", plugin / "skills" / "greet") in plan.derived_staged
    assert "COPY skills/opt/glove/plugins/demo/skills/greet /opt/glove/plugins/demo/skills/greet" in df
    assert "COPY skills/opt/glove/plugins/demo/scripts /opt/glove/plugins/demo/scripts" in df
    assert "COPY skills/opt/glove/plugins/demo/.mcp.json /opt/glove/plugins/demo/.mcp.json" in df
    # in the baked Markdown that names them only; the host checkout is never touched
    assert ("(grep -rlZ --include='*.md' -F '${CLAUDE_PLUGIN_' /opt/glove/plugins/demo || true) | xargs -0r "
            "sed -i -e 's|\\${CLAUDE_PLUGIN_ROOT}|/opt/glove/plugins/demo|g' "
            "-e 's|\\${CLAUDE_PLUGIN_DATA}|/work/.glove-plugin-data/demo|g'") in df
    assert "${CLAUDE_PLUGIN_ROOT}" in (plugin / "skills" / "greet" / "SKILL.md").read_text()
    # bin/ on PATH, never over a command the image has (no -f)
    assert "ln -s /opt/glove/plugins/demo/bin/demo /usr/local/bin/demo" in df
    assert [d for _, _, d in plan.composition.skills] == ["/opt/glove/plugins/demo/skills/greet",
                                                          "/opt/glove/plugins/demo/skills/other"]


def test_pep723_scripts_run_offline_from_a_baked_wheelhouse(tmp_path, plugin):
    plan = _plan(tmp_path)
    df = plan.derived_dockerfile
    assert "uv-$t-unknown-linux-gnu.tar.gz" in df and "sha256sum -c -" in df  # the pinned uv, verified
    assert "python install --no-bin 3.12" in df
    # only scripts with dependencies feed the wheelhouse (resolved with hashes,
    # wheels only), then their own read-only env, installed from it offline;
    # from the dependency sets, never a script's bytes, so before the plugin
    assert "printf '%s\\n' six==1.17.0 > /tmp/glove-req.in" in df
    assert "pip compile /tmp/glove-req.in --python /opt/glove/plugins/.uv/python3 --generate-hashes" in df
    assert "pip download --no-deps --only-binary=:all:" in df
    assert df.index("pip compile") < df.index("COPY skills/opt/glove/plugins/demo")
    [env] = re.findall(r"venv --python \S+ (/opt/glove/plugins/\.uv/envs/[0-9a-f]{12})", df)
    assert f"pip install --python {env}/bin/python --no-index --find-links /opt/glove/plugins/.uv/wheels" in df
    # each `uv run --script` shebang runs on its interpreter: nothing installs
    # at run time into the harness's noexec /tmp
    assert f"sed -i '1s|.*|#!{env}/bin/python|' /opt/glove/plugins/demo/scripts/withdep.py" in df
    assert "sed -i '1s|.*|#!/opt/glove/plugins/.uv/python3|' /opt/glove/plugins/demo/scripts/hello.py" in df
    assert "sed -i '1s|.*|#!/opt/glove/plugins/.uv/python3|' /opt/glove/plugins/demo/bin/demo" in df
    env = plan.environment
    assert {k: env[k] for k in ("UV_OFFLINE", "UV_NO_INDEX", "UV_PYTHON_DOWNLOADS")} == \
        {"UV_OFFLINE": "1", "UV_NO_INDEX": "1", "UV_PYTHON_DOWNLOADS": "never"}
    assert env["UV_FIND_LINKS"] == "/opt/glove/plugins/.uv/wheels"
    assert env["UV_PYTHON"] == "/opt/glove/plugins/.uv/python3"
    assert env["UV_CACHE_DIR"].startswith("/tmp/")  # every command's writable tmp


def test_no_scripts_no_uv(tmp_path):
    root = tmp_path / "skills" / "plain"
    _write(root / "hello" / "SKILL.md", "---\nname: hello\n---\nSay hello.\n")
    plan = _plan_of(tmp_path, _cfg(tmp_path, "pi", {"plain": {"path": "skills/plain"}}))
    # a plain directory of skills: each subdir with a SKILL.md is a skill
    assert [d for _, _, d in plan.composition.skills] == ["/opt/glove/plugins/plain/hello"]
    assert "uv" not in plan.derived_dockerfile and "UV_OFFLINE" not in plan.environment


def test_a_subset_of_skills_drops_the_rest_from_the_image(tmp_path, plugin):
    plan = _plan(tmp_path, skills=["greet"])
    assert [d for _, _, d in plan.composition.skills] == ["/opt/glove/plugins/demo/skills/greet"]
    assert not [s for _, s in plan.derived_staged if "other" in s.parts]  # never staged, hashed or baked
    (plugin / "skills" / "other" / "SKILL.md").write_text("changed")
    assert _plan(tmp_path, skills=["greet"]).image == plan.image
    with pytest.raises(ExtensionError, match=r"no skill \['nope'\]"):
        _plan(tmp_path, skills=["greet", "nope"])


def test_editing_a_skill_is_a_new_image_whose_plugin_layer_comes_last(tmp_path, plugin):
    cfg = _cfg(tmp_path, "pi", {"demo": {"path": "skills/demo-repo/demo"}})
    cfg.extensions["toolchains"] = {"blocks": [{"lang": "node", "version": "22.11.0"}]}
    before = _plan_of(tmp_path, cfg)
    (plugin / "skills" / "greet" / "SKILL.md").write_text("---\nname: greet\n---\nchanged\n")
    after = _plan_of(tmp_path, cfg)
    assert after.image != before.image
    # an edit rebuilds nothing else: the plugin layer is after the toolchains and the uv layer
    df = after.derived_dockerfile
    assert df.index("node-v22.11.0") < df.index("COPY skills/opt/glove/plugins/demo")
    assert df.split("COPY skills/opt/glove/plugins/demo")[0] == before.derived_dockerfile.split(
        "COPY skills/opt/glove/plugins/demo")[0]


@pytest.mark.parametrize("harness", ["pi", "claude-code", "vibe"])
def test_every_harness_loads_the_skills(tmp_path, plugin, harness):
    cfg = _cfg(tmp_path, harness, {"demo": {"path": "skills/demo-repo/demo", "skills": ["greet"]}})
    plan = _plan_of(tmp_path, cfg)
    home = tmp_path / "home"
    render_home(cfg, plan, home)
    df = plan.derived_dockerfile
    if harness == "claude-code":
        assert "ln -s /opt/glove/plugins/demo/skills/greet /opt/glove/cc/.claude/skills/greet" in df
        assert "--add-dir" in plan.command
    elif harness == "vibe":
        assert "ln -s /opt/glove/plugins/demo/skills/greet /opt/glove/vibe/skills/greet" in df
        assert 'skill_paths = [\n    "/opt/glove/vibe/skills",\n]' in (home / ".vibe" / "config.toml").read_text()
    else:
        settings = json.loads((home / ".pi" / "agent" / "settings.json").read_text())
        assert settings["skills"] == ["/opt/glove/plugins/demo/skills/greet"]


def test_mcp_is_opt_in_and_needs_its_tools_listed(tmp_path, plugin):
    assert not _plan(tmp_path, harness="claude-code").composition.mcp
    with pytest.raises(ExtensionError, match=r"list the tools it may use \(skills.plugins.demo.tools.demo"):
        _plan(tmp_path, harness="claude-code", mcp=True)
    plan = _plan(tmp_path, harness="claude-code", mcp=True, tools={"demo": ["search", "fetch"]})
    [(ext, item)] = plan.composition.mcp
    assert ext == "skills"
    # under the tool wrapper (no network); `uv run --script <its script>` on
    # that script's baked interpreter
    assert item == {"name": "demo", "transport": "stdio", "command": "/opt/glove/bin/glove-tool",
                    "args": ["--", "/opt/glove/plugins/.uv/python3", "/opt/glove/plugins/demo/mcp/server.py"],
                    "env": {"DEMO_VAULT": "/work/.glove-plugin-data/demo/vault",
                            "CLAUDE_PLUGIN_ROOT": "/opt/glove/plugins/demo",
                            "CLAUDE_PLUGIN_DATA": "/work/.glove-plugin-data/demo"},
                    "tools": ["search", "fetch"]}
    assert "glove-confine" not in plan.derived_dockerfile  # glove-tool is in every harness image


def test_mcp_per_harness(tmp_path, plugin):
    tools = {"demo": ["search"]}
    for harness in ("pi", "vibe"):
        [(_, item)] = _plan(tmp_path, harness=harness, mcp=True, tools=tools).composition.mcp
        assert item["command"] == "/opt/glove/bin/glove-tool" and item["args"][0] == "--"
    with pytest.raises(ExtensionError, match=r"tools maps a server of \['demo'\]"):
        _plan(tmp_path, harness="claude-code", mcp=True, tools={"other": ["x"]})


@pytest.mark.parametrize("harness", ["pi", "vibe", "claude-code"])
def test_a_stdio_server_under_enforcer_none_is_a_check_warning(tmp_path, plugin, harness):
    from glove.doctor import extension_checks

    (plugin / ".mcp.json").write_text(json.dumps({"mcpServers": {
        **MCP["mcpServers"], "web": {"type": "http", "url": "http://x.invalid/mcp"}}}))
    plugins = {"demo": {"path": "skills/demo-repo/demo", "mcp": True, "tools": {"demo": ["q"], "web": ["q"]}}}

    def checks(enforcer):
        cfg = _cfg(tmp_path, harness, plugins, enforcer=enforcer)
        plan = _plan_of(tmp_path, cfg)
        return [c for c in extension_checks(cfg.extensions, harness=harness, comp=plan.composition)
                if c.name.startswith("skills mcp")]

    [warning] = checks("none")  # the stdio server only: an http one needs no wrapper
    assert (warning.name, warning.status) == ("skills mcp demo/demo", "warn")
    assert "will not start under enforcer: none" in warning.detail
    assert checks("nono") == []


def test_an_http_server_passes_through_and_unknown_variables_are_refused(tmp_path, plugin):
    (plugin / ".mcp.json").write_text(json.dumps({"mcpServers": {"web": {"type": "http", "url": "http://x.invalid/mcp"}}}))
    [(_, item)] = _plan(tmp_path, harness="claude-code", mcp=True, tools={"web": ["q"]}).composition.mcp
    assert item == {"name": "web", "transport": "http", "url": "http://x.invalid/mcp", "tools": ["q"]}
    (plugin / ".mcp.json").write_text(json.dumps({"mcpServers": {"web": {"type": "http", "url": "${HOST}/mcp"}}}))
    with pytest.raises(ExtensionError, match="names a variable glove does not set"):
        _plan(tmp_path, harness="claude-code", mcp=True, tools={"web": ["q"]})


def test_env_takes_plain_values_only(tmp_path, plugin):
    plan = _plan(tmp_path, env={"DEMO_SPACE": "team", "DEMO_VERBOSE": True})
    assert plan.environment["DEMO_SPACE"] == "team" and plan.environment["DEMO_VERBOSE"] == "true"
    for env in ({"CONFLUENCE_PAT": "x"}, {"DEMO_TOKEN": "x"}, {"DEMO_URL": "keychain:svc"}):
        with pytest.raises(ExtensionError, match="looks like a secret; secrets never enter the harness"):
            _plan(tmp_path, env=env)


@pytest.mark.parametrize("make, err", [
    (lambda r, t: os.symlink("/etc/passwd", r / "scripts" / "p"), "symlink to '/etc/passwd', outside the plugin"),
    (lambda r, t: os.symlink("../../../../work", r / "w"), "outside the plugin"),
    (lambda r, t: (r / ".env").write_text("A=1\n"), r"\.env looks like a credential file"),
    (lambda r, t: (r / "keys" / "x").parent.mkdir() or (r / "keys" / "id_ed25519").write_text("k"),
     "id_ed25519 looks like a credential file"),
    (lambda r, t: (r / "certs.pem").write_text(PEM + "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEF\n"),
     "certs.pem holds a private key"),
])
def test_refused_trees(tmp_path, plugin, make, err):
    make(plugin, tmp_path)
    with pytest.raises(ExtensionError, match=err):
        _plan(tmp_path)


def test_a_relative_link_inside_the_plugin_is_fine(tmp_path, plugin):
    os.symlink("hello.py", plugin / "scripts" / "hi.py")
    (plugin / "bin" / ".DS_Store").write_text("x")  # Finder's: never staged, never linked
    df = _plan(tmp_path).derived_dockerfile
    assert "bin/.DS_Store" not in df and "/usr/local/bin/demo" in df


def test_a_dropped_skill_is_never_staged_so_never_checked(tmp_path, plugin):
    (plugin / "skills" / "other" / ".env").write_text("A=1\n")
    _write(plugin / "skills" / "other" / "tool.py", WITHDEP.replace("six==1.17.0", "never-baked==1"))
    plan = _plan(tmp_path, skills=["greet"])
    assert "never-baked" not in plan.derived_dockerfile  # nor its scripts' deps
    with pytest.raises(ExtensionError, match=r"skills/other/\.env looks like a credential file"):
        _plan(tmp_path)


def test_never_glove_state(tmp_path, plugin):
    os.makedirs(tmp_path / ".glove")
    os.rename(plugin.parent, tmp_path / ".glove" / "demo-repo")
    with pytest.raises(ConfigError, match=r"is glove state \(it overlaps .*/\.glove\)"):
        _plan_of(tmp_path, _cfg(tmp_path, "pi", {"demo": {"path": ".glove/demo-repo/demo"}}))


def test_never_a_plugin_the_agent_can_write(tmp_path, plugin):
    (tmp_path / "work").mkdir()
    os.rename(plugin.parent, tmp_path / "work" / "demo-repo")
    with pytest.raises(ConfigError, match=r"is writable by an agent \(it overlaps .*/work\)"):
        _plan_of(tmp_path, _cfg(tmp_path, "pi", {"demo": {"path": "work/demo-repo/demo"}}))
    # nor in a directory the session mounts read-write
    os.rename(tmp_path / "work" / "demo-repo", tmp_path / "skills" / "demo-repo")
    cfg = _cfg(tmp_path, "pi", {"demo": {"path": "skills/demo-repo/demo"}})
    cfg.add_dirs = [AddDir(path=str(tmp_path / "skills"), mode="rw")]
    with pytest.raises(ConfigError, match=r"is writable by an agent \(it overlaps .*/skills\)"):
        _plan_of(tmp_path, cfg)


@pytest.mark.parametrize("plugins, err", [
    ({"Demo": {"path": "skills"}}, "a plugin name is"),
    ({"demo": {}}, "want {path:"),
    ({"demo": {"path": "skills/demo-repo/demo", "relay": {}}}, r"relay: want \{commands"),
    ({"demo": {"path": "skills/demo-repo/demo", "x": 1}}, r"unknown keys \['x'\]"),
    ({"demo": {"path": "skills/missing"}}, "does not exist"),
    ({"demo": {"path": "skills/demo-repo/demo/scripts"}}, "neither a Claude Code plugin"),
])
def test_bad_plugin_blocks(tmp_path, plugin, plugins, err):
    with pytest.raises(ExtensionError, match=err):
        _plan_of(tmp_path, _cfg(tmp_path, "pi", plugins))


def test_materialize_creates_each_plugins_data_dir(tmp_path, plugin):
    plan = _plan(tmp_path)
    materialize(plan.composition)
    assert (tmp_path / "work" / ".glove-plugin-data" / "demo").is_dir()


def test_the_brief_names_each_plugin(tmp_path, plugin):
    brief = dict(_plan(tmp_path, skills=["greet"]).composition.rendered_briefs())["skills"]
    assert "Plugin **demo** is installed read-only at `/opt/glove/plugins/demo` (skills: greet)" in brief
    assert "never try to obtain, mint or store a credential yourself" in brief
    brief = dict(_plan(tmp_path).composition.rendered_briefs())["skills"]  # every skill: none named
    assert "at `/opt/glove/plugins/demo`; its writable data directory" in brief


def test_the_sessions_skills_dir_is_never_mounted(tmp_path, plugin):
    from glove.sessiondir import exposes_private

    assert exposes_private(tmp_path, tmp_path / "skills" / "demo-repo")[1] == "skills/"


def test_three_skills_of_one_name_all_get_a_link(tmp_path):
    plugins = {}
    for p in ("a", "b", "c"):
        _write(tmp_path / "skills" / p / "setup" / "SKILL.md", "---\nname: setup\n---\n")
        plugins[p] = {"path": f"skills/{p}"}
    links = _plan_of(tmp_path, _cfg(tmp_path, "claude-code", plugins)).composition.skill_links()
    assert links == [("setup", "/opt/glove/plugins/a/setup"), ("skills-setup", "/opt/glove/plugins/b/setup"),
                     ("skills-setup-2", "/opt/glove/plugins/c/setup")]


def test_skills_and_toolchains_share_one_uv_and_python(tmp_path, plugin):
    (tmp_path / "work").mkdir()
    cfg = make_cfg(harness="pi", name="s", workdir=str(tmp_path / "work"), extensions={
        "skills": {"plugins": {"demo": {"path": "skills/demo-repo/demo"}}},
        "toolchains": {"blocks": [{"lang": "python", "version": "3.12"}]}})
    df = _plan_of(tmp_path, cfg).derived_dockerfile
    shared = run_body(UV_HOME, *uv_python_steps("3.12"))
    # the same layer twice: the second finds uv and the Python in place
    assert df.count(shared) == 2 and df.index(shared) < df.index("pip compile")
    assert f"if [ ! -x {UV_HOME}/bin/uv ]; then" in shared
    assert f"&& ([ -e {UV_HOME}/python3.12 ] || ln -s" in shared  # grouped: an earlier failure still fails
    assert f'ln -s "$(readlink -f {UV_HOME}/python3.12)" /opt/glove/plugins/.uv/python3' in df
    assert f"venv --seed --python {UV_HOME}/python3.12 /opt/glove/toolchains/python/venv" in df
    assert not re.search(r"/opt/glove/(plugins/\.uv|toolchains/python)/(bin|python|runtime)\b", df)


@pytest.mark.parametrize(("requires", "python", "ok"), [
    (">=3.13", "3.12", False), ("<3.12", "3.12", False), (">=3.12.1", "3.12", True),
    ("~=3.12.0", "3.12", True), (">=3.11,!=3.13.*", "3.13", False), (">=3.11,!=3.13.*", "3.14", True)])
def test_a_scripts_requires_python_must_admit_the_python(tmp_path, plugin, requires, python, ok):
    (plugin / "scripts" / "hello.py").write_text(HELLO.replace(">=3.11", requires))
    cfg = _cfg(tmp_path, "pi", {"demo": {"path": "skills/demo-repo/demo"}})
    cfg.extensions["skills"]["python"] = python
    if ok:
        assert f"python install --no-bin {python}" in _plan_of(tmp_path, cfg).derived_dockerfile
    else:
        with pytest.raises(ExtensionError, match=rf"/opt/glove/plugins/demo/scripts/hello.py cannot run on "
                                                 rf"Python {python} \(its `requires-python`\)"):
            _plan_of(tmp_path, cfg)


def test_requires_python_binds_only_the_scripts_that_run_on_the_python(tmp_path, plugin):
    (plugin / "scripts" / "hello.py").write_text(HELLO.replace("-S uv run --script", "python3").replace(
        ">=3.11", ">=3.13"))  # the image's own python3, not `skills.python`
    assert "python install --no-bin 3.12" in _plan(tmp_path).derived_dockerfile


@pytest.mark.parametrize("requires", ['"3.12"', '">= three"', "3", '[">=3.11"]'])
def test_a_bad_requires_python_is_refused(tmp_path, plugin, requires):
    (plugin / "scripts" / "hello.py").write_text(HELLO.replace('">=3.11"', requires))
    with pytest.raises(ExtensionError, match=r"hello.py: `requires-python` is a version specifier"):
        _plan(tmp_path)
