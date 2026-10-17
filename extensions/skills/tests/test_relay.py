"""`skills` relays: a plugin's scripts run in a sidecar that holds their secrets
— the rendered sidecar, the shims, what is refused, the secrets at launch, and
the policy (what is relayed, and how)."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path

import pytest
import yaml
from helpers import PEM, hook_ctx, make_cfg, render

from glove.extensions import ExtensionError, launch_env, load_module, materialize

HERE = Path(__file__).resolve().parent.parent
hooks = load_module(HERE / "hooks.py", "skills")
API = ('#!/usr/bin/env -S uv run --script\n# /// script\n# dependencies = []\n# ///\n'
       'import os, sys\nprint("API", sys.argv[1:], os.environ.get("API_PAT"))\n')
COMMANDS = {"scripts/api.py": {"hosts": ["api.example.test", "*.files.example.test"], "allow": ["search", "fetch"],
                               "out_flags": ["-o", "--output"],
                               "env": {"API_PAT": "keychain:test-api-pat", "API_SPACE": "team"}}}


def _write(path, text, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(mode)


@pytest.fixture
def plugin(tmp_path):
    root = tmp_path / "skills" / "demo"
    _write(root / ".claude-plugin" / "plugin.json", '{"name": "demo"}')
    _write(root / "skills" / "api" / "SKILL.md", "Run `${CLAUDE_PLUGIN_ROOT}/scripts/api.py search x`.\n")
    _write(root / "scripts" / "api.py", API, 0o755)
    _write(root / "scripts" / "local.py", API, 0o755)
    _write(root / "scripts" / "dep.py", API.replace("[]", '["six"]'), 0o755)
    (tmp_path / "work").mkdir()
    (tmp_path / "local").mkdir()
    _write(tmp_path / "local" / "ws.json.j2", '{"token": "{{ secrets.tok }}"}\n')
    _write(tmp_path / "local" / "mint.sh", "#!/bin/sh\necho new\n", 0o755)
    return root


def _cfg(tmp_path, relay, harness="pi", egress=True, **kw):
    exts = {"skills": {"plugins": {"demo": {"path": "skills/demo", "relay": relay}}},
            **({"direct": {}} if egress else {})}
    return make_cfg(harness=harness, name="s", workdir=str(tmp_path / "work"), extensions=exts, **kw)


def _render(tmp_path, relay=None, **kw):
    plan, text = render(_cfg(tmp_path, relay or {"commands": COMMANDS}, **kw), tmp_path, session_dir=str(tmp_path))
    return plan, yaml.safe_load(text)


def test_the_relay_sidecar(tmp_path, plugin):
    plan, doc = _render(tmp_path, {"commands": COMMANDS, "check": ["scripts/api.py search glove"], "timeout": 60})
    svc = doc["services"]["glove-s-skill-demo"]
    assert svc["read_only"] is True and svc["cap_drop"] == ["ALL"] and svc["user"] != "0:0"
    assert "ports" not in svc and "secrets" not in svc
    assert svc["image"].startswith("glove/ext-relay-relayd:")  # the relay library, added for it
    assert svc["command"][2:] == ["--channel", "/run/glove/skill-demo", "--policy", hooks.RELAY_POLICY,
                                  "--work", "/work"]
    vols = {v["target"]: v for v in svc["volumes"]}
    assert vols["/work"]["source"] == os.path.realpath(tmp_path / "work")  # out_flags: the `work` privilege
    assert plan.composition.privileges["skills/skill-demo"] == [{"work": True}]
    assert vols[hooks.RELAY_POLICY]["read_only"] is True
    assert vols["/opt/glove/plugins/demo"] == {"type": "bind", "source": str(tmp_path / "ext" / "skills" / "relay"
                                                                              / "demo"),
                                               "target": "/opt/glove/plugins/demo", "read_only": True}
    assert vols["/run/glove/skill-demo"]["source"] == "glove-s-chan-skill-demo"
    harness = doc["services"]["glove-s-harness"]
    assert {"type": "volume", "source": "glove-s-chan-skill-demo", "target": "/run/glove/skill-demo"} \
        in harness["volumes"]
    env = svc["environment"]
    assert env["RELAY_TIMEOUT"] == "60" and env["RELAY_UPSTREAM"] == "http://glove-s-direct-proxy:8888"
    assert set(svc["networks"]) == {"glove-s-egress", "glove-s-skillnet"}
    settings = json.loads(env["RELAY_SETTINGS"])
    api = settings["commands"]["scripts/api.py"]
    assert api["hosts"] == ["api.example.test", "*.files.example.test"] and api["allow"] == ["search", "fetch"]
    pat = hooks._side("demo", "scripts/api.py", "env", "API_PAT")
    # named by what it carries: another command's, or a file's, never collides, and none moves with the order
    assert pat.startswith("SKILL_DEMO_") and pat not in {hooks._side("demo", "scripts/aaa.py", "env", "API_PAT"),
                                                         hooks._side("demo", "scripts/api.py", "file", "API_PAT")}
    assert api["env"] == {"API_SPACE": "team"} and api["secret_env"] == {"API_PAT": pat}
    assert api["python"] is True and settings["root"] == "/opt/glove/plugins/demo"
    assert env[pat] is None  # filled at `compose up`, never in the file
    assert "test-api-pat" not in yaml.safe_dump(doc)  # not even the reference
    # the checks: the sidecar up, then each through the relay, a warning unless required
    checks = [item for ext, item in plan.composition.verify if ext == "skills"]
    assert checks[0] == {"name": "skill-demo-up", "kind": "container-healthy", "service": "skill-demo"}
    assert checks[1] == {"name": "skill-demo-check-1", "kind": "exec-ok", "service": "skill-demo", "warn": True,
                         "timeout": 70, "argv": ["timeout", "60", "python3", hooks.RELAYD, "--call",
                                                 "/run/glove/skill-demo",
                                                 "scripts/api.py", "search", "glove"]}


def test_the_baked_script_is_a_shim_and_needs_no_uv(tmp_path, plugin):
    plan, _ = _render(tmp_path)
    df = plan.derived_dockerfile
    assert ("printf '%s\\n' '#!/bin/sh' 'exec /opt/glove/bin/glove-relay skill-demo scripts/api.py \"$@\"' > "
            "/opt/glove/plugins/demo/scripts/api.py && chmod a+rx /opt/glove/plugins/demo/scripts/api.py") in df
    assert "sed -i '1s|.*|#!/opt/glove/plugins/.uv/python3|' /opt/glove/plugins/demo/scripts/local.py" in df
    assert "#!/opt/glove/plugins/.uv/python3|' /opt/glove/plugins/demo/scripts/api.py" not in df
    assert "COPY relay/glove-relay /opt/glove/bin/glove-relay" in df  # the relay library's client


def test_no_work_privilege_without_file_flags_and_observe_labels_its_flows(tmp_path, plugin):
    commands = {"scripts/api.py": {**COMMANDS["scripts/api.py"], "out_flags": []}}
    cfg = _cfg(tmp_path, {"commands": commands})
    cfg.extensions["observe"] = {}
    plan, text = render(cfg, tmp_path, session_dir=str(tmp_path))
    doc = yaml.safe_load(text)
    svc = doc["services"]["glove-s-skill-demo"]
    assert "/work" not in {v["target"] for v in svc["volumes"]} and "--work" not in svc["command"]
    assert "skills/skill-demo" not in plan.composition.privileges
    assert set(svc["networks"]) == {"glove-s-skillnet"}  # only through its gate
    hop = next(s for s in plan.network.sidecars if s.role == "skill-demo-egress")
    assert hop.facts.get("client") == "skill-demo" and hop.facts.get("tool") == "skill"


def test_the_sidecar_trusts_the_sessions_corporate_ca(tmp_path, plugin):
    ca = tmp_path / "ca.pem"
    ca.write_text(PEM)
    _, doc = _render(tmp_path, corporate_ca=str(ca))
    svc = doc["services"]["glove-s-skill-demo"]
    assert {"type": "bind", "source": str(ca), "target": "/etc/glove/corporate-ca.pem", "read_only": True} \
        in svc["volumes"]
    assert svc["environment"]["GLOVE_CORPORATE_CA"] == "/etc/glove/corporate-ca.pem"


def test_without_a_relay_nothing_of_it_is_added(tmp_path, plugin):
    cfg = make_cfg(harness="pi", name="s", workdir=str(tmp_path / "work"),
                   extensions={"skills": {"plugins": {"demo": {"path": "skills/demo"}}}})
    plan, text = render(cfg, tmp_path, session_dir=str(tmp_path))
    names = [a.name for a in plan.composition.active]
    assert "relay" not in names and "direct" not in names
    assert "skillnet" not in plan.composition.networks and not plan.composition.channels
    assert "glove-s-skill-demo" not in yaml.safe_load(text)["services"]


def test_a_relay_needs_an_egress_provider(tmp_path, plugin):
    with pytest.raises(ExtensionError, match="requires the 'egress' slot"):
        _render(tmp_path, egress=False)


@pytest.mark.parametrize("relay,err", [
    ({"commands": {"scripts/dep.py": {"allow": ["*"]}}}, "standard library only"),
    ({"commands": {"scripts/nope.py": {"allow": ["*"]}}}, "not a file in what is baked"),
    ({"commands": {"../x.py": {"allow": ["*"]}}}, "a script's path in the plugin"),
    ({"commands": {"scripts/api.py": {"allow": []}}}, "allow lists the subcommands"),
    ({"commands": {"scripts/api.py": {"allow": ["*"], "hosts": ["https://x"]}}}, "a host name"),
    ({"commands": {"scripts/api.py": {"allow": ["*"], "out_flags": ["o"]}}}, "a flag"),
    ({"commands": {"scripts/api.py": {"allow": ["*"], "env": {"API_TOKEN": "literal"}}}}, "looks like a secret"),
    ({"commands": {"scripts/api.py": {"allow": ["*"], "env": {"HOME": "/x"}}}}, "does not set itself"),
    ({"commands": {"scripts/api.py": {"allow": ["*"], "env": {"A": {"secret": "env:X", "refresh": "local/mint.sh"}}}}},
     "stores into the Keychain"),
    ({"commands": {"scripts/api.py": {"allow": ["*"], "env": {"A": {"secret": "keychain:a",
                                                                     "refresh": "work/mint.sh"}}}}},
     "not a file in the session|agent can write"),
    ({"commands": {"scripts/api.py": {"allow": ["*"], "files": {"/etc/x": {"template": "local/ws.json.j2"}}}}},
     "under the script's home"),
    ({"commands": {"scripts/api.py": {"allow": ["*"], "files": {"~/x": {"template": "../ws.json.j2"}}}}},
     "a relative path in the session"),
    ({"commands": {"scripts/api.py": {"allow": ["*"]}}, "check": ["scripts/local.py x"]}, "a relayed command"),
    ({"commands": {"scripts/api.py": {"allow": ["*"], "bogus": 1}}}, "unknown keys"),
    ({"commands": {"scripts/api.py": {"allow": ["*"]}}, "timeout": 0}, "timeout is seconds"),
])
def test_refused_relays(tmp_path, plugin, relay, err):
    (tmp_path / "work" / "mint.sh").write_text("#!/bin/sh\n")
    with pytest.raises(ExtensionError, match=err):
        _render(tmp_path, relay)


def test_launch_resolves_the_secrets_and_renders_a_file_in_memory(tmp_path, plugin, monkeypatch):
    commands = copy.deepcopy(COMMANDS)
    commands["scripts/api.py"]["files"] = {"~/.config/ws.json": {"template": "local/ws.json.j2", "secrets": {
        "tok": {"secret": "keychain:test-ws", "refresh": "local/mint.sh"}}}}
    plan, doc = _render(tmp_path, {"commands": commands})
    from glove.plan import secret_refs

    assert {(lbl, ref) for lbl, ref in secret_refs(plan) if lbl.startswith("skills.")} == {  # for `glove check`
        ("skills.plugins.demo.relay (keychain:test-api-pat)", "keychain:test-api-pat"),
        ("skills.plugins.demo.relay (keychain:test-ws)", "keychain:test-ws")}
    skills = next(a for a in plan.composition.active if a.name == "skills")
    assert skills.contributed["egress_hosts"] == ["*.files.example.test", "api.example.test"]
    secrets = {"keychain:test-api-pat": "pat-1", "keychain:test-ws": "xo-2"}
    monkeypatch.setattr("glove.config.resolve_secret", lambda ref: secrets[ref])
    env = launch_env(plan.composition)
    ws = hooks._side("demo", "scripts/api.py", "file", "~/.config/ws.json")
    assert env[hooks._side("demo", "scripts/api.py", "env", "API_PAT")] == "pat-1"
    assert env[ws] == '{"token": "xo-2"}\n'
    settings = json.loads(doc["services"]["glove-s-skill-demo"]["environment"]["RELAY_SETTINGS"])
    assert settings["commands"]["scripts/api.py"]["files"] == {".config/ws.json": ws}
    ctx = hook_ctx(session_dir=tmp_path, work_dir=tmp_path / "work")
    relay = hooks._plugin(ctx, "demo", {"path": "skills/demo", "relay": {"commands": commands}})["relay"]
    assert relay.refresh == {"keychain:test-api-pat": None, "keychain:test-ws": tmp_path / "local" / "mint.sh"}
    # one secret, used twice: its hook counts wherever it is given
    commands["scripts/api.py"]["env"]["API_PAT"] = "keychain:test-ws"
    relay = hooks._plugin(ctx, "demo", {"path": "skills/demo", "relay": {"commands": commands}})["relay"]
    assert relay.refresh == {"keychain:test-ws": tmp_path / "local" / "mint.sh"}
    _write(tmp_path / "local" / "other.sh", "#!/bin/sh\n", 0o755)
    commands["scripts/api.py"]["env"]["API_PAT"] = {"secret": "keychain:test-ws", "refresh": "local/other.sh"}
    with pytest.raises(ValueError, match="already has another refresh hook"):
        hooks._plugin(ctx, "demo", {"path": "skills/demo", "relay": {"commands": commands}})
    assert not any("xo-2" in str(p.read_bytes()) for p in tmp_path.rglob("*") if p.is_file())  # never on disk


def test_materialize_stages_the_plugin_for_the_sidecar(tmp_path, plugin):
    plan, _ = _render(tmp_path)
    materialize(plan.composition)
    staged = tmp_path / "ext" / "skills" / "relay" / "demo"
    assert (staged / "scripts" / "api.py").read_text() == API  # the real script, not the shim
    assert (staged / "skills" / "api" / "SKILL.md").is_file()
    assert (tmp_path / "work" / ".glove-plugin-data" / "demo").is_dir()


def test_the_brief_names_the_relayed_scripts(tmp_path, plugin):
    plan, _ = _render(tmp_path)
    brief = dict(plan.composition.rendered_briefs())["skills"]
    assert "`scripts/api.py` (search, fetch)" in brief and "glove skills refresh <plugin>" in brief


def test_a_failed_check_suggests_a_refresh():
    hint = hooks.diagnose(hook_ctx(), {"kind": "exec-ok", "service": "skill-demo"}, None)
    assert "glove skills refresh demo" in hint
    assert hooks.diagnose(hook_ctx(), {"kind": "exec-ok", "service": "other"}, None) is None


# --- the policy --------------------------------------------------------------------


class Req:
    """relayd's Request, minus /proc: file arguments resolve inside `work` or are
    refused (with the policy's own refusal, as relayd's are caught alike)."""

    def __init__(self, policy, argv, work):
        self.refused, self.argv, self.cwd, self.work = policy.Refused, argv, str(work), str(work)

    def file(self, path):
        real = os.path.realpath(os.path.join(self.cwd, path))
        if not real.startswith(self.work + "/") or not os.path.isfile(real):
            raise self.refused(f"{path}: a file argument must be a regular file under {self.work}")
        return "/dev/fd/9"

    def directory(self, path):
        real = os.path.realpath(os.path.join(self.cwd, path))
        if not (real == self.work or real.startswith(self.work + "/")):
            raise self.refused(f"{path}: a destination must be under {self.work}")
        return real


def run(policy, work, *argv):
    return policy.prepare(Req(policy, list(argv), work), {})


@pytest.fixture
def policy(tmp_path, monkeypatch):
    settings = {"root": "/opt/glove/plugins/demo", "data": "/work/.glove-plugin-data/demo", "commands": {
        "scripts/api.py": {"hosts": ["api.example.test", "*.files.example.test"], "allow": ["search", "fetch"],
                           "out_flags": ["-o", "--output"], "in_flags": ["-f"], "env": {"API_SPACE": "team"},
                           "secret_env": {"API_PAT": "SKILL_DEMO_C0_E0"},
                           "files": {".config/ws.json": "SKILL_DEMO_C0_F0"}, "python": True},
        "bin/tool": {"hosts": [], "allow": ["*"], "env": {}, "secret_env": {}, "files": {}, "python": False}}}
    monkeypatch.setenv("RELAY_SETTINGS", json.dumps(settings))
    monkeypatch.setenv("SKILL_DEMO_C0_E0", "pat-1")
    monkeypatch.setenv("SKILL_DEMO_C0_F0", '{"token": "xo"}')
    p = load_module(HERE / "relay_policy.py", "skills")
    p.HOMES = str(tmp_path / "homes")
    p.setup({"proxy": None, "proxies": {"scripts/api.py": "http://127.0.0.1:4001"}, "work": "/work", "settings": {}})
    return p


@pytest.fixture
def work(tmp_path):
    w = tmp_path / "work"
    w.mkdir(exist_ok=True)
    (w / "q.sql").write_text("select 1")
    (w / "evil").symlink_to("/etc/passwd")
    return Path(os.path.realpath(w))


def test_the_policy_names_its_commands_and_one_fence_each(policy):
    assert sorted(policy.COMMANDS) == ["bin/tool", "scripts/api.py"]
    assert policy.HOSTS == {"scripts/api.py": ("api.example.test", ".files.example.test"), "bin/tool": ()}


def test_each_command_has_its_own_environment_and_home(policy, tmp_path):
    env = policy.ENVS["scripts/api.py"]
    home = Path(env["HOME"])
    assert home == tmp_path / "homes" / "1"  # sorted: bin/tool is 0
    assert env["API_PAT"] == "pat-1" and env["API_SPACE"] == "team"
    assert env["HTTPS_PROXY"] == "http://127.0.0.1:4001" and env["NO_PROXY"] == ""
    assert env["CLAUDE_PLUGIN_ROOT"] == "/opt/glove/plugins/demo"
    assert (home / ".config" / "ws.json").read_text() == '{"token": "xo"}'
    assert (home / ".config" / "ws.json").stat().st_mode & 0o777 == 0o600
    other = policy.ENVS["bin/tool"]
    assert "API_PAT" not in other and "HTTPS_PROXY" not in other and other["HOME"] != env["HOME"]


def test_allowed_subcommands_run_on_the_relay_python(policy, work):
    argv, env = run(policy, work, "scripts/api.py", "search", "glove", "-n", "1")
    assert argv == ["python3", "-s", "/opt/glove/plugins/demo/scripts/api.py", "search", "glove", "-n", "1"]
    assert env["API_PAT"] == "pat-1"
    assert run(policy, work, "scripts/api.py", "--help")[0][-1] == "--help"
    assert run(policy, work, "bin/tool", "anything")[0] == ["/opt/glove/plugins/demo/bin/tool", "anything"]


@pytest.mark.parametrize("args,err", [
    (["save-tokens", "x"], "save-tokens is not allowed here"),
    (["--verbose"], "its first argument is the subcommand"),
    (["--profile", "search", "mint"], "its first argument is the subcommand"),  # a global option's value
    (["-o", "out.md", "fetch"], "its first argument is the subcommand"),
    (["fetch", "evil"], "a path must be under /work"),  # a link in /work out of it
    (["fetch", "-o", "/etc/x"], "a destination must be under"),
    (["fetch", "--output=../../x"], "a destination must be under"),
    (["fetch", "-o/tmp/home/1/x"], "a destination must be under"),
    (["fetch", "-o"], "needs a path under /work"),
    (["fetch", "-f", "evil"], "a file argument must be"),
    (["fetch", "/tmp/home/1/.config/ws.json"], "a path must be under /work"),
    (["fetch", "~/.config/ws.json"], "a path must be under /work"),
    (["fetch", "../../tmp/x"], "a path must be under /work"),
    (["fetch", "--page=/etc/passwd"], "a path must be under /work"),
])
def test_refused_invocations(policy, work, args, err):
    with pytest.raises(policy.Refused, match=err):
        run(policy, work, "scripts/api.py", *args)


def test_without_work_a_name_in_the_relays_cwd_is_refused(policy, tmp_path):
    cwd = tmp_path / "cwd"
    (cwd / "creds").mkdir(parents=True)
    req = Req(policy, ["scripts/api.py", "fetch", "creds"], cwd)
    req.work = ""  # a relay without file flags: commands run in /tmp, no /work
    with pytest.raises(policy.Refused, match="a path must be under /work"):
        policy.prepare(req, {})
    req.argv = ["scripts/api.py", "fetch", "home"]  # a plain word: not a file there
    assert policy.prepare(req, {})[0][-1] == "home"


def test_reload_only_while_the_relay_is_as_rendered(tmp_path, plugin):
    cli = load_module(HERE / "cli.py", "skills")
    _, doc = _render(tmp_path)
    ctx = hook_ctx(session_dir=tmp_path, work_dir=tmp_path / "work")
    relay = hooks._plugin(ctx, "demo", {"path": "skills/demo", "relay": {"commands": COMMANDS}})["relay"]
    assert cli.rendered_as(doc["services"]["glove-s-skill-demo"], relay)
    commands = copy.deepcopy(COMMANDS)
    commands["scripts/aaa.py"] = commands["scripts/api.py"]  # sorts first: every index moves
    _write(plugin / "scripts" / "aaa.py", API, 0o755)
    moved = hooks._plugin(ctx, "demo", {"path": "skills/demo", "relay": {"commands": commands}})["relay"]
    assert not cli.rendered_as(doc["services"]["glove-s-skill-demo"], moved)
    assert not cli.rendered_as({}, relay)


def test_file_flags_are_rewritten_inside_work(policy, work):
    argv, _ = run(policy, work, "scripts/api.py", "fetch", "-o", "out.md", "--output=sub/x.md", "-f", "q.sql",
                  "-oy.md", str(work / "a.md"))
    assert argv[3:] == ["fetch", "-o", f"{work}/out.md", f"--output={work}/sub/x.md", "-f", "/dev/fd/9",
                        f"-o{work}/y.md", str(work / "a.md")]
