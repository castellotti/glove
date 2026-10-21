"""`github`: gh and network git relayed to a token-holding sidecar — the policy
(what is relayed, and how), its git hardening, and the rendered session."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml
from helpers import PEM, hook_ctx, make_cfg, render

from glove.extensions import ExtensionError, load_module

HERE = Path(__file__).resolve().parent.parent
policy = load_module(HERE / "relay_policy.py", "github")
Refused = policy.Refused


# what hooks.py renders for `token` alone
DEFAULT = {"allow": [], "git": list(policy.GIT_NET), "hosts": {"github.com": "RELAY_GITHUB_TOKEN"}}


class Req:
    """relayd's Request, minus /proc: file arguments resolve inside `work` or are refused."""

    def __init__(self, argv, cwd, work, settings=None):
        self.argv, self.cwd, self.work = argv, str(cwd), str(work)
        self.settings = {**DEFAULT, **(settings or {})}

    def _real(self, path):
        return os.path.realpath(path if path.startswith("/") else os.path.join(self.cwd, path))

    def file(self, path):
        if path == "-":
            raise Refused("no stdin")
        real = self._real(path)
        if not real.startswith(self.work + "/") or not os.path.isfile(real):
            raise Refused(f"{path}: a file argument must be a regular file under {self.work}")
        return "/dev/fd/9"

    def directory(self, path):
        real = self._real(path)
        if not (real == self.work or real.startswith(self.work + "/")):
            raise Refused(f"{path}: a destination must be under {self.work}")
        return real


@pytest.fixture
def work(tmp_path):
    w = tmp_path / "work"
    w.mkdir()
    (w / "body.md").write_text("hello")
    (w / "evil").symlink_to("/etc/passwd")
    return Path(os.path.realpath(w))


def gh(work, *args, settings=None):
    return policy.prepare(Req(["gh", *args], work, work, settings), {})[1:]


# --- gh -------------------------------------------------------------------------------


@pytest.mark.parametrize("args,why", [
    (["auth", "token"], "never relayed"),
    (["auth", "status"], "never relayed"),
    (["secret", "list"], "never relayed"),
    (["extension", "install", "o/r"], "never relayed"),
    (["alias", "set", "x", "y"], "never relayed"),
    (["config", "set", "editor", "x"], "never relayed"),
    (["codespace", "ssh"], "never relayed"),
    (["ssh-key", "add", "k"], "never relayed"),
    (["pr", "checkout", "1"], "github.allow"),
    (["repo", "delete", "o/r", "--yes"], "github.allow"),
    (["workflow", "run", "ci"], "github.allow"),
    (["--repo", "o/r", "pr", "list"], "name a gh command first"),
    (["api", "-X", "POST", "repos/o/r/issues"], "GET only"),
    (["api", "--method=DELETE", "repos/o/r"], "GET only"),
    (["api", "repos/o/r/issues", "-F", "title=x"], "-F"),
    (["api", "repos/o/r/issues", "--input", "body.md"], "--input"),
    (["api", "search/issues", "-f", "q=x"], "add -X GET"),
    (["api", "graphql", "-X", "GET", "-f", "query=x"], "no graphql"),
    (["api", "graphql", "-f", "query=x"], "no graphql"),
    (["api", "https://evil.example/x"], "no URL"),
    (["api", "repos/o/r", "--hostname", "evil.example"], "github.com only"),
    (["api", "repos/o/r", "-H", "X-HTTP-Method-Override: POST"], "method-override"),
    (["api"], "needs an endpoint"),
    (["pr", "list", "-R", "evil.example/o/r"], "github.com only"),
    (["pr", "list", "--repo=https://evil.example/o/r"], "github.com"),
    (["pr", "list", "--hostname", "ghe.example"], "github.com only"),
    (["pr", "create", "-t", "x", "--body-file", "/etc/passwd"], "under"),
    (["pr", "create", "-t", "x", "--body-file", "evil"], "under"),      # a symlink out of /work
    (["pr", "create", "-t", "x", "-F", "-"], "no stdin"),
    (["pr", "create", "-t", "x", "-Fbody.md"], "one by one"),            # attached value
    (["pr", "create", "-dF", "body.md"], "one by one"),                  # combined short options
    (["pr", "create", "--recover", "/work/x.json"], "reads a file"),
    (["issue", "create", "--template", "../../etc/passwd"], "reads a file"),
    (["pr", "create", "--", "--upload-pack=x"], "`--`"),
    (["repo", "clone", "o/r", "--", "--template=/x"], "only"),
    (["repo", "clone", "o/r", "/etc"], "under"),
    (["repo", "clone", "evil.example/o/r"], "github.com only"),
])
def test_gh_refuses(work, args, why):
    with pytest.raises(Refused, match=why.replace("(", r"\(").replace("`", "`")):
        gh(work, *args)


def test_gh_a_boolean_flag_never_hides_a_file_argument(work):
    # `-r` (rebase) is a boolean: a scanner that thought it took a value would
    # skip `--body-file` and pass /etc/passwd through unread
    with pytest.raises(Refused, match="under"):
        gh(work, "pr", "merge", "5", "-r", "--body-file", "/etc/passwd")


def test_gh_rewrites_file_and_directory_arguments(work):
    assert gh(work, "pr", "create", "-t", "x", "--body-file", "body.md") == [
        "pr", "create", "-t", "x", "--body-file", "/dev/fd/9"]
    assert gh(work, "issue", "comment", "3", "--body-file=body.md")[-2:] == ["--body-file", "/dev/fd/9"]
    assert gh(work, "pr", "review", "3", "-F", "body.md", "--approve")[-3:] == ["-F", "/dev/fd/9", "--approve"]
    assert gh(work, "run", "download", "7", "-D", "out") == ["run", "download", "7", "-D", f"{work}/out"]
    assert gh(work, "repo", "clone", "octocat/Hello-World", "hello") == [
        "repo", "clone", "octocat/Hello-World", f"{work}/hello"]


def test_gh_allowed_commands_pass_through(work):
    assert gh(work, "pr", "list", "-R", "o/r", "--state", "open") == ["pr", "list", "-R", "o/r", "--state", "open"]
    assert gh(work, "api", "repos/o/r", "--jq", ".full_name") == ["api", "repos/o/r", "--jq", ".full_name"]
    assert gh(work, "api", "-X", "GET", "search/issues", "-f", "q=repo:o/r") == [
        "api", "-X", "GET", "search/issues", "-f", "q=repo:o/r"]
    assert gh(work, "pr", "list", "-R", "github.com/o/r")[-1] == "github.com/o/r"
    assert gh(work, "browse", "-R", "o/r")[-1] == "--no-browser"
    assert gh(work, "--version") == ["--version"]


def test_gh_allow_setting_replaces_the_default_but_never_the_refused(work):
    s = {"allow": ["pr list", "label"]}
    assert gh(work, "label", "list", settings=s) == ["label", "list"]
    with pytest.raises(Refused, match=r"github\.allow"):
        gh(work, "pr", "view", "1", settings=s)
    with pytest.raises(Refused, match="never relayed"):
        gh(work, "auth", "token", settings={"allow": ["auth"]})


# --- git ------------------------------------------------------------------------------


def _env(tmp_path):
    os.environ["RELAY_GITHUB_TOKEN"] = "tok-123"
    try:
        return policy.setup({"proxy": "http://127.0.0.1:9", "settings": DEFAULT, "work": str(tmp_path)})
    finally:
        del os.environ["RELAY_GITHUB_TOKEN"]


def _repo(path: Path, **remotes) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", "-b", "main", str(path)], check=True)
    for name, url in remotes.items():
        subprocess.run(["git", "-C", str(path), "remote", "add", name, url], check=True)
    return path


def git(work, cwd, *args, env=None):
    return policy.prepare(Req(["git", *args], cwd, work), env or _env(work))[1:]


@pytest.mark.parametrize("args,why", [
    (["status"], "only git push"),
    (["-c", "core.sshCommand=x", "push"], "only git push"),
    (["push", "--receive-pack=touch /work/x", "origin"], "runs programs"),
    (["fetch", "--upload-pack", "x", "origin"], "runs programs"),
    (["fetch", "--upload=x", "origin"], "in full"),                     # git's abbreviations
    (["ls-remote", "-u", "x", "https://github.com/o/r"], "runs programs"),
    (["clone", "-u", "x", "https://github.com/o/r"], "runs programs"),
    (["clone", "--templ=/work/t", "https://github.com/o/r"], "in full"),
    (["clone", "--config", "core.hooksPath=/work", "https://github.com/o/r"], "runs programs"),
    (["clone", "--recurse-submodules", "https://github.com/o/r"], "runs programs"),
    (["clone", "--separate-git-dir=/tmp/x", "https://github.com/o/r"], "runs programs"),
    (["push", "--signed", "origin"], "runs programs"),
    (["clone", "-qn", "https://github.com/o/r"], "one by one"),
    (["clone", "https://gitlab.com/o/r.git"], "<host>/<owner>/<repo> only"),
    (["clone", "git@github.com:o/r.git"], "<host>/<owner>/<repo> only"),
    (["clone", "https://github.com.evil.example/o/r"], "<host>/<owner>/<repo> only"),
    (["clone", "https://github.com/o/r", "/etc/x"], "under"),
    (["ls-remote", "https://evil.example/o/r.git"], "<host>/<owner>/<repo> only"),
])
def test_git_refuses(work, args, why):
    with pytest.raises(Refused, match=why.replace("(", r"\(")):
        git(work, work, *args)


def test_git_remotes_must_resolve_to_github(work):
    repo = _repo(work / "r", origin="https://github.com/o/r.git", up="https://gitlab.com/o/r.git")
    env = _env(work)
    assert git(work, repo, "push", "-u", "origin", "main", env=env) == ["push", "-u", "origin", "main"]
    assert git(work, repo, "fetch", env=env) == ["fetch"]
    with pytest.raises(Refused, match=r"<host>/<owner>/<repo> only, the host one of github\.com"):
        git(work, repo, "fetch", "up", env=env)
    with pytest.raises(Refused, match=r"<host>/<owner>/<repo> only, the host one of github\.com"):
        git(work, repo, "fetch", "--all", env=env)
    with pytest.raises(Refused, match="not a remote"):
        git(work, repo, "push", "nope", env=env)
    # a push URL elsewhere: fetch is fine, push is not
    subprocess.run(["git", "-C", str(repo), "remote", "set-url", "--push", "origin", "https://evil.example/x"],
                   check=True)
    assert git(work, repo, "fetch", "origin", env=env) == ["fetch", "origin"]
    with pytest.raises(Refused, match="only"):
        git(work, repo, "push", "origin", env=env)
    # the default push remote is the branch's pushRemote
    subprocess.run(["git", "-C", str(repo), "remote", "set-url", "--delete", "--push", "origin", "evil"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "branch.main.pushRemote", "up"], check=True)
    with pytest.raises(Refused, match="only"):
        git(work, repo, "push", env=env)


def test_git_url_rewrites_are_resolved(work):
    repo = _repo(work / "r", origin="https://github.com/o/r.git")
    subprocess.run(["git", "-C", str(repo), "config", "url.https://evil.example/.insteadOf", "https://github.com/"],
                   check=True)
    with pytest.raises(Refused, match="only"):
        git(work, repo, "push", "origin")
    with pytest.raises(Refused, match="rewrites URLs"):
        git(work, repo, "push", "https://github.com/o/r.git")


def test_the_rewrite_lookup_runs_once_and_only_for_url_remotes(work, monkeypatch):
    repo = _repo(work / "r", origin="https://github.com/o/r.git")
    calls = []
    real = policy._git_out
    monkeypatch.setattr(policy, "_git_out", lambda req, env, *a: calls.append(a) or real(req, env, *a))
    git(work, repo, "fetch", "--multiple", "https://github.com/o/r", "https://github.com/o/s")
    assert [a for a in calls if "--get-regexp" in a] == [("config", "--get-regexp", r"^url\..*insteadof$")]
    calls.clear()
    git(work, repo, "fetch", "origin")
    assert not [a for a in calls if "--get-regexp" in a]


def test_clone_destination_is_rewritten_inside_work(work):
    assert git(work, work, "clone", "-b", "main", "https://github.com/o/r.git", "sub/r") == [
        "clone", "-b", "main", "https://github.com/o/r.git", f"{work}/sub/r"]
    # the destination word itself, not a later option value that spells it too
    assert git(work, work, "clone", "https://github.com/o/r", "up", "-o", "up") == [
        "clone", "https://github.com/o/r", f"{work}/up", "-o", "up"]
    assert git(work, work, "clone", "--", "https://github.com/o/r", "up") == [
        "clone", "--", "https://github.com/o/r", f"{work}/up"]


def test_children_get_a_fresh_environment_and_defanged_git(work):
    env = _env(work)
    assert env["GH_TOKEN"] == "tok-123" and env["HTTPS_PROXY"] == "http://127.0.0.1:9"
    assert env["GIT_CONFIG_GLOBAL"] == "/dev/null" and env["GIT_TERMINAL_PROMPT"] == "0"
    pairs = {env[f"GIT_CONFIG_KEY_{i}"]: env[f"GIT_CONFIG_VALUE_{i}"] for i in range(int(env["GIT_CONFIG_COUNT"]))}
    assert pairs["core.hooksPath"] == "/dev/null" and pairs["protocol.allow"] == "never"
    assert pairs["http.proxy"] == "http://127.0.0.1:9" and "PATH" in env and "RELAY_GITHUB_TOKEN" not in env
    with pytest.raises(SystemExit):
        policy.setup({"proxy": "x", "settings": DEFAULT, "work": str(work)})


def test_a_hostile_repo_config_cannot_run_code_or_take_the_token(work, tmp_path):
    """The agent owns .git/config: its hooks path, fsmonitor and credential
    helpers are overridden; ours answers for github.com only."""
    repo = _repo(work / "r", origin="https://github.com/o/r.git")
    mark = tmp_path / "ran"
    for k, v in [("core.hooksPath", str(work)), ("core.fsmonitor", f"touch {mark}"),
                 ("credential.helper", f"!touch {mark}; echo password=stolen"),
                 ("credential.https://github.com.helper", f"!touch {mark}")]:
        subprocess.run(["git", "-C", str(repo), "config", "--add", k, v], check=True)
    env = {**_env(work), "PATH": os.environ["PATH"]}

    def cfg(key):
        return subprocess.run(["git", "config", "--get", key], cwd=repo, env=env, capture_output=True,
                              text=True).stdout.strip()

    assert cfg("core.hooksPath") == "/dev/null" and cfg("core.fsmonitor") == "false"

    def fill(host):
        r = subprocess.run(["git", "credential", "fill"], cwd=repo, env=env, capture_output=True, text=True,
                           input=f"protocol=https\nhost={host}\n\n", timeout=20)
        return r.stdout

    out = fill("github.com")
    assert "password=tok-123" in out and "stolen" not in out and not mark.exists()
    assert "tok-123" not in fill("evil.example") and not mark.exists()


# --- the session ----------------------------------------------------------------------

CC_LLM = {"provider": "anthropic-compatible", "location": "host", "endpoint": "127.0.0.1:8080", "model": "m"}


def _render(tmp_path, harness="claude-code", observe=False, enforcer=None, corporate_ca=None, **gh_settings):
    exts = {"direct": {}, "github": {"token": "env:GH_TEST", **gh_settings}, **({"observe": {}} if observe else {})}
    if harness == "claude-code":
        exts["llm"] = CC_LLM
    cfg = make_cfg(harness=harness, name="s", workdir=str(tmp_path / "w"), extensions=exts,
                   **({"enforcer": enforcer} if enforcer else {}),
                   **({"corporate_ca": corporate_ca} if corporate_ca else {}))
    (tmp_path / "w").mkdir(exist_ok=True)
    plan, text = render(cfg, tmp_path)
    return plan, yaml.safe_load(text)


@pytest.mark.parametrize("observe", [False, True])
def test_the_relay_sidecar(tmp_path, observe):
    plan, doc = _render(tmp_path, observe=observe)
    svc = doc["services"]["glove-s-gh"]
    assert svc["read_only"] is True and svc["cap_drop"] == ["ALL"] and svc["user"] != "0:0"
    assert "ports" not in svc and "secrets" not in svc
    work = os.path.realpath(tmp_path / "w")
    vols = {v["target"]: v for v in svc["volumes"]}
    assert vols["/work"] == {"type": "bind", "source": work, "target": "/work"}  # the `work` privilege, rw
    assert vols["/opt/glove/github/relay_policy.py"]["read_only"] is True
    assert vols["/run/glove/github"] == {"type": "volume", "source": "glove-s-chan-github",
                                         "target": "/run/glove/github"}
    assert plan.composition.privileges["github/gh"] == [{"work": True}]
    assert svc["environment"]["RELAY_GITHUB_TOKEN"] is None  # filled at `compose up`, never in the file
    assert svc["command"] == ["relayd", "--channel", "/run/glove/github",
                              "--policy", "/opt/glove/github/relay_policy.py", "--work", "/work"]
    assert svc["healthcheck"]["test"] == ["CMD", "test", "-p", "/run/glove/github/door"]
    assert json.loads(svc["environment"]["RELAY_SETTINGS"]) == DEFAULT
    assert svc["image"].startswith("glove/ext-relay-relayd:")
    if observe:  # only through its own gate, labelled for Layman
        assert set(svc["networks"]) == {"glove-s-ghnet"}
        assert svc["environment"]["RELAY_UPSTREAM"] == "http://glove-s-github-egress:8888"
        hop = next(s for s in plan.network.sidecars if s.role == "github-egress")
        assert not hop.harness and hop.facts.get("client") == "github" and hop.facts.get("tool") == "gh"
    else:
        assert set(svc["networks"]) == {"glove-s-egress", "glove-s-ghnet"}
        assert svc["environment"]["RELAY_UPSTREAM"] == "http://glove-s-direct-proxy:8888"


def test_the_sidecar_trusts_the_sessions_corporate_ca_read_only(tmp_path):
    from glove.cafile import TRUST_DIR, TRUST_ENV

    plan, doc = _render(tmp_path)
    svc = doc["services"]["glove-s-gh"]
    assert not set(TRUST_ENV) & set(svc["environment"]) and svc["command"][0] == "relayd"
    assert TRUST_DIR not in {v["target"] for v in svc["volumes"]}
    ca = tmp_path / "ca.pem"
    ca.write_text(PEM)
    plan, doc = _render(tmp_path, corporate_ca=str(ca))
    svc = doc["services"]["glove-s-gh"]
    assert {k: svc["environment"][k] for k in TRUST_ENV} == TRUST_ENV  # relayd passes them to gh and git
    assert {v["target"]: v for v in svc["volumes"]}[TRUST_DIR] == {
        "type": "bind", "source": plan.trust_host_dir, "target": TRUST_DIR, "read_only": True}
    assert svc["entrypoint"][3:] == ["glove-trust"] and svc["command"][0] == "relayd"  # the bundle first


def test_on_selinux_the_cas_copy_is_relabelled(tmp_path, monkeypatch):
    # TODO 1f: glove's own copy in .glove/trust/, never the operator's file, so `z` is safe
    from glove.cafile import TRUST_DIR
    from glove.plan import build_session_plan
    from glove.runtimes.podman import PodmanRuntime

    monkeypatch.setattr(PodmanRuntime, "selinux_enabled", lambda self: True)
    ca = tmp_path / "ca.pem"
    ca.write_text(PEM)
    (tmp_path / "w").mkdir()
    cfg = make_cfg(harness="claude-code", name="s", workdir=str(tmp_path / "w"), corporate_ca=str(ca),
                   extensions={"direct": {}, "github": {"token": "env:GH_TEST"}, "llm": CC_LLM})
    plan = build_session_plan(cfg, home_dir=str(tmp_path / "home"), state_dir=str(tmp_path / "ext"))
    rt = PodmanRuntime()
    rt._rootless = True
    services = yaml.safe_load(rt.render(plan, tmp_path).compose_yaml)["services"]
    for name in ("glove-s-gh", "glove-s-harness"):
        vols = {v["target"]: v for v in services[name]["volumes"]}
        assert vols[TRUST_DIR]["bind"] == {"selinux": "z"} and vols[TRUST_DIR]["source"] == plan.trust_host_dir


@pytest.mark.parametrize("harness", ["claude-code", "pi", "vibe"])
def test_the_harness_gets_the_channel_and_the_shims_but_no_route(tmp_path, harness):
    plan, doc = _render(tmp_path, harness=harness)
    h = doc["services"]["glove-s-harness"]
    assert {"type": "volume", "source": "glove-s-chan-github", "target": "/run/glove/github"} in h["volumes"]
    assert list(h["networks"]) == ["glove-s-net"]
    assert not any("TOKEN" in k for k in h["environment"])
    # fresh checkouts read as root-owned through Docker Desktop's file sharing
    assert h["environment"]["GIT_CONFIG_PARAMETERS"] == "'safe.directory'='/work' 'safe.directory'='*'"
    assert "COPY relay/glove-relay /opt/glove/bin/glove-relay" in plan.derived_dockerfile
    assert "COPY github/gh /usr/local/bin/gh" in plan.derived_dockerfile
    assert "COPY github/git /usr/local/bin/git" in plan.derived_dockerfile
    assert doc["volumes"]["glove-s-chan-github"]["driver_opts"]["type"] == "tmpfs"
    assert "github-egress" not in {s.role for s in plan.network.sidecars if s.harness}


@pytest.mark.parametrize("enforcer", ["nono", "nono+srt", "srt"])
def test_every_enforcer_grants_the_channel_and_no_network(tmp_path, enforcer):
    plan, _ = _render(tmp_path, enforcer=enforcer)
    p = plan.policies
    if enforcer == "srt":
        s = json.loads(p["srt-settings.json"])
        assert "/run/glove/github" in s["filesystem"]["allowWrite"] and s["network"]["allowedDomains"] == []
        return
    tool = json.loads(p["tool.json"])
    assert "/run/glove/github" in tool["filesystem"]["allow"] and tool["network"] == {"block": True}
    if enforcer == "nono":
        assert "/run/glove/github" in json.loads(p["harness.json"])["filesystem"]["allow"]
    else:
        assert "/run/glove/github" in json.loads(p["srt-harness.json"])["filesystem"]["allowWrite"]


def test_requires_egress_and_a_token_reference(tmp_path):
    with pytest.raises(ExtensionError, match="'egress' slot"):
        make_cfg_plan(tmp_path, {"llm": CC_LLM, "github": {"token": "env:X"}})
    with pytest.raises(ExtensionError, match="secret"):
        make_cfg_plan(tmp_path, {"llm": CC_LLM, "direct": {}, "github": {"token": "ghp_literal"}})
    with pytest.raises(ExtensionError, match="needs a token"):
        make_cfg_plan(tmp_path, {"llm": CC_LLM, "direct": {}, "github": {}})
    with pytest.raises(ExtensionError, match="must match"):
        make_cfg_plan(tmp_path, {"llm": CC_LLM, "direct": {}, "github": {"token": "env:X", "allow": ["pr; rm"]}})


def make_cfg_plan(tmp_path, exts):
    from glove.plan import build_session_plan

    cfg = make_cfg(harness="claude-code", name="s", workdir=str(tmp_path), extensions=exts)
    return build_session_plan(cfg, home_dir=str(tmp_path / "h"), state_dir=str(tmp_path / "x"))


def test_launch_env_resolves_the_token_in_memory():
    hooks = load_module(HERE / "hooks.py", "github")
    assert hooks.launch_env(hook_ctx(settings={"token": "keychain:svc"}), lambda ref: "tok\n") == {
        "env": {"RELAY_GITHUB_TOKEN": "tok"}}
    with pytest.raises(ValueError, match="empty"):
        hooks.launch_env(hook_ctx(settings={"token": "env:X"}), lambda ref: " ")


def test_shims_are_valid_bash():
    for f in ("shim/gh", "shim/git"):
        assert os.access(HERE / f, os.X_OK)
        subprocess.run(["bash", "-n", str(HERE / f)], check=True)


# --- GitHub Enterprise hosts, git verbs -----------------------------------------------

GHE = {**DEFAULT, "hosts": {"ghe.corp.example": "RELAY_GITHUB_TOKEN_1", "git.other.example": "RELAY_GITHUB_TOKEN_2"}}
BOTH = {**DEFAULT, "hosts": {"github.com": "RELAY_GITHUB_TOKEN", "ghe.corp.example": "RELAY_GITHUB_TOKEN_1"}}


def test_the_fence_tunnels_to_the_served_hosts_only():
    assert policy.fence_hosts(DEFAULT) == policy.GITHUB_HOSTS
    assert policy.fence_hosts(GHE) == ("ghe.corp.example", ".ghe.corp.example", "git.other.example",
                                       ".git.other.example")
    assert policy.fence_hosts(BOTH) == (*policy.GITHUB_HOSTS, "ghe.corp.example", ".ghe.corp.example")


@pytest.mark.parametrize("args,ok", [
    (["pr", "list", "-R", "ghe.corp.example/o/r"], True),
    (["pr", "list", "--repo=https://git.other.example/o/r.git"], True),
    (["pr", "list", "-R", "o/r"], True),                      # the default host (GH_HOST)
    (["pr", "list", "--hostname", "GHE.corp.example."], True),
    (["api", "repos/o/r", "--hostname", "git.other.example"], True),
    (["repo", "clone", "ghe.corp.example/o/r"], True),
    (["pr", "list", "-R", "github.com/o/r"], False),           # no github.com token: not served
    (["api", "repos/o/r", "--hostname", "github.com"], False),
    (["pr", "list", "-R", "evil.ghe.corp.example/o/r"], False),
    (["pr", "list", "--repo=https://ghe.corp.example.evil/o/r"], False),
    (["repo", "clone", "https://github.com/o/r"], False),
])
def test_gh_names_only_served_hosts(work, args, ok):
    if ok:
        assert gh(work, *args, settings=GHE)
    else:
        with pytest.raises(Refused, match=r"serves ghe\.corp\.example, git\.other\.example only|the host one of"):
            gh(work, *args, settings=GHE)


def _ghe_env(work, settings, **tokens):
    os.environ.update(tokens)
    try:
        return policy.setup({"proxy": "http://127.0.0.1:9", "settings": settings, "work": str(work)})
    finally:
        for k in tokens:
            del os.environ[k]


def test_git_reaches_only_served_hosts_and_only_the_listed_verbs(work):
    env = _ghe_env(work, GHE, RELAY_GITHUB_TOKEN_1="t1", RELAY_GITHUB_TOKEN_2="t2")

    def run(*args, settings=GHE, cwd=work):
        return policy.prepare(Req(["git", *args], cwd, work, settings), env)[1:]

    assert run("clone", "https://ghe.corp.example/o/r.git") == ["clone", "https://ghe.corp.example/o/r.git"]
    with pytest.raises(Refused, match=r"the host one of ghe\.corp\.example, git\.other\.example"):
        run("clone", "https://github.com/o/r")
    repo = _repo(work / "r", origin="https://git.other.example/o/r.git")
    assert run("push", "origin", "main", cwd=repo) == ["push", "origin", "main"]
    read_only = {**GHE, "git": ["fetch", "clone", "ls-remote"]}
    assert run("fetch", "origin", settings=read_only, cwd=repo) == ["fetch", "origin"]
    with pytest.raises(Refused, match=r"only git fetch, clone, ls-remote \(and pull\) are relayed in this session"):
        run("push", "origin", "main", settings=read_only, cwd=repo)
    with pytest.raises(Refused, match="only git clone are relayed"):
        run("fetch", settings={**GHE, "git": ["clone"]}, cwd=repo)


def test_each_host_gets_its_own_token(work):
    """gh: github.com's from GH_TOKEN, an Enterprise host's from hosts.yml
    (0600, gh's current layout); git: one credential helper per host."""
    env = {**_ghe_env(work, BOTH, RELAY_GITHUB_TOKEN="gh-tok", RELAY_GITHUB_TOKEN_1="ghe-tok"),
           "PATH": os.environ["PATH"]}
    assert env["GH_TOKEN"] == "gh-tok" and "GH_HOST" not in env and "GH_ENTERPRISE_TOKEN" not in env
    assert env["RELAY_GITHUB_TOKEN_1"] == "ghe-tok" and "RELAY_GITHUB_TOKEN" not in env  # git's helper reads it
    hosts_yml = Path(env["GH_CONFIG_DIR"]) / "hosts.yml"
    assert hosts_yml.stat().st_mode & 0o777 == 0o600
    doc = yaml.safe_load(hosts_yml.read_text())
    assert doc == {"ghe.corp.example": {"git_protocol": "https", "user": "x-access-token", "oauth_token": "ghe-tok",
                                        "users": {"x-access-token": {"oauth_token": "ghe-tok"}}}}
    assert yaml.safe_load((Path(env["GH_CONFIG_DIR"]) / "config.yml").read_text())["version"] == "1"
    repo = _repo(work / "r")

    def fill(host):
        return subprocess.run(["git", "credential", "fill"], cwd=repo, env=env, capture_output=True, text=True,
                              input=f"protocol=https\nhost={host}\n\n", timeout=20).stdout

    assert "password=gh-tok" in fill("github.com") and "password=ghe-tok" in fill("ghe.corp.example")
    assert "tok" not in fill("evil.example") and "tok" not in fill("api.ghe.corp.example.evil")
    # Enterprise only: no github.com token anywhere, the first host is gh's default
    env = _ghe_env(work, GHE, RELAY_GITHUB_TOKEN_1="t1", RELAY_GITHUB_TOKEN_2="t2")
    assert "GH_TOKEN" not in env and env["GH_HOST"] == "ghe.corp.example"
    pairs = {env[f"GIT_CONFIG_KEY_{i}"] for i in range(int(env["GIT_CONFIG_COUNT"]))}
    assert "credential.https://github.com.helper" not in pairs
    with pytest.raises(SystemExit, match=r"git\.other\.example"):
        _ghe_env(work, GHE, RELAY_GITHUB_TOKEN_1="t1")


hooks = load_module(HERE / "hooks.py", "github")


@pytest.mark.parametrize("settings,why", [
    ({}, "needs a token"),
    ({"hosts": [{"host": "ghe.example"}]}, "must be"),
    ({"hosts": [{"host": "ghe.example", "token": "ghp_x"}]}, "a reference"),
    ({"hosts": [{"host": "github.com", "token": "env:X"}]}, "github.token"),
    ({"hosts": [{"host": "api.github.com", "token": "env:X"}]}, "github.token"),
    ({"hosts": [{"host": "octo.ghe.com", "token": "env:X"}]}, "ghe.com"),
    ({"hosts": [{"host": "10.0.0.1", "token": "env:X"}]}, "not a host name"),
    ({"hosts": [{"host": "ghe", "token": "env:X"}]}, "not a host name"),
    ({"hosts": [{"host": "https://ghe.example", "token": "env:X"}]}, "not a host name"),
    ({"hosts": [{"host": "a.example", "token": "env:X"}, {"host": "A.example.", "token": "env:Y"}]}, "twice"),
])
def test_hosts_are_checked(settings, why):
    with pytest.raises(ValueError, match=why):
        hooks.hosts(settings)


def test_contribute_names_each_hosts_token_and_its_reference():
    s = {"token": "keychain:gh", "hosts": [{"host": "GHE.corp.example", "token": "keychain:ghe"}], "allow": None,
         "git": ["fetch"]}
    assert hooks.contribute(hook_ctx(settings=s)) == {
        "vars": {"settings": {"allow": [], "git": ["fetch"], "hosts": {"github.com": "RELAY_GITHUB_TOKEN",
                                                                       "ghe.corp.example": "RELAY_GITHUB_TOKEN_1"}},
                 "tokens": ["RELAY_GITHUB_TOKEN", "RELAY_GITHUB_TOKEN_1"]},
        "egress_hosts": [*(f"*{h}" if h.startswith(".") else h for h in policy.GITHUB_HOSTS), "ghe.corp.example",
                         "*.ghe.corp.example"],
        "secret_refs": {"hosts.ghe.corp.example": "keychain:ghe"}}  # `token`: core checks it (a secret setting)
    assert hooks.launch_env(hook_ctx(settings=s), lambda ref: f"{ref}-value\n") == {
        "env": {"RELAY_GITHUB_TOKEN": "keychain:gh-value", "RELAY_GITHUB_TOKEN_1": "keychain:ghe-value"}}
    with pytest.raises(ValueError, match=r"ghe\.corp\.example resolves to an empty value"):
        hooks.launch_env(hook_ctx(settings=s), lambda ref: "" if ref == "keychain:ghe" else "x")


def test_the_sidecar_gets_a_token_per_host(tmp_path):
    _, doc = _render(tmp_path, hosts=[{"host": "ghe.corp.example", "token": "env:GHE"}], git=["fetch"])
    env = doc["services"]["glove-s-gh"]["environment"]
    assert env["RELAY_GITHUB_TOKEN"] is None and env["RELAY_GITHUB_TOKEN_1"] is None
    assert json.loads(env["RELAY_SETTINGS"]) == {"allow": [], "git": ["fetch"], "hosts": {
        "github.com": "RELAY_GITHUB_TOKEN", "ghe.corp.example": "RELAY_GITHUB_TOKEN_1"}}
    plan = make_cfg_plan(tmp_path, {"llm": CC_LLM, "direct": {}, "github": {
        "hosts": [{"host": "ghe.corp.example", "token": "keychain:ghe"}]}})
    from glove.plan import secret_refs

    assert ("github.hosts.ghe.corp.example", "keychain:ghe") in secret_refs(plan)
    assert not [label for label, _ in secret_refs(plan) if label == "github.token"]
    plan = make_cfg_plan(tmp_path, {"llm": CC_LLM, "direct": {}, "github": {
        "token": "keychain:gh", "hosts": [{"host": "ghe.corp.example", "token": "keychain:ghe"}]}})
    assert [r for r in secret_refs(plan) if r[0].startswith("github.")] == [
        ("github.token", "keychain:gh"), ("github.hosts.ghe.corp.example", "keychain:ghe")]  # each once
    with pytest.raises(ExtensionError, match="must match"):
        make_cfg_plan(tmp_path, {"llm": CC_LLM, "direct": {}, "github": {"token": "env:X", "git": ["gc"]}})


def test_the_brief_names_the_served_hosts_and_verbs(tmp_path):
    def brief(gh_settings):
        plan = make_cfg_plan(tmp_path, {"llm": CC_LLM, "direct": {}, "github": gh_settings})
        return dict(plan.composition.rendered_briefs())["github"]

    text = brief({"token": "env:X"})
    assert "The hosts served: `github.com`." in text and "`git push`/`fetch`/`clone`/`ls-remote`/`pull`" in text
    assert "Not relayed" not in text
    text = brief({"hosts": [{"host": "GHE.corp.example", "token": "env:X"}], "git": ["fetch", "clone"]})
    assert "The hosts served: `ghe.corp.example` (gh's default: `ghe.corp.example`" in text
    assert "`git fetch`/`clone`/`pull`" in text
    assert "Not relayed in this session: `git push`, `git ls-remote`." in text and "pull/<n>/head" in text
    text = brief({"hosts": [{"host": "ghe.corp.example.", "token": "env:X"}], "git": []})
    assert "https://ghe.corp.example/OWNER/REPO.git" in text and "git's network commands" not in text
    assert "`git fetch` (and `git pull`)," in text and "pull/<n>/head" not in text


def test_check_warns_when_a_filtering_egress_does_not_admit_what_the_relay_reaches(tmp_path):
    from glove.doctor import extension_checks

    def egress_check(allow, cidrs=()):
        requested = {"llm": CC_LLM, "corporate": {"allow_domains": allow, "allow_cidrs": list(cidrs)},
                     "github": {"token": "env:A", "hosts": [{"host": "ghe.corp.example", "token": "env:B"}]}}
        return next(c for c in extension_checks(requested, harness="claude-code", session_dir=tmp_path)
                    if c.name == "github egress")

    c = egress_check(["github.com", "*.corp.example", "ghe.corp.example"])  # github.com alone is not enough
    assert c.status == "warn" and c.detail == (
        "corporate does not admit all it reaches: add 'api.github.com', 'uploads.github.com', 'codeload.github.com', "
        "'*.githubusercontent.com' to the hosts corporate allows")
    allow = ["github.com", "*.github.com", "*.githubusercontent.com", "ghe.corp.example", "*.ghe.corp.example"]
    c = egress_check(allow)
    assert c.status == "ok" and c.detail.endswith("needs corporate to allow it by CIDR too")
    assert egress_check(allow, ["10.0.0.0/8"]).detail.startswith("corporate admits github.com, api.github.com")
    from glove.doctor import egress_host_checks

    plan = make_cfg_plan(tmp_path, {"llm": CC_LLM, "direct": {}, "github": {"token": "env:A"}})
    gh = next(a for a in plan.composition.active if a.name == "github")
    assert egress_host_checks(plan.composition, gh) == []  # direct filters by nothing
