"""The github relay's policy: which `gh` and `git` invocations the sidecar runs
for the harness, and how (loaded by path by relay's relayd.py).

The sidecar holds the token and mounts the harness's /work read-write, so this
file is the boundary of that trust edge:

- `gh`: only subcommands in `github.allow` (settings), never the ones that
  touch credentials or run code (`ALWAYS_REFUSED`); `gh api` is GET only,
  never GraphQL, never a full URL; every host named is github.com; file
  arguments are opened here, inside /work only, and handed over as /dev/fd/N.
- `git`: only the network verbs (push, fetch, clone, ls-remote; the harness's
  `git pull` is a relayed fetch plus a local merge), to https://github.com
  remotes only, with options that run programs or read outside /work refused,
  and the agent's repo config defanged (`GIT_HARDENING`: no hooks, fsmonitor,
  helpers, askpass, editors, submodules, other protocols; ours is the only
  credential helper and it answers for https://github.com alone).
- every child's traffic goes through relayd's fence, which tunnels to GitHub's
  hosts (`HOSTS`) and nothing else.
"""

from __future__ import annotations

import os
import re
import subprocess


class Refused(Exception):
    """This invocation is not relayed."""


COMMANDS = frozenset({"gh", "git"})
HOSTS = ("github.com", "api.github.com", "uploads.github.com", "codeload.github.com", ".githubusercontent.com")

# never runnable, whatever `allow` says: credentials, code that runs in the
# sidecar, account keys
ALWAYS_REFUSED = frozenset({
    "auth", "extension", "extensions", "ext", "alias", "config", "codespace", "cs", "secret", "variable",
    "ssh-key", "gpg-key",
})
DEFAULT_ALLOW = (
    "pr list", "pr view", "pr create", "pr status", "pr diff", "pr checks", "pr comment", "pr review", "pr edit",
    "pr close", "pr reopen", "pr merge", "pr ready",
    "issue list", "issue view", "issue create", "issue comment", "issue edit", "issue close", "issue reopen",
    "issue status",
    "repo view", "repo clone",
    "run list", "run view", "run watch", "run rerun", "run cancel", "run download",
    "workflow list", "workflow view", "release list", "release view",
    "api", "browse", "status", "search",
)

HELPER = '!f() { test "$1" = get && printf "username=x-access-token\\npassword=%s\\n" "$GH_TOKEN"; }; f'


def git_hardening(proxy: str) -> list[tuple[str, str]]:
    """Command-scope git config (GIT_CONFIG_COUNT): read after the repo's own,
    so it wins for every key it names."""
    return [
        ("core.hooksPath", "/dev/null"),
        ("core.fsmonitor", "false"),
        ("core.sshCommand", "/bin/false"),
        ("core.askPass", "/bin/false"),
        ("core.pager", "cat"),
        ("core.editor", "/bin/false"),
        ("sequence.editor", "/bin/false"),
        ("diff.external", ""),
        ("credential.helper", ""),  # an empty value drops every helper configured before it
        ("credential.https://github.com.helper", HELPER),
        ("protocol.allow", "never"),
        ("protocol.https.allow", "always"),
        ("http.proxy", proxy),
        ("http.sslVerify", "true"),
        ("http.extraHeader", ""),
        ("fetch.recurseSubmodules", "false"),
        ("push.recurseSubmodules", "no"),
        ("submodule.recurse", "false"),
        ("push.gpgSign", "false"),
        ("gc.auto", "0"),
        ("maintenance.auto", "false"),
        ("fetch.writeCommitGraph", "false"),
        ("safe.bareRepository", "explicit"),
        ("safe.directory", "*"),  # the harness made these checkouts; ownership reads oddly across mounts
    ]


def setup(ctx: dict) -> dict[str, str]:
    """The children's environment (built from nothing: no sidecar env leaks)."""
    token = os.environ.get("RELAY_GITHUB_TOKEN", "").strip()
    if not token:
        raise SystemExit("relayd: the github token is empty")
    proxy = ctx["proxy"]
    home = "/tmp/relay-home"
    os.makedirs(f"{home}/gh", mode=0o700, exist_ok=True)
    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": home, "LANG": "C.UTF-8",
        "GH_TOKEN": token, "GH_CONFIG_DIR": f"{home}/gh",
        "HTTPS_PROXY": proxy, "HTTP_PROXY": proxy, "https_proxy": proxy, "http_proxy": proxy, "NO_PROXY": "",
        "GH_PROMPT_DISABLED": "1", "GH_NO_UPDATE_NOTIFIER": "1", "GH_NO_EXTENSION_UPDATE_NOTIFIER": "1",
        "GH_SPINNER_DISABLED": "1", "GH_PAGER": "cat", "PAGER": "cat", "GIT_PAGER": "cat",
        "EDITOR": "/bin/false", "VISUAL": "/bin/false", "GH_EDITOR": "/bin/false", "GIT_EDITOR": "/bin/false",
        "GIT_SEQUENCE_EDITOR": "/bin/false", "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "/bin/false",
        "SSH_ASKPASS": "/bin/false", "GIT_SSH_COMMAND": "/bin/false",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
    }
    pairs = git_hardening(proxy)
    env["GIT_CONFIG_COUNT"] = str(len(pairs))
    for i, (k, v) in enumerate(pairs):
        env[f"GIT_CONFIG_KEY_{i}"] = k
        env[f"GIT_CONFIG_VALUE_{i}"] = v
    return env


def prepare(req, env: dict[str, str]) -> tuple[list[str], dict[str, str]]:
    cmd, args = req.argv[0], req.argv[1:]
    if cmd == "gh":
        return ["gh", *_gh(req, args)], {}
    return ["git", *_git(req, args, env)], {}


# --- gh ----------------------------------------------------------------------------

REPO_URL = re.compile(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?(\.git)?/?")


def _split(tok: str) -> tuple[str, str | None]:
    """`--flag=value` → (--flag, value); anything else → (tok, None)."""
    if tok.startswith("--") and "=" in tok:
        name, _, value = tok.partition("=")
        return name, value
    return tok, None


def _host_ok(value: str, what: str) -> None:
    if value.lower().rstrip(".") != "github.com":
        raise Refused(f"{what} {value!r}: this relay serves github.com only")


def _repo_ok(value: str) -> None:
    """`-R [HOST/]OWNER/REPO` or a URL: github.com only."""
    if "://" in value:
        if not REPO_URL.fullmatch(value):
            raise Refused(f"repository {value!r}: an https://github.com/<owner>/<repo> URL only")
    elif value.count("/") == 2:
        _host_ok(value.split("/", 1)[0], "repository host")
    elif value.count("/") > 2 or value.startswith(("git@", "ssh:")):
        raise Refused(f"repository {value!r}: use OWNER/REPO")


# Flags whose value is checked or replaced. Every token is judged on its own
# (no table of which flags take values): a scanner that wrongly thought a
# boolean flag swallowed the next token would let a raw `--body-file <path>`
# through, so the token after any of these is always their value, and
# combined or attached short options (`-dF x`, `-Fx`) are refused outright.
GH_FILE_FLAGS = frozenset({"-F", "--body-file"})
GH_DIR_FLAGS = frozenset({"-D", "--dir"})
GH_HOST_FLAGS = frozenset({"--hostname"})
GH_REPO_FLAGS = frozenset({"-R", "--repo"})
GH_CHECKED_FLAGS = GH_FILE_FLAGS | GH_DIR_FLAGS | GH_HOST_FLAGS | GH_REPO_FLAGS


def _gh(req, args: list[str]) -> list[str]:
    if args in (["--version"], ["version"], ["--help"]):
        return args
    words = []
    for tok in args[:2]:
        if tok.startswith("-"):
            break
        words.append(tok)
    if not words:
        raise Refused("name a gh command first (e.g. `gh pr list --repo OWNER/REPO`)")
    if words[0] == "api":  # `gh api <endpoint>`: the endpoint is no subcommand
        words = words[:1]
    if words[0] in ALWAYS_REFUSED:
        raise Refused(f"`gh {words[0]}` is never relayed (it touches credentials or runs code in the sidecar)")
    allow = req.settings.get("allow") or DEFAULT_ALLOW
    joined = " ".join(words)
    if words[0] not in allow and joined not in allow:
        raise Refused(f"`gh {joined}` is not in this session's github.allow")
    rest = args[len(words):]
    if words[0] == "api":
        return [*words, *_gh_api(rest)]
    if joined == "repo clone":  # `gh repo clone <repo> [<dir>]`, nothing else (extra git args run code)
        if not 1 <= len(rest) <= 2 or any(t.startswith("-") for t in rest):
            raise Refused("relayed as `gh repo clone OWNER/REPO [<dir under /work>]` only")
        _repo_ok(rest[0])
        return [*words, rest[0], *([req.directory(rest[1])] if len(rest) > 1 else [])]
    out: list[str] = [*words]
    i = 0
    while i < len(rest):
        name, value = _split(rest[i])
        if name == "--":
            raise Refused("`--` is not relayed")
        if name.startswith("-") and not name.startswith("--") and len(name) > 2:
            raise Refused(f"{name}: spell short options out one by one, value as the next word")
        if name == "--recover" or (words[-1] == "create" and name in ("-T", "--template")):
            raise Refused(f"{name} reads a file in the sidecar: pass the body with --body-file <file under /work>")
        if name not in GH_CHECKED_FLAGS:
            out.append(rest[i])
            i += 1
            continue
        if value is None:
            if i + 1 >= len(rest):
                raise Refused(f"{name} needs a value")
            value = rest[i + 1]
            i += 1
        i += 1
        if name in GH_FILE_FLAGS:
            value = req.file(value)
        elif name in GH_DIR_FLAGS:
            value = req.directory(value)
        elif name in GH_HOST_FLAGS:
            _host_ok(value, name)
        else:
            _repo_ok(value)
        out += [name, value]
    if words[0] == "browse" and "--no-browser" not in out and "-n" not in out:
        out.append("--no-browser")
    return out


GH_API_VALUE = frozenset({"-X", "--method", "-H", "--header", "-f", "--raw-field", "-F", "--field", "--input",
                          "--hostname", "-q", "--jq", "-t", "--template", "--cache", "-p", "--preview"})


def _gh_api(args: list[str]) -> list[str]:
    method, explicit, fields, endpoint = "GET", False, False, None
    out: list[str] = []
    i = 0
    while i < len(args):
        name, value = _split(args[i])
        takes = name in GH_API_VALUE and value is None
        if takes and i + 1 >= len(args):
            raise Refused(f"{name} needs a value")
        v = value if value is not None else (args[i + 1] if takes else None)
        if name in ("-X", "--method"):
            method, explicit = (v or "").upper(), True
        elif name in ("-F", "--field", "--input"):
            raise Refused(f"gh api {name} is not relayed (it sends a body or reads files); use -X GET with -f")
        elif name in ("-f", "--raw-field"):
            fields = True
        elif name in ("-H", "--header") and "method-override" in (v or "").lower():
            raise Refused("gh api: method-override headers are not relayed")
        elif name == "--hostname":
            _host_ok(v or "", "--hostname")
        elif not name.startswith("-") and endpoint is None:
            endpoint = name
        elif name.startswith("-") and not name.startswith("--") and len(name) > 2:
            raise Refused(f"{name}: spell short options out one by one")
        out += [name, v] if takes else [args[i]]
        i += 2 if takes else 1
    if endpoint is None:
        raise Refused("gh api needs an endpoint (e.g. repos/OWNER/REPO)")
    if "://" in endpoint or endpoint.lstrip("/").split("?")[0] == "graphql":
        raise Refused("gh api: a REST path on api.github.com only (no URL, no graphql)")
    if method != "GET":
        raise Refused(f"gh api is relayed for GET only (got {method})")
    if fields and not explicit:
        raise Refused("gh api with -f sends a POST unless told otherwise: add -X GET")
    return out


# --- git ---------------------------------------------------------------------------

GIT_NET = ("push", "fetch", "clone", "ls-remote")
GIT_REFUSED = frozenset({
    "--upload-pack", "--receive-pack", "--exec", "--template", "--config", "-c", "--reference",
    "--reference-if-able", "--separate-git-dir", "--signed", "--recurse-submodules", "--recursive",
    "--bundle-uri", "--shared", "-s", "--local", "-l", "--no-local", "--dissociate",
})
GIT_VALUE = {
    "push": frozenset({"--repo", "-o", "--push-option"}),
    "fetch": frozenset({"--depth", "--deepen", "--shallow-since", "--shallow-exclude", "-j", "--jobs",
                        "--negotiation-tip", "-o", "--server-option", "--refmap", "--filter"}),
    "clone": frozenset({"-o", "--origin", "-b", "--branch", "--depth", "--shallow-since", "--shallow-exclude",
                        "-j", "--jobs", "--filter", "--revision", "--server-option", "--ref-format"}),
    "ls-remote": frozenset({"--sort", "-o", "--server-option"}),
}


def _url_ok(url: str) -> None:
    if not REPO_URL.fullmatch(url):
        raise Refused(f"remote {url!r}: this relay pushes and fetches https://github.com/<owner>/<repo> only "
                      "(switch the remote with `git remote set-url origin https://github.com/OWNER/REPO.git`)")


def _git_out(req, env: dict[str, str], *args: str) -> str:
    r = subprocess.run(["git", *args], cwd=req.cwd, env=env, capture_output=True, text=True, timeout=15)
    return r.stdout.strip() if r.returncode == 0 else ""


def _remote_urls(req, env, remote: str, push: bool) -> list[str]:
    """Every URL `remote` (a name or a URL) resolves to, rewrites applied."""
    if "://" in remote or re.match(r"^[^/]+@[^:]+:", remote):
        if _git_out(req, env, "config", "--get-regexp", r"^url\..*insteadof$"):
            raise Refused("this repository rewrites URLs (url.*.insteadOf): push and fetch by remote name")
        return [remote]
    urls = _git_out(req, env, "remote", "get-url", "--all", *(["--push"] if push else []), remote).splitlines()
    if not urls:
        raise Refused(f"{remote!r} is not a remote of this repository")
    return urls


def _default_remote(req, env, push: bool) -> str:
    branch = _git_out(req, env, "symbolic-ref", "--short", "-q", "HEAD")
    keys = ([f"branch.{branch}.pushRemote"] if push and branch else []) + (["remote.pushDefault"] if push else []) \
        + ([f"branch.{branch}.remote"] if branch else [])
    for k in keys:
        v = _git_out(req, env, "config", "--get", k)
        if v:
            return v
    return "origin"


def _git(req, args: list[str], env: dict[str, str]) -> list[str]:
    if not args or args[0] not in GIT_NET:
        raise Refused(f"only git {', '.join(GIT_NET)} (and pull) are relayed; everything else is local")
    sub, rest = args[0], args[1:]
    value_flags = GIT_VALUE[sub]
    known = GIT_REFUSED | value_flags
    out, positionals = [sub], []
    pos_at: list[int] = []  # where each positional sits in `out`
    remotes_all = False
    repo_opt = None
    i = 0
    while i < len(rest):
        name, value = _split(rest[i])
        if name == "--":
            positionals += rest[i + 1:]
            pos_at += range(len(out) + 1, len(out) + len(rest) - i)
            out += rest[i:]
            break
        if name.startswith("--") and name not in known and any(k.startswith(name) for k in known):
            raise Refused(f"{name}: spell git options in full")  # git takes unambiguous abbreviations
        if name in GIT_REFUSED or (name == "-u" and sub in ("clone", "ls-remote")):
            raise Refused(f"git {sub} {name} is not relayed (it runs programs or reaches outside /work)")
        if name.startswith("-") and not name.startswith("--") and len(name) > 2 and name[:2] not in ("-j", "-o"):
            raise Refused(f"{name}: spell short options out one by one")
        takes = name in value_flags and value is None
        if takes and i + 1 >= len(rest):
            raise Refused(f"{name} needs a value")
        if name == "--repo":
            repo_opt = value if value is not None else rest[i + 1]
        if name == "--all" and sub == "fetch":
            remotes_all = True
        if not name.startswith("-"):
            positionals.append(name)
            pos_at.append(len(out))
        out += [name, rest[i + 1]] if takes else [rest[i]]
        i += 2 if takes else 1
    if sub == "clone":
        if not positionals:
            raise Refused("git clone needs a URL")
        _url_ok(positionals[0])
        if len(positionals) > 1:
            out[pos_at[1]] = req.directory(positionals[1])
        return out
    push = sub == "push"
    if remotes_all:
        remotes = _git_out(req, env, "remote").split()
    elif "--multiple" in out:
        remotes = positionals
    else:
        remotes = [repo_opt or (positionals[0] if positionals else _default_remote(req, env, push))]
    if not remotes:
        raise Refused("this repository has no remotes")
    for r in remotes:
        for url in _remote_urls(req, env, r, push):
            _url_ok(url)
    return out
