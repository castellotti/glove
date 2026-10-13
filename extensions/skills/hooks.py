"""`skills`: Claude Code plugins, and plain directories of skills, for every harness.

Plan time (`contribute`, pure): each plugin is checked, then baked into the
derived harness image at /opt/glove/plugins/<name>/ as a `copy_host` layer,
which core renders last (an edit to a checkout rebuilds nothing else) and
refuses when an agent could write the tree. Only the selected skills are
staged, with the plugin's other files. In the baked copy `${CLAUDE_PLUGIN_ROOT}`
and `${CLAUDE_PLUGIN_DATA}` are replaced in the Markdown that names them, and
`bin/` is linked into /usr/local/bin (never over a command the image has).
Skills reach the harness through the neutral `skills` contribution, so Claude
Code loads them with `--add-dir`, not as a plugin.

PEP 723 scripts run offline on a baked Python: each set of dependencies is
installed at build time (an earlier layer, keyed only on the Python and the
dependency sets) into its own read-only environment, and a script's
`uv run --script` shebang (or an `.mcp.json` `uv run --script` command) is
pointed at it. The harness's /tmp is noexec, so nothing with a compiled
extension could load from a uv cache there. An explicit `uv run --script` still
works for pure-Python dependencies: the env points uv at the baked wheelhouse.

`mcp: true` turns the plugin's `.mcp.json` into neutral `mcp` items (their
`tools` listed in the session file); a stdio server runs under the tool wrapper
(bin/glove-confine), never with the harness's own network.

Refused: a symlink that leaves the plugin; a file that looks like a credential
(image layers are not secret storage); a secret in `env` (secrets never enter
the harness).
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import shlex
import tomllib
from pathlib import Path
from typing import Any, NamedTuple

from glove.image import STAGE_IGNORE

ROOT = "/opt/glove/plugins"
DATA = "/work/.glove-plugin-data"
UV = f"{ROOT}/.uv"  # uv, its Python and the wheelhouse (a plugin name never starts with `.`)
PYTHON = f"{UV}/python3"
WHEELS = f"{UV}/wheels"
ENVS = f"{UV}/envs"  # one per set of dependencies
CONFINE = "/opt/glove/bin/glove-confine"  # bin/glove-confine
PLUGIN_KEYS = frozenset({"path", "skills", "env", "mcp", "tools"})

_NAME = re.compile(r"^[a-z0-9][a-z0-9-]*\Z")
_FILE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_ENV_VAR = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\Z")
# PEP 723's reference regex for an inline metadata block
_SCRIPT = re.compile(r"^# /// (?P<type>[a-zA-Z0-9-]+)$\s(?P<content>(^#(| .*)$\s)+)^# ///$", re.MULTILINE)
_UV_SHEBANG = re.compile(r"\buv run (.* )?--script\b")
# a PEM private key block (a key's body follows the header), and the names of
# files that hold credentials by convention
_PEM_KEY = re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----\r?\n[A-Za-z0-9+/=:\r\n -]{16}")
_CREDENTIAL_NAMES = (".env", ".env.*", ".netrc", ".npmrc", ".pypirc", ".git-credentials", "*.p12", "*.pfx",
                     "*.jks", "*.keystore", "id_rsa*", "id_dsa*", "id_ecdsa*", "id_ed25519*")
_NOT_CREDENTIALS = (".env.example", ".env.sample", ".env.template")
_SCAN_LIMIT = 4 << 20  # bytes of one file searched (a key sits near the start; scripts are small)


class SkillsError(ValueError):
    pass


class Script(NamedTuple):
    """A PEP 723 script in the image: `path`, its `deps`, whether its shebang
    runs it with `uv run --script`."""

    path: str
    deps: tuple[str, ...]
    uv_shebang: bool

    @property
    def env(self) -> str | None:
        """Its dependencies' env (None: none, the baked Python as is)."""
        key = "\n".join(sorted(self.deps))
        return f"{ENVS}/{hashlib.sha256(key.encode()).hexdigest()[:12]}" if self.deps else None

    @property
    def python(self) -> str:
        return f"{self.env}/bin/python" if self.env else PYTHON


def plugin_vars(name: str) -> dict[str, str]:
    """The plugin variables glove resolves, for plugin `name`."""
    return {"CLAUDE_PLUGIN_ROOT": f"{ROOT}/{name}", "CLAUDE_PLUGIN_DATA": f"{DATA}/{name}"}


def contribute(ctx: dict[str, Any]) -> dict[str, Any]:
    s = ctx["settings"]
    out: dict[str, Any] = {"image": [], "skills": [], "mcp": [], "env": {}}
    plugins = [_plugin(ctx, name, raw) for name, raw in (s.get("plugins") or {}).items()]
    scripts = [x for p in plugins for x in p["scripts"]]
    if scripts:  # before the plugins: a plugin edit never rebuilds this
        out["image"].append({"run": [_uv_layer(str(s["python"]), scripts)]})
        out["env"].update(UV_OFFLINE="1", UV_NO_INDEX="1", UV_FIND_LINKS=WHEELS, UV_PYTHON=PYTHON,
                          UV_PYTHON_DOWNLOADS="never", UV_CACHE_DIR="/tmp/glove-uv")
    for p in plugins:
        out["skills"] += p["skills"]
        for k, v in p["env"].items():
            if k in out["env"]:
                raise SkillsError(f"skills.plugins: env {k!r} is set by two plugins (or by glove)")
            out["env"][k] = v
        out["mcp"] += p["mcp"]
    if any(m["transport"] == "stdio" for m in out["mcp"]):
        out["image"].append({"copy": [["bin/glove-confine", CONFINE]], "run": [f"chmod 0755 {CONFINE}"]})
    if plugins:  # one layer for every plugin: core renders it last
        out["image"].append({"copy_host": [c for p in plugins for c in p["copy"]],
                             "run": [_bake(plugins)]})
    return out


def materialize(ctx: dict[str, Any]) -> None:
    """Each plugin's `${CLAUDE_PLUGIN_DATA}`, in the session's /work."""
    work = ctx["work"]["host"]
    if not work:
        return
    for name in ctx["settings"].get("plugins") or {}:
        Path(work, Path(DATA).name, name).mkdir(mode=0o755, parents=True, exist_ok=True)


def _plugin(ctx: dict[str, Any], name: Any, raw: Any) -> dict[str, Any]:
    from glove.mounts import existing_host_path

    where = f"skills.plugins.{name}"
    if not isinstance(name, str) or not _NAME.fullmatch(name):
        raise SkillsError(f"skills.plugins: a plugin name is [a-z0-9-], starting with a letter or digit; got {name!r}")
    if not isinstance(raw, dict) or not isinstance(raw.get("path"), str) or not raw["path"]:
        raise SkillsError(f"{where}: want {{path: <plugin dir>, skills: [...], env: {{...}}, mcp: …, tools: …}}")
    if extra := sorted(set(raw) - PLUGIN_KEYS):
        raise SkillsError(f"{where}: unknown keys {extra} (known: {sorted(PLUGIN_KEYS)})")
    try:
        root = existing_host_path(ctx.get("session_dir"), raw["path"], "dir")
    except ValueError as e:
        raise SkillsError(f"{where}: path {e}") from None
    dest = f"{ROOT}/{name}"
    is_plugin = (root / ".claude-plugin" / "plugin.json").is_file()
    skills_dir = root / "skills" if is_plugin else root
    skills_dest = f"{dest}/skills" if is_plugin else dest
    available = sorted(d.name for d in skills_dir.iterdir() if (d / "SKILL.md").is_file()) \
        if skills_dir.is_dir() else []
    if not is_plugin and not available:
        raise SkillsError(f"{where}: {root} is neither a Claude Code plugin (.claude-plugin/plugin.json) "
                          "nor a directory of skills (<skill>/SKILL.md)")
    chosen = raw.get("skills", available)
    if not isinstance(chosen, list) or not all(isinstance(k, str) for k in chosen):
        raise SkillsError(f"{where}: skills is a list of skill names")
    if unknown := sorted(set(chosen) - set(available)):
        raise SkillsError(f"{where}: no skill {unknown} in {skills_dir} (it has {available})")
    chosen = [k for k in available if k in chosen]
    # what is staged: the selected skills, and a plugin's other top-level entries
    copy = [(skills_dir / k, f"{skills_dest}/{k}") for k in chosen]
    if is_plugin:
        copy += [(e, f"{dest}/{e.name}") for e in sorted(root.iterdir())
                 if e.name not in STAGE_IGNORE and e.name != "skills"]
    scripts = [x for src, at in copy for x in _check_tree(where, root, src, at)]
    bins = sorted(f.name for f in (root / "bin").iterdir() if f.is_file() and not f.name.startswith(".")
                  and f.name not in STAGE_IGNORE) if is_plugin and (root / "bin").is_dir() else []
    if bad := [b for b in bins if not _FILE_NAME.fullmatch(b)]:
        raise SkillsError(f"{where}: bin/ names {bad}: letters, digits, '.', '_' and '-' only")
    return {
        "name": name, "dest": dest, "copy": copy, "bins": bins, "scripts": scripts,
        "skills": [f"{skills_dest}/{k}" for k in chosen],
        "env": _env(where, raw.get("env")),
        "mcp": _mcp(ctx, where, name, root, raw, {x.path: x.python for x in scripts}) if raw.get("mcp") else [],
    }


def _check_tree(where: str, root: Path, src: Path, at: str) -> list[Script]:
    """Check what staging `src` (baked at `at`) copies, bar the image's ignore
    list: no symlink leaves the plugin, no file looks like a credential.
    Returns its PEP 723 scripts, from the same read."""
    scripts: list[Script] = []
    entries = [src] if not src.is_dir() or src.is_symlink() else []
    for d, dirs, names in os.walk(src) if not entries else ():
        dirs[:] = [x for x in dirs if x not in STAGE_IGNORE]
        entries += [*(Path(d, x) for x in dirs), *(Path(d, x) for x in names if x not in STAGE_IGNORE)]
    for entry in entries:
        rel = entry.relative_to(root)
        if entry.is_symlink():
            target = os.readlink(entry)
            if os.path.isabs(target) or not Path(os.path.realpath(entry)).is_relative_to(root):
                raise SkillsError(f"{where}: {rel} is a symlink to {target!r}, outside the plugin; "
                                  "copy the file in, or link within the plugin (relative)")
            continue
        if entry.is_dir():
            continue
        if any(fnmatch.fnmatch(entry.name, g) for g in _CREDENTIAL_NAMES) and entry.name not in _NOT_CREDENTIALS:
            raise SkillsError(f"{where}: {rel} looks like a credential file; image layers are not secret "
                              "storage — remove it from the plugin (secrets come from the Keychain)")
        with entry.open("rb") as fh:
            data = fh.read(_SCAN_LIMIT)
        if _PEM_KEY.search(data):
            raise SkillsError(f"{where}: {rel} holds a private key; image layers are not secret storage")
        if entry.suffix in (".py", "") and b"# /// script" in data:
            path = at if entry == src else f"{at}/{entry.relative_to(src)}"
            if script := _script(where, entry.name, data, path):
                scripts.append(script)
    return scripts


def _script(where: str, name: str, data: bytes, path: str) -> Script | None:
    """A PEP 723 script (baked at `path`), or None."""
    try:
        text = data.decode()
    except UnicodeDecodeError:
        return None
    for m in _SCRIPT.finditer(text):
        if m["type"] != "script":
            continue
        body = "".join(line[2:] if line.startswith("# ") else line[1:]
                       for line in m["content"].splitlines(keepends=True))
        try:
            deps = tomllib.loads(body).get("dependencies", [])
        except tomllib.TOMLDecodeError as e:
            raise SkillsError(f"{where}: {name}: bad inline script metadata: {e}") from None
        if not isinstance(deps, list) or not all(isinstance(x, str) and x.isprintable() for x in deps):
            raise SkillsError(f"{where}: {name}: `dependencies` is a list of one-line strings")
        first = text.split("\n", 1)[0]
        return Script(path, tuple(deps), first.startswith("#!") and _UV_SHEBANG.search(first) is not None)
    return None


def _env(where: str, env: Any) -> dict[str, str]:
    """Plain values for the harness env (shell commands see them too): never a
    secret, by name or by reference — secrets never enter the harness."""
    from glove.config import is_secret_ref
    from glove.enforcers.base import is_secret_env_name

    if env is None:
        return {}
    if not isinstance(env, dict):
        raise SkillsError(f"{where}: env maps names to plain values")
    out = {}
    for k, v in env.items():
        if not isinstance(k, str) or not _ENV_VAR.fullmatch(k) or not isinstance(v, str | int | float | bool):
            raise SkillsError(f"{where}: env {k!r}: a name ([A-Za-z_][A-Za-z0-9_]*) and a plain value")
        if is_secret_env_name(k) or (isinstance(v, str) and is_secret_ref(v)):
            raise SkillsError(f"{where}: env {k!r} looks like a secret; secrets never enter the harness "
                              "(no shell command could read it anyway)")
        out[k] = str(v).lower() if isinstance(v, bool) else str(v)
    return out


def _mcp(ctx: dict[str, Any], where: str, name: str, root: Path, raw: dict,
         pythons: dict[str, str]) -> list[dict[str, Any]]:
    """The plugin's `.mcp.json` servers as neutral `mcp` items (core checks
    their fields), each with the `tools` the session file allows (the tool
    inventory fails closed). A `uv run --script <one of its scripts>` runs on
    that script's `pythons` entry."""
    path = root / ".mcp.json"
    if not path.is_file():
        raise SkillsError(f"{where}: mcp: true, but {root} has no .mcp.json")
    try:
        servers = json.loads(path.read_text()).get("mcpServers")
    except (ValueError, AttributeError) as e:
        raise SkillsError(f"{where}: {path}: {e}") from None
    if not isinstance(servers, dict):
        raise SkillsError(f"{where}: {path} has no `mcpServers` mapping")
    tools = raw.get("tools") or {}
    if not isinstance(tools, dict) or set(tools) - set(servers):
        raise SkillsError(f"{where}: tools maps a server of {sorted(servers)} to its tools")
    if "mcp" not in ctx["renders"]:
        return []
    values = plugin_vars(name)
    out = []
    for server, spec in servers.items():
        w = f"{where} mcp {server!r}"
        if server not in tools:
            raise SkillsError(f"{w}: list the tools it may use (skills.plugins.{name}.tools.{server}: [...])")
        spec = _substitute(w, spec, values)
        kind = spec.get("type", "stdio" if "command" in spec else "")
        if kind == "http":
            item = {"transport": "http", "url": spec.get("url")}
        elif kind == "stdio":
            command, args = spec.get("command"), spec.get("args", [])
            if not isinstance(args, list):
                raise SkillsError(f"{w}: args is a list")
            if command == "uv" and args[:2] == ["run", "--script"] and len(args) > 2 and args[2] in pythons:
                command, args = pythons[args[2]], args[2:]
            # under the tool wrapper: never the harness's own sandbox, whose
            # network reaches the session's forwarders
            item = {"transport": "stdio", "command": CONFINE, "args": [command, *args],
                    "env": {**(spec.get("env") or {}), **values}}
        else:
            raise SkillsError(f"{w}: type {kind or spec.get('type')!r}: only stdio and http servers")
        out.append({"name": server, **item, "tools": tools[server]})
    return out


def _substitute(where: str, value: Any, values: dict[str, str]) -> Any:
    if isinstance(value, str):
        for k, v in values.items():
            value = value.replace(f"${{{k}}}", v)
        if "${" in value:
            raise SkillsError(f"{where}: {value!r} names a variable glove does not set (only {', '.join(values)})")
        return value
    if isinstance(value, list):
        return [_substitute(where, v, values) for v in value]
    if isinstance(value, dict):
        return {k: _substitute(where, v, values) for k, v in value.items()}
    return value


def _bake(plugins: list[dict[str, Any]]) -> str:
    """After the copies: the plugin variables in the Markdown that names them
    (only those files are rewritten), each `uv run --script` shebang on its
    interpreter, `bin/` linked (`ln -s` without -f: a name the image already
    has fails the build)."""
    from glove.toolchains import run_body

    steps = []
    for p in plugins:
        sed = " ".join(f"-e 's|\\${{{k}}}|{v}|g'" for k, v in plugin_vars(p["name"]).items())
        steps.append(f"(grep -rlZ --include='*.md' -F '${{CLAUDE_PLUGIN_' {p['dest']} || true) "
                     f"| xargs -0r sed -i {sed}")
        steps += [f"sed -i '1s|.*|#!{x.python}|' {shlex.quote(x.path)}" for x in p["scripts"] if x.uv_shebang]
        for b in p["bins"]:
            f = shlex.quote(f"{p['dest']}/bin/{b}")
            steps += [f"chmod a+rx {f}", f"ln -s {f} {shlex.quote(f'/usr/local/bin/{b}')}"]
    return run_body(ROOT, *steps)


def _uv_layer(python: str, scripts: list[Script]) -> str:
    """uv (pinned), a Python, one wheelhouse of every script's dependencies
    (resolved with hashes; wheels only: an sdist-only dependency fails the
    build here), and an env per set of dependencies installed from it. Keyed
    only on the Python and the dependency sets, never a script's bytes."""
    from glove.image import apt_bootstrap
    from glove.toolchains import run_body, uv_steps

    uv = f"{UV}/bin/uv"
    venv = "/tmp/glove-wheels"
    steps = [apt_bootstrap("curl", ("ca-certificates", "curl")),
             *uv_steps(UV),
             f"export UV_PYTHON_INSTALL_DIR={UV}/python UV_PYTHON_PREFERENCE=only-managed UV_NO_CACHE=1",
             f"{uv} python install --no-bin {python}",
             f'ln -s "$({uv} python find {python})" {PYTHON}',
             f"(command -v uv >/dev/null || ln -s {uv} /usr/local/bin/uv)",
             f"mkdir -p {WHEELS}"]
    envs = sorted({(x.env, tuple(sorted(x.deps))) for x in scripts if x.env})
    if envs:
        steps.append(f"{uv} venv --seed --python {PYTHON} {venv}")
        for env, deps in envs:
            steps += [f"printf '%s\\n' {' '.join(shlex.quote(d) for d in deps)} > /tmp/glove-req.in",
                      f"{uv} pip compile /tmp/glove-req.in --python {PYTHON} --generate-hashes --no-header "
                      "-o /tmp/glove-req.txt",
                      f"{venv}/bin/pip download --no-deps --only-binary=:all: -r /tmp/glove-req.txt -d {WHEELS}",
                      f"{uv} venv --python {PYTHON} {env}",
                      f"{uv} pip install --python {env}/bin/python --no-index --find-links {WHEELS} --no-deps "
                      "-r /tmp/glove-req.txt"]
        steps.append(f"rm -rf {venv} /tmp/glove-req.in /tmp/glove-req.txt")
    return run_body(UV, *steps)
