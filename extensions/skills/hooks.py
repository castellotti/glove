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

`relay:` runs some of a plugin's scripts in a sidecar of their own
(`skill-<name>`, relay's relayd under relay_policy.py), which holds their
secrets and their only network route: in the baked copy each such script is a
shim (`glove-relay skill-<name> <script>`), at the path the skill names. The
secrets are resolved at `glove up` (`launch_env`), in memory; a `files:`
template is rendered there too, and written only in the sidecar's tmpfs.

Refused: a symlink that leaves the plugin; a file that looks like a credential
(image layers are not secret storage); a secret in `env` (secrets never enter
the harness; they go under `relay`).
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

from glove.api import (
    HOST_GLOB,
    STAGE_IGNORE,
    HookContext,
    apt_bootstrap,
    existing_host_path,
    hook,
    is_secret_env_name,
    is_secret_ref,
    overlaps,
    render_value,
    run_body,
    uv_steps,
)

ROOT = "/opt/glove/plugins"
DATA = "/work/.glove-plugin-data"
UV = f"{ROOT}/.uv"  # uv, its Python and the wheelhouse (a plugin name never starts with `.`)
PYTHON = f"{UV}/python3"
WHEELS = f"{UV}/wheels"
ENVS = f"{UV}/envs"  # one per set of dependencies
CONFINE = "/opt/glove/bin/glove-confine"  # bin/glove-confine
PLUGIN_KEYS = frozenset({"path", "skills", "env", "mcp", "tools", "relay"})
RELAY_KEYS = frozenset({"commands", "check", "timeout"})
COMMAND_KEYS = frozenset({"hosts", "allow", "out_flags", "in_flags", "env", "files"})
RELAY_POLICY = "/opt/glove/skills/relay_policy.py"  # where the sidecar sees relay_policy.py
RELAY_CLIENT = "/opt/glove/bin/glove-relay"  # relay's client, in the harness image
SERVICE = "skill-"  # a relay's sidecar (and channel): skill-<plugin>
CHECK_TIMEOUT = 60  # seconds a check may take (a hung one would hold up `glove up`)

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
_HOME_PART = re.compile(r"^(?!\.\.?\Z)[A-Za-z0-9._-]+\Z")  # a dot file too (~/.config), never . or ..
_FLAG = re.compile(r"^--?[A-Za-z0-9][A-Za-z0-9-]*\Z")
_SUB = re.compile(r"^(\*|[A-Za-z0-9][A-Za-z0-9._:-]*)\Z")
# set by relay_policy.py for every command: not the operator's to override
_RELAY_ENV = frozenset({"PATH", "HOME", "TMPDIR", "LANG", "PYTHONDONTWRITEBYTECODE", "PYTHONUNBUFFERED",
                        "CLAUDE_PLUGIN_ROOT", "CLAUDE_PLUGIN_DATA", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY"})


class SkillsError(ValueError):
    pass


class Relay(NamedTuple):
    """A plugin's `relay:`, checked: what its sidecar runs (`settings`, for
    relay_policy.py), the env vars glove fills at `compose up` (`secrets`:
    var → a reference, or a `files:` template and its references), each
    reference's refresh hook, its checks, and the baked scripts to shim."""

    name: str
    timeout: int
    work: bool
    settings: dict[str, Any]
    secrets: dict[str, Any]
    refresh: dict[str, Path | None]
    checks: list[tuple[list[str], bool]]
    shims: dict[str, str]  # path in the image → command

    @property
    def service(self) -> str:
        return f"{SERVICE}{self.name}"

    @property
    def channel(self) -> str:
        return f"/run/glove/{self.service}"

    def check_argv(self, argv: list[str]) -> list[str]:
        """A check, run inside the sidecar through the relay (its policy, its
        fences) as the agent's calls go; stopped after CHECK_TIMEOUT."""
        return ["timeout", str(CHECK_TIMEOUT), "relayd", "--call", self.channel, *argv]


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


@hook
def contribute(ctx: HookContext) -> dict[str, Any]:
    s = ctx.settings
    h: dict[str, Any] = {"image": [], "skills": [], "mcp": [], "env": {}}  # its `harness:`
    out: dict[str, Any] = {"harness": h}
    plugins = [_plugin(ctx, name, raw) for name, raw in (s.get("plugins") or {}).items()]
    scripts = [x for p in plugins for x in p["scripts"] if not (p["relay"] and x.path in p["relay"].shims)]
    if scripts:  # before the plugins: a plugin edit never rebuilds this
        h["image"].append({"run": [_uv_layer(str(s["python"]), scripts)]})
        h["env"].update(UV_OFFLINE="1", UV_NO_INDEX="1", UV_FIND_LINKS=WHEELS, UV_PYTHON=PYTHON,
                          UV_PYTHON_DOWNLOADS="never", UV_CACHE_DIR="/tmp/glove-uv")
    for p in plugins:
        h["skills"] += p["skills"]
        for k, v in p["env"].items():
            if k in h["env"]:
                raise SkillsError(f"skills.plugins: env {k!r} is set by two plugins (or by glove)")
            h["env"][k] = v
        h["mcp"] += p["mcp"]
    if any(m["transport"] == "stdio" for m in h["mcp"]):
        h["image"].append({"copy": [["bin/glove-confine", CONFINE]], "run": [f"chmod 0755 {CONFINE}"]})
    if plugins:  # one layer for every plugin: core renders it last
        h["image"].append({"copy_host": [c for p in plugins for c in p["copy"]],
                             "run": [_bake(plugins)]})
    relays = [p["relay"] for p in plugins if p["relay"]]
    if relays:
        out.update(_relay_contrib(relays))
    return out


def _relay_contrib(relays: list[Relay]) -> dict[str, Any]:
    """Per relay: its channel, its hop to the egress proxy, its checks, and
    what its services fragment renders (`vars.relays`)."""
    return {
        "channels": {r.service: {"services": [r.service]} for r in relays},
        "privileges": {r.service: {"work": True} for r in relays if r.work},
        "trust": [r.service for r in relays],
        # like github's: a gate in front of the egress proxy (observe) labels
        # the plugin's flows `client: skill-<name>`
        "endpoints": {f"{r.service}-egress": {
            "harness": False, "interpose": True, "target": {"slot": "egress"}, "listen_networks": ["skillnet"],
            "observe": {"tool": "skill", "client": r.service}} for r in relays},
        "verify": [
            *({"name": f"{r.service}-up", "kind": "container-healthy", "service": r.service} for r in relays),
            # through the relay (its policy, its fences), from inside the sidecar
            *({"name": f"{r.service}-check-{i}", "kind": "exec-ok", "service": r.service,
               "argv": r.check_argv(argv), "timeout": CHECK_TIMEOUT + 10, "warn": not required}
              for r in relays for i, (argv, required) in enumerate(r.checks, 1)),
        ],
        # for `glove check`: every reference a relay resolves at `glove up`, and
        # the hosts its fences reach (a filtering egress must admit them)
        "secret_refs": {f"plugins.{r.name}.relay ({ref})": ref for r in relays for ref in r.refresh},
        "egress_hosts": sorted({h for r in relays for spec in r.settings["commands"].values()
                                for h in spec.get("hosts") or ()}),
        "vars": {"relays": [{"name": r.name, "service": r.service, "timeout": r.timeout, "work": r.work,
                             "settings": r.settings, "secrets": sorted(r.secrets), "policy": RELAY_POLICY}
                            for r in relays]},
    }


@hook
def diagnose(ctx: HookContext, check: dict[str, Any], run) -> str | None:
    """A relay's failed check: most likely a credential that expired."""
    service = str(check.get("service", ""))
    if check.get("kind") != "exec-ok" or not service.startswith(SERVICE):
        return None
    plugin = service.removeprefix(SERVICE)
    return (f"  an expired or missing credential? `glove skills refresh {plugin}` stores "
            "a new one and reloads the relay (the harness keeps running); `glove skills status` checks again")


@hook
def launch_env(ctx: HookContext, resolve_secret) -> dict[str, Any]:
    """Every relay's secrets, resolved now, in memory, for its sidecar's
    environment at `compose up`; a `files:` template rendered with its own."""
    env: dict[str, str] = {}
    for relay in relays(ctx):
        env.update(relay_env(relay, resolve_secret))
    return {"env": env}


def relays(ctx: HookContext, only: str | None = None) -> list[Relay]:
    """The plugins' relays (`only`: that plugin's), checked."""
    return [_plugin(ctx, name, raw)["relay"] for name, raw in (ctx.settings.get("plugins") or {}).items()
            if (only is None or name == only) and isinstance(raw, dict) and raw.get("relay")]


def relay_env(relay: Relay, resolve_secret) -> dict[str, str]:
    cache: dict[str, str] = {}  # one Keychain read per secret, however often it is used

    def value(ref: str) -> str:
        if ref not in cache:
            cache[ref] = resolve_secret(ref).strip()
            if not cache[ref]:
                raise SkillsError(f"skills.plugins.{relay.name}.relay: {ref} resolves to an empty value")
        return cache[ref]

    out = {}
    for var, spec in relay.secrets.items():
        if isinstance(spec, str):
            out[var] = value(spec)
            continue
        where = f"skills.plugins.{relay.name}.relay: {spec['template']}"
        try:
            text = spec["template"].read_text()
        except OSError as e:
            raise SkillsError(f"{where}: {e}") from None
        out[var] = render_value(text, {"secrets": {k: value(ref) for k, ref in spec["secrets"].items()}}, where)
    return out


@hook
def materialize(ctx: HookContext) -> None:
    """Each plugin's `${CLAUDE_PLUGIN_DATA}`, in the session's /work; a relayed
    plugin's staged copy under relay/<name>/ in the extension's state, which
    its sidecar binds read-only (a snapshot, like the image's)."""
    import shutil

    staged = Path(ctx.state_dir) / "relay"
    shutil.rmtree(staged, ignore_errors=True)
    for name, raw in (ctx.settings.get("plugins") or {}).items():
        if ctx.work_dir:
            Path(ctx.work_dir, Path(DATA).name, name).mkdir(mode=0o755, parents=True, exist_ok=True)
        if not (isinstance(raw, dict) and raw.get("relay")):
            continue
        p = _plugin(ctx, name, raw)
        for src, at in p["copy"]:
            dst = staged / name / Path(at).relative_to(p["dest"])
            dst.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            if src.is_dir() and not src.is_symlink():
                shutil.copytree(src, dst, symlinks=True, ignore=shutil.ignore_patterns(*STAGE_IGNORE))
            else:
                shutil.copy2(src, dst, follow_symlinks=False)


_CHECKED: dict[tuple, dict[str, Any]] = {}  # contribute, materialize and launch_env read a plugin once


def _plugin(ctx: HookContext, name: Any, raw: Any) -> dict[str, Any]:
    key = (str(ctx.session_dir), str(ctx.work_dir or ""), name, json.dumps(raw, sort_keys=True, default=str))
    if key not in _CHECKED:
        _CHECKED[key] = _check_plugin(ctx, name, raw)
    return _CHECKED[key]


def _check_plugin(ctx: HookContext, name: Any, raw: Any) -> dict[str, Any]:
    where = f"skills.plugins.{name}"
    if not isinstance(name, str) or not _NAME.fullmatch(name):
        raise SkillsError(f"skills.plugins: a plugin name is [a-z0-9-], starting with a letter or digit; got {name!r}")
    if not isinstance(raw, dict) or not isinstance(raw.get("path"), str) or not raw["path"]:
        raise SkillsError(f"{where}: want {{path: <plugin dir>, skills: [...], env: {{...}}, mcp: …, tools: …}}")
    if extra := sorted(set(raw) - PLUGIN_KEYS):
        raise SkillsError(f"{where}: unknown keys {extra} (known: {sorted(PLUGIN_KEYS)})")
    try:
        root = existing_host_path(ctx.session_dir, raw["path"], "dir")
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
        "relay": _relay(ctx, where, name, root, raw["relay"], copy, scripts) if "relay" in raw else None,
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


def _relay(ctx: HookContext, where: str, name: str, root: Path, raw: Any,
           copy: list[tuple[Path, str]], scripts: list[Script]) -> Relay:
    """`relay: {commands: {<script>: {hosts, allow, out_flags, in_flags, env,
    files}}, check: [...], timeout}`, checked against the staged copy."""
    where = f"{where}.relay"
    if not isinstance(raw, dict) or not isinstance(raw.get("commands"), dict) or not raw["commands"]:
        raise SkillsError(f"{where}: want {{commands: {{<script>: {{hosts, allow, …}}}}, check: [...], timeout}}")
    if extra := sorted(set(raw) - RELAY_KEYS):
        raise SkillsError(f"{where}: unknown keys {extra} (known: {sorted(RELAY_KEYS)})")
    timeout = raw.get("timeout", 300)
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 3600:
        raise SkillsError(f"{where}: timeout is seconds, 1 to 3600")
    dest = f"{ROOT}/{name}"
    staged = {at for _, at in copy}
    deps = {x.path: x.deps for x in scripts}
    commands: dict[str, Any] = {}
    secrets: dict[str, Any] = {}
    refresh: dict[str, Path | None] = {}
    shims: dict[str, str] = {}
    for cmd, spec in sorted(raw["commands"].items()):
        w = f"{where}.commands.{cmd}"
        at = f"{dest}/{cmd}"
        if (not isinstance(cmd, str) or cmd.startswith("/") or ".." in Path(cmd).parts
                or not all(_FILE_NAME.fullmatch(part) for part in Path(cmd).parts)):
            raise SkillsError(f"{w}: a script's path in the plugin (scripts/x.py)")
        host = root / cmd
        if host.is_symlink() or not host.is_file() or not any(at == s or at.startswith(f"{s}/") for s in staged):
            raise SkillsError(f"{w}: not a file in what is baked of {root}")
        if deps.get(at):
            raise SkillsError(f"{w}: a relayed script runs on the relay's Python, standard library only "
                              f"(it lists dependencies {list(deps[at])})")
        if not isinstance(spec, dict) or (extra := sorted(set(spec) - COMMAND_KEYS)):
            raise SkillsError(f"{w}: want {{hosts, allow, out_flags, in_flags, env, files}}"
                              + (f"; unknown keys {extra}" if isinstance(spec, dict) else ""))
        hosts = _strings(w, spec, "hosts", HOST_GLOB, "a host name, or *.<domain>")
        allow = _strings(w, spec, "allow", _SUB, "a subcommand, or *")
        if not allow:
            raise SkillsError(f"{w}: allow lists the subcommands it may run (`*`: any)")
        flags = {k: _strings(w, spec, k, _FLAG, "a flag (-o, --output)") for k in ("out_flags", "in_flags")}
        plain, secret_env = {}, {}
        for var, v in _relay_env(w, spec.get("env")).items():
            if isinstance(v, str):
                plain[var] = v
                continue
            secret_env[var] = side = _side(name, cmd, "env", var)
            secrets[side] = v[0]
            _refresh(ctx, refresh, f"{w}.env.{var}", *v)
        files = {}
        for rel, fspec in sorted((spec.get("files") or {}).items()):
            wf = f"{w}.files.{rel}"
            if not isinstance(rel, str) or not rel.startswith("~/") or not all(
                    _HOME_PART.fullmatch(part) for part in rel[2:].split("/")):
                raise SkillsError(f"{wf}: a path under the script's home (~/.config/x.json)")
            if not isinstance(fspec, dict) or set(fspec) - {"template", "secrets"} or "template" not in fspec:
                raise SkillsError(f"{wf}: want {{template: local/<file>.j2, secrets: {{<name>: keychain:…}}}}")
            refs = {}
            for k, ref in (fspec.get("secrets") or {}).items():
                ref, hook = _secret_spec(f"{wf}.secrets.{k}", ref)
                refs[str(k)] = ref
                _refresh(ctx, refresh, f"{wf}.secrets.{k}", ref, hook)
            files[rel[2:]] = side = _side(name, cmd, "file", rel)
            secrets[side] = {"template": _session_file(ctx, f"{wf}.template", fspec["template"]), "secrets": refs}
        first = host.read_bytes()[:256].split(b"\n", 1)[0]
        python = host.suffix == ".py" or at in deps or (first.startswith(b"#!") and (b"python" in first
                                                                                      or b"uv run" in first))
        commands[cmd] = {"hosts": hosts, "allow": allow, **flags, "env": plain, "secret_env": secret_env,
                         "files": files, "python": python}
        shims[at] = cmd
    checks = []
    for item in raw.get("check") or []:
        if isinstance(item, dict):
            run, required = item.get("run"), item.get("required", False)
        else:
            run, required = item, False
        argv = shlex.split(run) if isinstance(run, str) else []
        if not argv or argv[0] not in commands or not isinstance(required, bool):
            raise SkillsError(f"{where}.check: {item!r}: a relayed command and its arguments "
                              "(\"scripts/x.py status\", or {run: …, required: true})")
        checks.append((argv, required))
    work = any(c["out_flags"] or c["in_flags"] for c in commands.values())
    settings = {"root": dest, "data": f"{DATA}/{name}", "commands": commands}
    return Relay(name, timeout, work, settings, secrets, refresh, checks, shims)


def _side(plugin: str, cmd: str, kind: str, key: str) -> str:
    """The sidecar env var that carries one secret (or rendered file): named
    by what it is for, so adding or moving a command renames no other."""
    digest = hashlib.sha256(f"{cmd}\0{kind}\0{key}".encode()).hexdigest()[:12].upper()
    return f"SKILL_{plugin.replace('-', '_').upper()}_{digest}"


def _refresh(ctx: HookContext, refresh: dict[str, Path | None], where: str, ref: str, hook: str | None) -> None:
    """Record `ref`'s refresh hook: one per secret, wherever it is used."""
    path = _session_file(ctx, f"{where}.refresh", hook) if hook else None
    if path and refresh.get(ref) not in (None, path):
        raise SkillsError(f"{where}: {ref} already has another refresh hook ({refresh[ref]})")
    refresh[ref] = path or refresh.get(ref)


def _strings(where: str, spec: dict, key: str, pattern: re.Pattern, what: str) -> list[str]:
    items = spec.get(key) or []
    if not isinstance(items, list) or not all(isinstance(x, str) and pattern.fullmatch(x) for x in items):
        raise SkillsError(f"{where}: {key} is a list; each item {what}")
    return list(items)


def _secret_spec(where: str, value: Any) -> tuple[str, str | None]:
    """`keychain:<svc>` | `env:<VAR>` | `{secret: …, refresh: local/<hook>}`."""
    ref, hook = (value.get("secret"), value.get("refresh")) if isinstance(value, dict) else (value, None)
    if (not isinstance(ref, str) or not is_secret_ref(ref) or (isinstance(value, dict) and set(value) -
                                                               {"secret", "refresh"})):
        raise SkillsError(f"{where}: a secret is keychain:<service> | env:<VAR> | "
                          "{secret: keychain:<service>, refresh: local/<hook>}")
    if hook is not None and not ref.startswith("keychain:"):
        raise SkillsError(f"{where}: a refresh hook stores into the Keychain: its secret is keychain:<service>")
    return ref, hook


def _relay_env(where: str, env: Any) -> dict[str, Any]:
    """A relayed command's env: plain values, or secrets (as `_secret_spec`;
    a secret-shaped name must be one: no literal secret in the session file)."""
    if env is None:
        return {}
    if not isinstance(env, dict):
        raise SkillsError(f"{where}: env maps names to values or secrets")
    out: dict[str, Any] = {}
    for k, v in env.items():
        if not isinstance(k, str) or not _ENV_VAR.fullmatch(k) or k in _RELAY_ENV or k.upper().startswith(
                ("RELAY_", "GLOVE_", "SKILL_")):
            raise SkillsError(f"{where}: env {k!r}: a name ([A-Za-z_][A-Za-z0-9_]*) the relay does not set itself")
        if isinstance(v, dict) or (isinstance(v, str) and is_secret_ref(v)):
            out[k] = _secret_spec(f"{where}.env.{k}", v)
        elif isinstance(v, str | int | float) and not isinstance(v, bool):
            if is_secret_env_name(k):
                raise SkillsError(f"{where}: env {k!r} looks like a secret: keychain:<service>, never the value")
            out[k] = str(v)
        else:
            raise SkillsError(f"{where}: env {k!r}: a plain value or a secret reference")
    return out


def _session_file(ctx: HookContext, where: str, value: Any) -> Path:
    """A file in the session directory (a template, a refresh hook), never one
    an agent can write (`work/`)."""
    session = Path(ctx.session_dir or ".")
    if not isinstance(value, str) or value.startswith(("/", "~")) or ".." in Path(value).parts:
        raise SkillsError(f"{where}: a relative path in the session directory (local/…), got {value!r}")
    path = session / value
    if not path.is_file() or not Path(os.path.realpath(path)).is_relative_to(os.path.realpath(session)):
        raise SkillsError(f"{where}: {value} is not a file in the session directory")
    if ctx.work_dir and overlaps(path, ctx.work_dir):
        raise SkillsError(f"{where}: {value} is in work/, which the agent can write; keep it in local/")
    return path


def _mcp(ctx: HookContext, where: str, name: str, root: Path, raw: dict,
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
    if "mcp" not in ctx.renders:
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
    steps = []
    for p in plugins:
        sed = " ".join(f"-e 's|\\${{{k}}}|{v}|g'" for k, v in plugin_vars(p["name"]).items())
        steps.append(f"(grep -rlZ --include='*.md' -F '${{CLAUDE_PLUGIN_' {p['dest']} || true) "
                     f"| xargs -0r sed -i {sed}")
        shims = p["relay"].shims if p["relay"] else {}
        steps += [f"sed -i '1s|.*|#!{x.python}|' {shlex.quote(x.path)}" for x in p["scripts"]
                  if x.uv_shebang and x.path not in shims]
        for at, cmd in shims.items():  # the script runs in the plugin's relay sidecar
            line = f'exec {RELAY_CLIENT} {p["relay"].service} {shlex.quote(cmd)} "$@"'
            steps.append(f"printf '%s\\n' '#!/bin/sh' {shlex.quote(line)} > {shlex.quote(at)} "
                         f"&& chmod a+rx {shlex.quote(at)}")
        for b in p["bins"]:
            f = shlex.quote(f"{p['dest']}/bin/{b}")
            steps += [f"chmod a+rx {f}", f"ln -s {f} {shlex.quote(f'/usr/local/bin/{b}')}"]
    return run_body(ROOT, *steps)


def _uv_layer(python: str, scripts: list[Script]) -> str:
    """uv (pinned), a Python, one wheelhouse of every script's dependencies
    (resolved with hashes; wheels only: an sdist-only dependency fails the
    build here), and an env per set of dependencies installed from it. Keyed
    only on the Python and the dependency sets, never a script's bytes."""
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
