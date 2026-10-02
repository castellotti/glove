"""Version-pinned language toolchains baked into the derived harness image.

The session file's optional ``toolchains:`` list declares, per ecosystem, an
exact runtime version, a package manager from a closed set, and optionally a
project whose dependencies are installed lockfile-strict. Everything is
installed at **build time** (the image build has network; the harness at run
time has none) into the derived image (glove/image.py), so the tag is
content-addressed by the block and the project's manifest + lockfile — only
those are baked, so editing the project's source never rebuilds its installs.

Two rules shape the layout:

- Everything lands under ``ROOT`` (``/opt/glove/toolchains``): on the read-only
  rootfs, never under a runtime bind mount (``/work``, ``/mnt/…``, the harness
  home), which would shadow it. Every enforcer already lets the harness and its
  commands read ``/opt/glove``, so no policy changes.
- The runtime finds it through env, not by living at the "natural" path:
  ``PATH`` (an image ``ENV``, since it must extend each base image's own PATH)
  plus ``PLAYWRIGHT_BROWSERS_PATH`` / ``VIRTUAL_ENV`` (harness env,
  set-if-absent so an explicit ``env:`` entry wins). Never ``NODE_PATH``: nono
  strips it (with ``NODE_OPTIONS``/``PYTHONPATH``) from every wrapped command,
  so a node project's deps are linked into that node's own global folder.

The surface is declarative: glove owns every command, there is no free-form
script. ``lang`` is a registry (``HANDLERS``); adding Ruby or Go is a new
handler, not a schema change. Unset, nothing renders differently.
"""

from __future__ import annotations

import json
import re
import shlex
from collections.abc import Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, ClassVar

from .config import ConfigError
from .image import _apt_bootstrap, _q, _staged

ROOT = "/opt/glove/toolchains"
BLOCK_KEYS = frozenset({"lang", "version", "manager", "project", "install", "packages", "browsers"})

# uv drives Python installs (interpreter, venv, `sync`). Pinned with its release
# checksums so the build trusts no download it did not expect.
UV_VERSION = "0.12.22"
UV_SHA256 = {
    "x86_64": "b9980552309f09c15172b8be828555e375097f16deb459795ce7bfd200380f0b",
    "aarch64": "6f66a14e8239871fb477f9746c941fedfa77e8fe28a8bc7c07e1dc7f53a66712",
}

# A package token: a name with an optional version/extras/specifier. Never an
# option (leading `-`) and never whitespace; quoted on render regardless.
_PACKAGE = re.compile(r"^[A-Za-z0-9@][A-Za-z0-9@._/+:=<>!~,\[\]-]*$")
_MANAGER_VERSION = re.compile(r"^[0-9][0-9A-Za-z.+-]*$")
_NPM_FLAGS = "--no-audit --no-fund --cache /tmp/npm-cache"


@dataclass(frozen=True)
class Toolchain:
    lang: str
    version: str
    manager: str
    manager_version: str | None = None
    install: str | None = None  # None ⇔ no project
    project: Path | None = None  # validated host dir (resolve()); None in `parse`
    project_spec: str | None = None  # as written in the session file
    # resolve(): the manifest + lockfile baked for the install (never the whole tree)
    project_files: tuple[Path, ...] = ()
    project_playwright: bool = False  # resolve(): the project depends on playwright
    packages: tuple[str, ...] = ()
    browsers: tuple[str, ...] = ()

    @property
    def prefix(self) -> str:
        """This block's install root; one block per `lang`, so never shared."""
        return f"{ROOT}/{self.lang}"

    @property
    def label(self) -> str:
        """The build-context directory its project files are staged under."""
        return f"toolchain-{self.lang}"

    @property
    def project_dir(self) -> str:
        return f"{self.prefix}/project"


@dataclass(frozen=True)
class Mode:
    files: tuple[tuple[str, ...], ...]  # required files (each: any of), the ones baked
    cmd: str  # run in the project dir; `{…}` fields filled by the handler


@dataclass(frozen=True)
class Manager:
    modes: dict[str, Mode]  # install mode → files + command
    default: str  # the lockfile-strict mode
    versioned: bool = False  # takes `manager: name@X.Y.Z`
    add: str = ""  # installs `packages` ({pkgs}), when not a global npm install


class Handler:
    """One ecosystem: validation facts plus block → (image lines by phase, env, PATH, brief)."""

    lang: str
    version_re: re.Pattern
    version_hint: str
    managers: ClassVar[dict[str, Manager]]
    default_manager: str
    browsers: frozenset[str] = frozenset()

    def phases(self, tc: Toolchain) -> tuple[list[str], list[str], list[str]]:
        """(runtime, global tools, project) Dockerfile lines: rendered phase by
        phase across blocks, so the slow-changing layers come first."""
        raise NotImplementedError

    def path(self, tc: Toolchain) -> list[str]:
        raise NotImplementedError

    def env(self, tc: Toolchain) -> dict[str, str]:
        raise NotImplementedError

    def describe(self, tc: Toolchain) -> list[str]:
        raise NotImplementedError

    def check(self, tc: Toolchain, where: str) -> None:
        """Extra checks on a block (resolved, when it has a project)."""


def _run(tc: Toolchain, *steps: str) -> str:
    """A build step that leaves everything it wrote under the block's prefix
    readable by the (non-root) harness, touching only what needs it (a blanket
    `chmod -R` would copy every file of earlier layers up into this one)."""
    readable = (f"find {tc.prefix} \\( ! -perm -a+r -o -perm /a+x ! -perm -a+x \\) "
                "-exec chmod a+rX {} +")
    return "RUN " + " \\\n    && ".join([*steps, readable])


def _fetch(tc: Toolchain, arch: dict[str, str], name: str, url: str, verify: str, dest: str,
           member: str = "") -> str:
    """Download tarball `name` (`$a`/`$t`/`$s` set per dpkg arch by `arch`)
    from `url`, check it with `verify`, and unpack it (or one `member`) into `dest`."""
    cases = " ".join(f"{d}) {v};;" for d, v in arch.items())
    return _run(
        tc,
        f'case "$(dpkg --print-architecture)" in {cases} '
        '*) echo "glove toolchains: unsupported architecture" >&2; exit 1;; esac',
        f'f="{name}" && cd /tmp',
        f'curl -fsSLO "{url}/$f"',
        verify,
        f"mkdir -p {dest}",
        f'tar -xzf "$f" -C {dest} --strip-components=1 --no-same-owner' + (f' "{member}"' if member else ""),
        'rm "$f"',
    )


def _copy_project(tc: Toolchain) -> str:
    return f"COPY {json.dumps([*(_staged(tc.label, f) for f in tc.project_files), tc.project_dir + '/'])}"


class NodeHandler(Handler):
    lang = "node"
    version_re = re.compile(r"^\d+\.\d+\.\d+$")
    version_hint = "an exact X.Y.Z, e.g. 22.11.0"
    managers: ClassVar[dict[str, Manager]] = {
        "npm": Manager({"ci": Mode((("package.json",), ("package-lock.json", "npm-shrinkwrap.json")),
                                   f"npm ci {_NPM_FLAGS}"),
                        "install": Mode((("package.json",),), f"npm install {_NPM_FLAGS}")}, "ci"),
        "pnpm": Manager({"frozen": Mode((("package.json",), ("pnpm-lock.yaml",)),
                                        "pnpm install --frozen-lockfile --store-dir /tmp/pnpm-store"),
                         "install": Mode((("package.json",),), "pnpm install --store-dir /tmp/pnpm-store")},
                        "frozen", versioned=True),
        "yarn": Manager({"frozen": Mode((("package.json",), ("yarn.lock",)),
                                        "yarn install --frozen-lockfile --cache-folder /tmp/yarn-cache"),
                         "install": Mode((("package.json",),), "yarn install --cache-folder /tmp/yarn-cache")},
                        "frozen", versioned=True),
    }
    default_manager = "npm"
    browsers = frozenset({"chromium", "firefox", "webkit"})
    PLAYWRIGHT = ("playwright", "@playwright/test")

    def runtime(self, tc: Toolchain) -> str:
        return f"{tc.prefix}/{tc.version}"

    def browsers_dir(self, tc: Toolchain) -> str:
        return f"{tc.prefix}/browsers"

    def check(self, tc: Toolchain, where: str) -> None:
        if tc.browsers and not (tc.project_playwright or self._global_playwright(tc)):
            raise ConfigError(f"{where}: `browsers` needs playwright — a project depending on "
                              f"{' or '.join(self.PLAYWRIGHT)}, or one of them in `packages`")

    def _global_playwright(self, tc: Toolchain) -> bool:
        return any(p == n or p.startswith(f"{n}@") for p in tc.packages for n in self.PLAYWRIGHT)

    def phases(self, tc: Toolchain) -> tuple[list[str], list[str], list[str]]:
        v = tc.version
        rt = self.runtime(tc)
        path = f"export PATH={rt}/bin:$PATH"
        runtime = [_fetch(tc, {"amd64": "a=x64", "arm64": "a=arm64"}, f"node-v{v}-linux-$a.tar.gz",
                          f"https://nodejs.org/dist/v{v}",
                          f'curl -fsSL "https://nodejs.org/dist/v{v}/SHASUMS256.txt" | grep " $f\\$" | sha256sum -c -',
                          rt)]
        globals_ = ([f"{tc.manager}@{tc.manager_version or 'latest'}"] if tc.manager != "npm" else []) \
            + list(tc.packages)
        tools = [_run(tc, path, f"npm install -g {_NPM_FLAGS} {_q(globals_)}", "rm -rf /tmp/npm-cache")] \
            if globals_ else []
        project = []
        if tc.project_files:
            # `<prefix>/lib/node` is in the pinned node's global require path: deps resolve from anywhere
            project += [_copy_project(tc), _run(tc, path, f"cd {tc.project_dir}",
                                                self.managers[tc.manager].modes[tc.install].cmd,
                                                "rm -rf /tmp/npm-cache /tmp/pnpm-store /tmp/yarn-cache",
                                                f"ln -s {tc.project_dir}/node_modules {rt}/lib/node")]
        if tc.browsers:
            # --with-deps apt-installs the engines' shared libraries (build runs as root)
            # the project's own playwright when it has one, else the global from `packages`
            cli = f"{tc.project_dir}/node_modules/.bin/playwright" if tc.project_playwright else "playwright"
            project.append(_run(tc, path, f"PLAYWRIGHT_BROWSERS_PATH={self.browsers_dir(tc)} "
                                          f"{cli} install --with-deps {_q(tc.browsers)}",
                                "rm -rf /var/lib/apt/lists/*"))
        return runtime, tools, project

    def path(self, tc: Toolchain) -> list[str]:
        out = [f"{self.runtime(tc)}/bin"]
        if tc.project_spec:
            out.append(f"{tc.project_dir}/node_modules/.bin")
        return out

    def env(self, tc: Toolchain) -> dict[str, str]:
        out = {}
        if tc.browsers:
            out["PLAYWRIGHT_BROWSERS_PATH"] = self.browsers_dir(tc)
        return out

    def describe(self, tc: Toolchain) -> list[str]:
        out = [f"- **Node {tc.version}** (`node`, `npm`"
               + (f", `{tc.manager}`" if tc.manager != "npm" else "") + ") is first on `PATH`"
               + (f"; global tools: {', '.join(f'`{p}`' for p in tc.packages)}" if tc.packages else "") + "."]
        if tc.project_spec:
            nm = f"{tc.project_dir}/node_modules"
            out.append(
                f"  - The project's dependencies are installed (read-only) at `{nm}`; their CLIs are on "
                f"`PATH` and `node`'s `require` finds them from any directory. A bundler, dev server, test "
                f"runner or ES `import` resolves "
                f"`./node_modules` from the project root, so in a copy under `/work` run "
                f"`ln -s {nm} node_modules` in that project directory first (if it has none)."
            )
        if tc.browsers:
            out.append(f"  - Playwright browsers ({', '.join(tc.browsers)}) are installed at "
                       f"`{self.browsers_dir(tc)}` (`PLAYWRIGHT_BROWSERS_PATH`); launch them with "
                       "`chromiumSandbox: false` (the container is the sandbox), after `mkdir -p \"$TMPDIR\"`.")
        return out


class PythonHandler(Handler):
    lang = "python"
    version_re = re.compile(r"^\d+\.\d+(\.\d+)?$")
    version_hint = "X.Y or X.Y.Z, e.g. 3.12"
    _UV_ADD = "{uv} pip install --python {py} {pkgs}"
    managers: ClassVar[dict[str, Manager]] = {
        # --no-install-project: only the manifest + lockfile are baked, not the project itself
        "uv": Manager({"sync": Mode((("pyproject.toml",), ("uv.lock",)),
                                    "{uv} sync --locked --no-install-project --python {v}"),
                       "requirements": Mode((("requirements.txt",),),
                                            "{uv} pip install --python {py} -r requirements.txt")},
                      "sync", add=_UV_ADD),
        "pip": Manager({"requirements": Mode((("requirements.txt",),),
                                             "{py} -m pip install --no-cache-dir -r requirements.txt")},
                       "requirements", add="{py} -m pip install --no-cache-dir {pkgs}"),
    }
    default_manager = "uv"

    def venv(self, tc: Toolchain) -> str:
        return f"{tc.prefix}/venv"

    def phases(self, tc: Toolchain) -> tuple[list[str], list[str], list[str]]:
        p = tc.prefix
        venv = self.venv(tc)
        fields = {"uv": f"{p}/bin/uv", "py": f"{venv}/bin/python", "v": shlex.quote(tc.version)}
        env = (f"export UV_PYTHON_INSTALL_DIR={p}/runtime UV_PYTHON_PREFERENCE=only-managed "
               f"UV_NO_CACHE=1 UV_PROJECT_ENVIRONMENT={venv}")
        runtime = [
            _fetch(tc, {d: f"t={t}; s={UV_SHA256[t]}" for d, t in (("amd64", "x86_64"), ("arm64", "aarch64"))},
                   "uv-$t-unknown-linux-gnu.tar.gz", f"https://github.com/astral-sh/uv/releases/download/{UV_VERSION}",
                   'echo "$s  $f" | sha256sum -c -', f"{p}/bin", member="uv-$t-unknown-linux-gnu/uv"),
            # seeded in every mode (`uv sync` keeps the seed packages), so the brief's `pip` is the venv's
            _run(tc, env, "{uv} python install --no-bin {v}".format(**fields),
                 f"{fields['uv']} venv --seed --python {fields['v']} {venv}"),
        ]
        manager = self.managers[tc.manager]
        project = []
        if tc.project_files:
            project += [_copy_project(tc),
                        _run(tc, env, f"cd {tc.project_dir}", manager.modes[tc.install].cmd.format(**fields))]
        if tc.packages:  # after the project: `uv sync` is exact and would remove them
            project.append(_run(tc, env, manager.add.format(**fields, pkgs=_q(tc.packages))))
        return runtime, [], project

    def path(self, tc: Toolchain) -> list[str]:
        return [f"{self.venv(tc)}/bin"]

    def env(self, tc: Toolchain) -> dict[str, str]:
        return {"VIRTUAL_ENV": self.venv(tc)}

    def describe(self, tc: Toolchain) -> list[str]:
        has = [x for x, on in (("the project's dependencies", tc.project_spec),
                               (", ".join(f"`{p}`" for p in tc.packages), tc.packages)) if on]
        return [f"- **Python {tc.version}**: the virtualenv `{self.venv(tc)}` is active (`python`, `pip` and "
                "installed CLIs are first on `PATH`)"
                + (f", with {' and '.join(has)} installed" if has else "")
                + ". It is read-only: packages cannot be added at run time."]


HANDLERS: dict[str, Handler] = {h.lang: h for h in (NodeHandler(), PythonHandler())}


# --- parse + resolve -----------------------------------------------------------------


def _strings(where: str, key: str, value: Any, pattern: re.Pattern | None = None) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(x, str) and x for x in value):
        raise ConfigError(f"{where}: `{key}` must be a list of strings, got {value!r}")
    bad = [x for x in value if pattern is not None and not pattern.match(x)]
    if bad:
        raise ConfigError(f"{where}: `{key}` entries {bad} are not package names")
    return tuple(value)


def _parse_block(i: int, raw: Any) -> Toolchain:
    where = f"toolchains[{i}]"
    if not isinstance(raw, dict):
        raise ConfigError(f"{where}: must be a mapping (lang, version, manager, …)")
    unknown = sorted(set(raw) - BLOCK_KEYS)
    if unknown:
        raise ConfigError(f"{where}: unknown key(s) {unknown} (known: {sorted(BLOCK_KEYS)})")
    lang = raw.get("lang")
    h = HANDLERS.get(lang) if isinstance(lang, str) else None
    if h is None:
        raise ConfigError(f"{where}: `lang` must be one of {sorted(HANDLERS)}, got {lang!r}")
    where = f"toolchains[{i}] ({lang})"
    version = raw.get("version")
    if isinstance(version, int | float) and not isinstance(version, bool):
        raise ConfigError(f"{where}: quote `version` (YAML reads {version!r} as a number): \"{version}\"")
    if not isinstance(version, str) or not version:
        raise ConfigError(f"{where}: `version` is required — {h.version_hint}")
    if not h.version_re.match(version):
        raise ConfigError(f"{where}: `version` must be {h.version_hint}, got {version!r}")
    manager_raw = raw.get("manager", h.default_manager)
    if not isinstance(manager_raw, str):
        raise ConfigError(f"{where}: `manager` must be one of {sorted(h.managers)}, got {manager_raw!r}")
    manager, _, mver = manager_raw.partition("@")
    if manager not in h.managers:
        raise ConfigError(f"{where}: `manager` must be one of {sorted(h.managers)}, got {manager!r}")
    if mver and (not h.managers[manager].versioned or not _MANAGER_VERSION.match(mver)):
        raise ConfigError(f"{where}: `manager: {manager_raw}` — only pnpm/yarn take a version (`pnpm@9.15.0`); "
                          "npm comes with the Node runtime and uv is pinned by glove")
    if manager == "yarn" and mver and int(re.match(r"\d+", mver).group()) >= 2:
        raise ConfigError(f"{where}: `manager: {manager_raw}` — only Yarn 1.x (`yarn@1.22.22`) is supported; "
                          "Yarn 2+ (Berry) is not published as the npm `yarn` package")
    project = raw.get("project")
    if project is not None and (not isinstance(project, str) or not project):
        raise ConfigError(f"{where}: `project` must be a directory path, got {project!r}")
    install = raw.get("install")
    modes = h.managers[manager].modes
    if install is not None and project is None:
        raise ConfigError(f"{where}: `install` needs a `project` to install")
    if install is not None and install not in modes:
        raise ConfigError(f"{where}: `install` for {manager} must be one of {sorted(modes)}, got {install!r}")
    if project is not None and install is None:
        install = h.managers[manager].default
    browsers = _strings(where, "browsers", raw.get("browsers"))
    if browsers and not h.browsers:
        raise ConfigError(f"{where}: `browsers` is only for lang: node")
    bad = sorted(set(browsers) - h.browsers)
    if bad:
        raise ConfigError(f"{where}: unknown browser(s) {bad} (known: {sorted(h.browsers)})")
    tc = Toolchain(lang=lang, version=version, manager=manager, manager_version=mver or None, install=install,
                   project_spec=project, packages=_strings(where, "packages", raw.get("packages"), _PACKAGE),
                   browsers=browsers)
    if project is None:  # a project is checked once resolved
        h.check(tc, where)
    return tc


def parse(raw: list | None) -> list[Toolchain]:
    """The blocks (Config has checked it is a list), validated without touching
    the filesystem (`project` unresolved)."""
    blocks = [_parse_block(i, b) for i, b in enumerate(raw or [])]
    seen: dict[str, int] = {}
    for i, tc in enumerate(blocks):
        if tc.lang in seen:
            raise ConfigError(f"toolchains[{i}]: a second `lang: {tc.lang}` block (the first is "
                              f"toolchains[{seen[tc.lang]}]); both would install into {tc.prefix} and set the "
                              "same PATH/env")
        seen[tc.lang] = i
    return blocks


def _depends_on_playwright(project: Path) -> bool:
    try:
        pkg = json.loads((project / "package.json").read_text())
    except (OSError, ValueError):
        return False
    deps = {**(pkg.get("dependencies") or {}), **(pkg.get("devDependencies") or {})}
    return any(n in deps for n in NodeHandler.PLAYWRIGHT)


def resolve(raw: list | None, session_dir: Path | None) -> list[Toolchain]:
    """`parse` plus the plan-time project checks: it resolves (``~``, relative to
    the session dir, symlinks), is a directory exposing no private path, and has
    the files its install mode needs — regular files, which are what is baked."""
    from .mounts import existing_host_path
    from .sessiondir import exposes_private

    out = []
    for i, tc in enumerate(parse(raw)):
        if tc.project_spec is None:
            out.append(tc)
            continue
        where = f"toolchains[{i}] ({tc.lang}) project"
        try:
            project = existing_host_path(session_dir, tc.project_spec, "dir")
        except ValueError as e:
            raise ConfigError(f"{where}: {e}") from None
        exposed = exposes_private(session_dir, project)
        if exposed:
            raise ConfigError(f"{where}: {tc.project_spec!r} would bake {exposed[1]} ({exposed[0]}) into the image; "
                              "name a directory that does not contain it")
        h = HANDLERS[tc.lang]
        modes = h.managers[tc.manager].modes
        hint = " (or `install: install`, which is not lockfile-strict)" \
            if tc.install != "install" and "install" in modes else ""
        files = []
        for any_of in modes[tc.install].files:
            found = next((project / f for f in any_of if (project / f).is_file()), None)
            if found is None:
                raise ConfigError(f"{where}: `{tc.manager}` install `{tc.install}` needs {' or '.join(any_of)} "
                                  f"in {project}{hint}")
            if found.is_symlink():  # never bake what a link points at
                raise ConfigError(f"{where}: {found} is a symlink; make it a regular file")
            files.append(found)
        tc = replace(tc, project=project, project_files=tuple(files),
                     project_playwright=tc.lang == "node" and _depends_on_playwright(project))
        h.check(tc, f"toolchains[{i}] ({tc.lang})")
        out.append(tc)
    return out


# --- render ------------------------------------------------------------------------------


def path_entries(blocks: Sequence[Toolchain]) -> list[str]:
    return [p for tc in blocks for p in HANDLERS[tc.lang].path(tc)]


def harness_env(blocks: Sequence[Toolchain]) -> dict[str, str]:
    """Runtime env (besides PATH, which the image sets) for the harness."""
    out: dict[str, str] = {}
    for tc in blocks:
        out.update(HANDLERS[tc.lang].env(tc))
    return out


def dockerfile_lines(blocks: Sequence[Toolchain]) -> tuple[list[str], list[tuple[str, Path]]]:
    """(Dockerfile lines, [(label, staged project file)]) for the derived image:
    every block's runtime, then their global tools, then their project installs,
    so bumping a lockfile never re-downloads a runtime."""
    lines = [f"# toolchains: {', '.join(f'{tc.lang} {tc.version}' for tc in blocks)}",
             _apt_bootstrap("curl", ("ca-certificates", "curl"))]
    phases = [HANDLERS[tc.lang].phases(tc) for tc in blocks]
    for n in range(3):
        for tc, ph in zip(blocks, phases, strict=True):
            if n == 0:
                lines.append(f"# toolchain: {tc.lang} {tc.version} ({tc.manager}"
                             + (f", install: {tc.install}" if tc.install else "") + ")")
            lines += ph[n]
    lines.append(f"ENV PATH={':'.join(path_entries(blocks))}:$PATH")
    return lines, [(tc.label, f) for tc in blocks for f in tc.project_files]


def brief(blocks: Sequence[Toolchain], enforcer: str) -> str:
    """The context-file section telling the agent what is baked in."""
    from .enforcers import get_enforcer

    browsers_ok = get_enforcer(enforcer).tools_run_browsers
    lines = ["## Toolchains", "",
             "Baked into this image at build time (shell commands have no network, so nothing can be "
             f"installed now). Everything lives under `{ROOT}` (read-only):", ""]
    for tc in blocks:
        lines += HANDLERS[tc.lang].describe(tc)
        if tc.browsers and not browsers_ok:
            lines.append(f"  - These browsers **cannot start inside a shell command** under this session's "
                         f"`{enforcer}` sandbox; don't retry, say so.")
    return "\n".join(lines)
