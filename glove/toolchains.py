"""Version-pinned language toolchains baked into the derived harness image.

The session file's optional ``toolchains:`` list declares, per ecosystem, an
exact runtime version, a package manager from a closed set, and optionally a
project whose dependencies are installed lockfile-strict. Everything is
installed at **build time** (the image build has network; the harness at run
time has none) into the derived image (glove/image.py), so the tag is
content-addressed by the block and the staged project.

Two rules shape the layout:

- Everything lands under ``ROOT`` (``/opt/glove/toolchains``): on the read-only
  rootfs, never under a runtime bind mount (``/work``, the harness home, a
  ``mounts:`` entry), which would shadow it. Every enforcer already lets the
  harness and its commands read ``/opt/glove``, so no policy changes.
- The runtime finds it through env, not by living at the "natural" path:
  ``PATH`` (an image ``ENV``, since it must extend each base image's own PATH)
  plus ``NODE_PATH`` / ``PLAYWRIGHT_BROWSERS_PATH`` / ``VIRTUAL_ENV`` (harness
  env, set-if-absent so an explicit ``env:`` entry wins).

The surface is declarative: glove owns every command, there is no free-form
script. ``lang`` is a registry (``HANDLERS``); adding Ruby or Go is a new
handler, not a schema change. Unset, nothing renders differently.
"""

from __future__ import annotations

import json
import os
import re
import shlex
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, ClassVar

from .config import ConfigError

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
_CURL = ("RUN command -v curl >/dev/null || (apt-get update "
         "&& apt-get install -y --no-install-recommends ca-certificates curl "
         "&& rm -rf /var/lib/apt/lists/*)")


@dataclass(frozen=True)
class Toolchain:
    lang: str
    version: str
    manager: str
    manager_version: str | None = None
    install: str | None = None  # None ⇔ no project
    project: Path | None = None  # validated host dir (resolve()); None in `parse`
    project_spec: str | None = None  # as written in the session file
    packages: tuple[str, ...] = ()
    browsers: tuple[str, ...] = ()

    @property
    def prefix(self) -> str:
        """This block's install root; one block per `lang`, so never shared."""
        return f"{ROOT}/{self.lang}"

    @property
    def label(self) -> str:
        """The build-context directory its project is staged under."""
        return f"toolchain-{self.lang}"


@dataclass(frozen=True)
class Manager:
    modes: dict[str, tuple[tuple[str, ...], ...]]  # install mode → required files (each: any of)
    default: str  # the lockfile-strict mode


class Handler:
    """One ecosystem: validation facts plus block → (image lines, env, PATH, brief)."""

    lang: str
    version_re: re.Pattern
    version_hint: str
    managers: ClassVar[dict[str, Manager]]
    default_manager: str
    browsers: frozenset[str] = frozenset()

    def lines(self, tc: Toolchain) -> list[str]:
        raise NotImplementedError

    def path(self, tc: Toolchain) -> list[str]:
        raise NotImplementedError

    def env(self, tc: Toolchain) -> dict[str, str]:
        raise NotImplementedError

    def describe(self, tc: Toolchain) -> list[str]:
        raise NotImplementedError

    def check(self, tc: Toolchain, project: Path | None, where: str) -> None:
        """Extra checks on a block; `project` is its resolved directory (None:
        no project, or not resolved yet)."""


def _run(*steps: str) -> str:
    return "RUN " + " \\\n    && ".join(steps)


def _q(items) -> str:
    return " ".join(shlex.quote(str(p)) for p in items)


class NodeHandler(Handler):
    lang = "node"
    version_re = re.compile(r"^\d+\.\d+\.\d+$")
    version_hint = "an exact X.Y.Z, e.g. 22.11.0"
    managers: ClassVar[dict[str, Manager]] = {
        "npm": Manager({"ci": (("package.json",), ("package-lock.json", "npm-shrinkwrap.json")),
                        "install": (("package.json",),)}, "ci"),
        "pnpm": Manager({"frozen": (("package.json",), ("pnpm-lock.yaml",)),
                         "install": (("package.json",),)}, "frozen"),
        "yarn": Manager({"frozen": (("package.json",), ("yarn.lock",)),
                         "install": (("package.json",),)}, "frozen"),
    }
    default_manager = "npm"
    browsers = frozenset({"chromium", "firefox", "webkit"})
    _PLAYWRIGHT = ("playwright", "@playwright/test")

    def runtime(self, tc: Toolchain) -> str:
        return f"{tc.prefix}/{tc.version}"

    def project_dir(self, tc: Toolchain) -> str:
        return f"{tc.prefix}/project"

    def browsers_dir(self, tc: Toolchain) -> str:
        return f"{tc.prefix}/browsers"

    def check(self, tc: Toolchain, project: Path | None, where: str) -> None:
        if tc.browsers and not self._has_playwright(tc, project):
            raise ConfigError(f"{where}: `browsers` needs playwright — a project depending on "
                              f"{' or '.join(self._PLAYWRIGHT)}, or one of them in `packages`")

    def _has_playwright(self, tc: Toolchain, project: Path | None) -> bool:
        if any(p == n or p.startswith(f"{n}@") for p in tc.packages for n in self._PLAYWRIGHT):
            return True
        return self._project_has_playwright(project)

    def _project_has_playwright(self, project: Path | None) -> bool:
        if project is None:
            return False
        try:
            pkg = json.loads((project / "package.json").read_text())
        except (OSError, ValueError):
            return False
        deps = {**(pkg.get("dependencies") or {}), **(pkg.get("devDependencies") or {})}
        return any(n in deps for n in self._PLAYWRIGHT)

    def lines(self, tc: Toolchain) -> list[str]:
        rt = self.runtime(tc)
        v = tc.version
        path = f"export PATH={rt}/bin:$PATH"
        npm_g = "npm install -g --no-audit --no-fund --cache /tmp/npm-cache"
        out = [_run(
            'case "$(dpkg --print-architecture)" in amd64) a=x64;; arm64) a=arm64;; '
            '*) echo "glove toolchains: unsupported architecture" >&2; exit 1;; esac',
            f'f="node-v{v}-linux-$a.tar.gz" && cd /tmp',
            f'curl -fsSLO "https://nodejs.org/dist/v{v}/$f"',
            f'curl -fsSL "https://nodejs.org/dist/v{v}/SHASUMS256.txt" | grep " $f\\$" | sha256sum -c -',
            f"mkdir -p {rt}",
            f'tar -xzf "$f" -C {rt} --strip-components=1 --no-same-owner',
            'rm "$f"',
        )]
        if tc.manager != "npm":
            spec = f"{tc.manager}@{tc.manager_version or 'latest'}"
            out.append(_run(path, f"{npm_g} {shlex.quote(spec)}",
                            "rm -rf /tmp/npm-cache"))
        if tc.packages:
            out.append(_run(path, f"{npm_g} {_q(tc.packages)}", "rm -rf /tmp/npm-cache"))
        if tc.project is not None:
            dest = self.project_dir(tc)
            out.append(f"COPY {json.dumps([f'{tc.label}/{tc.project.name}', dest])}")
            install = {
                ("npm", "ci"): "npm ci --no-audit --no-fund --cache /tmp/npm-cache",
                ("npm", "install"): "npm install --no-audit --no-fund --cache /tmp/npm-cache",
                ("pnpm", "frozen"): "pnpm install --frozen-lockfile --store-dir /tmp/pnpm-store",
                ("pnpm", "install"): "pnpm install --store-dir /tmp/pnpm-store",
                ("yarn", "frozen"): "yarn install --frozen-lockfile --cache-folder /tmp/yarn-cache",
                ("yarn", "install"): "yarn install --cache-folder /tmp/yarn-cache",
            }[(tc.manager, tc.install)]
            out.append(_run(path, f"cd {dest}", install,
                            "rm -rf /tmp/npm-cache /tmp/pnpm-store /tmp/yarn-cache"))
        if tc.browsers:
            # --with-deps apt-installs the engines' shared libraries (build runs as root)
            # the project's own playwright when it has one, else the global from `packages`
            cli = (f"{self.project_dir(tc)}/node_modules/.bin/playwright"
                   if self._project_has_playwright(tc.project) else "playwright")
            out.append(_run(path, f"PLAYWRIGHT_BROWSERS_PATH={self.browsers_dir(tc)} "
                                  f"{cli} install --with-deps {_q(tc.browsers)}",
                            "rm -rf /var/lib/apt/lists/*"))
        out.append(_run(f"chmod -R a+rX {tc.prefix}"))
        return out

    def path(self, tc: Toolchain) -> list[str]:
        out = [f"{self.runtime(tc)}/bin"]
        if tc.project_spec:
            out.append(f"{self.project_dir(tc)}/node_modules/.bin")
        return out

    def env(self, tc: Toolchain) -> dict[str, str]:
        out = {}
        if tc.project_spec:
            out["NODE_PATH"] = f"{self.project_dir(tc)}/node_modules"
        if tc.browsers:
            out["PLAYWRIGHT_BROWSERS_PATH"] = self.browsers_dir(tc)
        return out

    def describe(self, tc: Toolchain) -> list[str]:
        out = [f"- **Node {tc.version}** (`node`, `npm`"
               + (f", `{tc.manager}`" if tc.manager != "npm" else "") + ") is first on `PATH`"
               + (f"; global tools: {', '.join(f'`{p}`' for p in tc.packages)}" if tc.packages else "") + "."]
        if tc.project_spec:
            nm = f"{self.project_dir(tc)}/node_modules"
            out.append(
                f"  - The project's dependencies are installed (read-only) at `{nm}`; their CLIs are on "
                f"`PATH` and `NODE_PATH` points there. A bundler, dev server or test runner resolves "
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
    managers: ClassVar[dict[str, Manager]] = {
        "uv": Manager({"sync": (("pyproject.toml",), ("uv.lock",)),
                       "requirements": (("requirements.txt",),)}, "sync"),
        "pip": Manager({"requirements": (("requirements.txt",),)}, "requirements"),
    }
    default_manager = "uv"

    def venv(self, tc: Toolchain) -> str:
        return f"{tc.prefix}/venv"

    def project_dir(self, tc: Toolchain) -> str:
        return f"{tc.prefix}/project"

    def lines(self, tc: Toolchain) -> list[str]:
        p = tc.prefix
        uv = f"{p}/bin/uv"
        venv = self.venv(tc)
        py = f"{venv}/bin/python"
        env = (f"export UV_PYTHON_INSTALL_DIR={p}/runtime UV_PYTHON_PREFERENCE=only-managed "
               f"UV_NO_CACHE=1 UV_PROJECT_ENVIRONMENT={venv}")
        cases = " ".join(f"{a}) t={t}; s={UV_SHA256[t]};;" for a, t in (("amd64", "x86_64"), ("arm64", "aarch64")))
        out = [_run(
            f'case "$(dpkg --print-architecture)" in {cases} '
            '*) echo "glove toolchains: unsupported architecture" >&2; exit 1;; esac',
            'f="uv-$t-unknown-linux-gnu.tar.gz" && cd /tmp',
            f'curl -fsSLO "https://github.com/astral-sh/uv/releases/download/{UV_VERSION}/$f"',
            'echo "$s  $f" | sha256sum -c -',
            f"mkdir -p {p}/bin",
            f'tar -xzf "$f" -C {p}/bin --strip-components=1 --no-same-owner "uv-$t-unknown-linux-gnu/uv"',
            'rm "$f"',
        )]
        # seeded in every mode (`uv sync` keeps the seed packages), so the brief's `pip` is the venv's
        out.append(_run(env, f"{uv} python install --no-bin {shlex.quote(tc.version)}",
                        f"{uv} venv --seed --python {shlex.quote(tc.version)} {venv}"))
        if tc.project is not None:
            dest = self.project_dir(tc)
            out.append(f"COPY {json.dumps([f'{tc.label}/{tc.project.name}', dest])}")
            install = {
                ("uv", "sync"): f"{uv} sync --locked --python {shlex.quote(tc.version)}",
                ("uv", "requirements"): f"{uv} pip install --python {py} -r requirements.txt",
                ("pip", "requirements"): f"{py} -m pip install --no-cache-dir -r requirements.txt",
            }[(tc.manager, tc.install)]
            out.append(_run(env, f"cd {dest}", install))
        if tc.packages:
            add = (f"{uv} pip install --python {py} {_q(tc.packages)}" if tc.manager == "uv"
                   else f"{py} -m pip install --no-cache-dir {_q(tc.packages)}")
            out.append(_run(env, add))
        out.append(_run(f"chmod -R a+rX {p}"))
        return out

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
    if mver and (lang != "node" or manager == "npm" or not _MANAGER_VERSION.match(mver)):
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
        h.check(tc, None, where)
    return tc


def parse(raw: Any) -> list[Toolchain]:
    """The blocks, validated without touching the filesystem (`project` unresolved)."""
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ConfigError("`toolchains` must be a list of blocks ({lang, version, manager, …})")
    blocks = [_parse_block(i, b) for i, b in enumerate(raw)]
    seen: dict[str, int] = {}
    for i, tc in enumerate(blocks):
        if tc.lang in seen:
            raise ConfigError(f"toolchains[{i}]: a second `lang: {tc.lang}` block (the first is "
                              f"toolchains[{seen[tc.lang]}]); both would install into {tc.prefix} and set the "
                              "same PATH/env")
        seen[tc.lang] = i
    return blocks


def resolve(raw: Any, session_dir: Path | None) -> list[Toolchain]:
    """`parse` plus the plan-time project checks: it resolves (``~``, relative to
    the session dir, symlinks), is a directory exposing no private path (it is
    baked into the image the agent reads), and has the files its install mode needs."""
    from .mounts import host_path
    from .sessiondir import exposes_private

    out = []
    for i, tc in enumerate(parse(raw)):
        if tc.project_spec is None:
            out.append(tc)
            continue
        where = f"toolchains[{i}] ({tc.lang}) project"
        try:
            project = host_path(session_dir, tc.project_spec)
        except ValueError:
            raise ConfigError(f"{where}: {tc.project_spec!r} must be an absolute path here") from None
        if not project.exists():
            raise ConfigError(f"{where}: {tc.project_spec!r} does not exist ({project})")
        if not project.is_dir():
            raise ConfigError(f"{where}: {tc.project_spec!r} is not a directory ({project})")
        exposed = exposes_private(session_dir, project)
        if exposed:
            raise ConfigError(f"{where}: {tc.project_spec!r} would bake {exposed[1]} ({exposed[0]}) into the image; "
                              "name a directory that does not contain it")
        h = HANDLERS[tc.lang]
        modes = h.managers[tc.manager].modes
        hint = " (or `install: install`, which is not lockfile-strict)" \
            if tc.install != "install" and "install" in modes else ""
        for any_of in modes[tc.install]:
            if not any((project / f).is_file() for f in any_of):
                raise ConfigError(f"{where}: `{tc.manager}` install `{tc.install}` needs {' or '.join(any_of)} "
                                  f"in {project}{hint}")
        h.check(tc, project, f"toolchains[{i}] ({tc.lang})")
        out.append(replace(tc, project=project))
    return out


# --- render ------------------------------------------------------------------------------


def path_entries(blocks: list[Toolchain]) -> list[str]:
    return [p for tc in blocks for p in HANDLERS[tc.lang].path(tc)]


def harness_env(blocks: list[Toolchain]) -> dict[str, str]:
    """Runtime env (besides PATH, which the image sets) for the harness."""
    out: dict[str, str] = {}
    for tc in blocks:
        out.update(HANDLERS[tc.lang].env(tc))
    return out


def dockerfile_lines(blocks: list[Toolchain]) -> tuple[list[str], list[tuple[str, Path]]]:
    """(Dockerfile lines, [(label, staged project dir)]) for the derived image."""
    lines: list[str] = []
    staged: list[tuple[str, Path]] = []
    if not blocks:
        return lines, staged
    lines += [f"# toolchains: {', '.join(f'{tc.lang} {tc.version}' for tc in blocks)}", _CURL]
    for tc in blocks:
        lines.append(f"# toolchain: {tc.lang} {tc.version} ({tc.manager}"
                     + (f", install: {tc.install}" if tc.install else "") + ")")
        lines += HANDLERS[tc.lang].lines(tc)
        if tc.project is not None:
            staged.append((tc.label, tc.project))
    lines.append(f"ENV PATH={':'.join(path_entries(blocks))}:$PATH")
    return lines, staged


# Enforcers whose per-command sandbox is nono's tool profile: Chromium cannot
# start there (it is denied /proc/self/maps, /proc/sys and /etc/fonts, and its
# own sandbox setup aborts). Widening that profile is a policy decision (/proc
# is where the harness's env, with the LLM key, lives), so it is not made here.
NONO_TOOLS = frozenset({"nono", "nono+srt"})


def brief(blocks: list[Toolchain], enforcer: str = "") -> str:
    """The context-file section telling the agent what is baked in."""
    if not blocks:
        return ""
    lines = ["## Toolchains", "",
             "Baked into this image at build time (shell commands have no network, so nothing can be "
             f"installed now). Everything lives under `{ROOT}` (read-only):", ""]
    for tc in blocks:
        lines += HANDLERS[tc.lang].describe(tc)
        if tc.browsers and enforcer in NONO_TOOLS:
            lines.append(f"  - These browsers **cannot start inside a shell command** under this session's "
                         f"`{enforcer}` sandbox; don't retry, say so.")
    return "\n".join(lines)


def mount_clash(container_paths: list[str]) -> str | None:
    """The first runtime mount point overlapping ``ROOT`` (it would shadow the baked toolchains)."""
    for p in container_paths:
        p = os.path.normpath(p)
        if p == ROOT or ROOT.startswith(p.rstrip("/") + "/") or p.startswith(ROOT + "/"):
            return p
    return None
