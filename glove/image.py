"""Compose extension image layers into a derived harness image.

The minimal base (``glove/<harness>:<ver>``) is built from the harness's own
Dockerfile. When extensions contribute image layers or Pi extensions, glove
composes a *derived* image: ``FROM <base>`` plus each contribution, in
extension order. Its tag is content-addressed — a hash of the rendered
Dockerfile and every staged file — so any change to a layer, a setting that
selects one, or an asset yields a new image, and "not selected" means "not in
the image".
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from .harness import HarnessProfile, adapter_call

if TYPE_CHECKING:
    from .extensions import Composition
    from .harnessconfig import AdapterContext

LAYER_KEYS = frozenset({"apt", "pip", "npm", "copy", "copy_host", "run", "env", "stage"})
# Never staged or hashed: host build output and caches (a host node_modules or
# .venv is the wrong OS/arch, and would poison the content hash), and macOS's
# Finder metadata.
STAGE_IGNORE = ("node_modules", "__pycache__", ".venv", ".git", ".DS_Store")
ENV_VAR = re.compile(r"^[A-Z][A-Z0-9_]*\Z")  # an env name glove renders (image ENV, harness env)


def _q(pkgs) -> str:
    """Shell-quote package tokens (pip version specifiers carry `<`/`>`/`;`)."""
    return shlex.join(map(str, pkgs))


def _apt_bootstrap(probe: str, pkgs) -> str:
    """Apt-install `pkgs` unless the base image already has `probe`."""
    return f"RUN {apt_bootstrap(probe, pkgs)}"


def apt_bootstrap(probe: str, pkgs) -> str:
    """`_apt_bootstrap` without the `RUN` (a step of a longer one)."""
    return (f"command -v {probe} >/dev/null || (apt-get update "
            f"&& apt-get install -y --no-install-recommends {_q(pkgs)} "
            "&& rm -rf /var/lib/apt/lists/*)")


def run_body(prefix: str, *steps: str) -> str:
    """A `run` item that leaves everything it wrote under `prefix` readable by
    the (non-root) harness, touching only what needs it (a blanket `chmod -R`
    would copy every file of earlier layers up into this one)."""
    readable = (f"find {prefix} \\( ! -perm -a+r -o -perm /a+x ! -perm -a+x \\) "
                "-exec chmod a+rX {} +")
    return " \\\n    && ".join([*steps, readable])


def fetch_steps(arch: dict[str, str], name: str, url: str, verify: str, dest: str, member: str = "") -> list[str]:
    """Build steps: download tarball `name` (`$a`/`$t`/`$s` set per dpkg arch by
    `arch`) from `url`, check it with `verify`, and unpack it (or one `member`) into `dest`."""
    cases = " ".join(f"{d}) {v};;" for d, v in arch.items())
    return [
        f'case "$(dpkg --print-architecture)" in {cases} '
        '*) echo "glove: unsupported architecture" >&2; exit 1;; esac',
        f'f="{name}" && cd /tmp',
        f'curl -fsSLO "{url}/$f"',
        verify,
        f"mkdir -p {dest}",
        f'tar -xzf "$f" -C {dest} --strip-components=1 --no-same-owner' + (f' "{member}"' if member else ""),
        'rm "$f"',
    ]


# uv, pinned with its release checksums so the build trusts no download it did not expect.
UV_VERSION = "0.12.22"
UV_SHA256 = {
    "x86_64": "b9980552309f09c15172b8be828555e375097f16deb459795ce7bfd200380f0b",
    "aarch64": "6f66a14e8239871fb477f9746c941fedfa77e8fe28a8bc7c07e1dc7f53a66712",
}


def uv_steps(prefix: str) -> list[str]:
    """Build steps: the pinned uv (checksum-verified) into `<prefix>/bin`."""
    return fetch_steps({d: f"t={t}; s={UV_SHA256[t]}" for d, t in (("amd64", "x86_64"), ("arm64", "aarch64"))},
                       "uv-$t-unknown-linux-gnu.tar.gz",
                       f"https://github.com/astral-sh/uv/releases/download/{UV_VERSION}",
                       'echo "$s  $f" | sha256sum -c -', f"{prefix}/bin", member="uv-$t-unknown-linux-gnu/uv")


def staged_name(ext: str, src: Path) -> str:
    """Build-context path a source is staged at, namespaced by extension."""
    return f"{ext}/{src.name}"


def _layer_lines(ext: str, layer: dict, profile: HarnessProfile,
                 ext_dir: Path) -> tuple[list[str], list[tuple[str, Path]]]:
    """(Dockerfile lines, [(label, staged source)]) for one layer. A `copy`
    source is a path inside the extension; a `copy_host` source (only from a
    `contribute` hook: a manifest's is refused) an absolute host path the hook
    checked, staged under `<ext><its destination's parent>`; `env` image ENV
    lines (Docker expands `$VAR` in a value, so one may extend another:
    `$PATH`). `stage: late`: see `render_dockerfile`."""
    unknown = set(layer) - LAYER_KEYS
    if unknown:
        raise ValueError(f"extension {ext!r}: unknown image layer keys {sorted(unknown)}")
    if layer.get("stage") not in (None, "late"):
        raise ValueError(f"extension {ext!r}: image layer `stage` is `late` or unset, got {layer['stage']!r}")
    lines: list[str] = []
    sources: list[tuple[str, Path]] = []
    if layer.get("apt"):
        lines.append(
            "RUN apt-get update "
            f"&& apt-get install -y --no-install-recommends {_q(layer['apt'])} "
            "&& rm -rf /var/lib/apt/lists/*"
        )
    if layer.get("pip"):
        if profile.pip_install is None:
            raise ValueError(
                f"harness {profile.name!r} has no Python installer but extension {ext!r} "
                f"requests pip packages {list(layer['pip'])}"
            )
        if profile.pip_bootstrap:
            lines.append(_apt_bootstrap("pip3", profile.pip_bootstrap))
        lines.append(f"RUN {' '.join(profile.pip_install)} {_q(layer['pip'])}")
    if layer.get("npm"):
        lines.append(f"RUN npm install -g {_q(layer['npm'])}")
    for src, dst in layer.get("copy") or []:
        path = (ext_dir / src).resolve()
        if not path.exists() or not path.is_relative_to(ext_dir):
            raise ValueError(f"extension {ext!r}: image copy source {src!r} must exist inside the extension")
        sources.append((ext, path))
        lines.append(f"COPY {staged_name(ext, path)} {dst}")
    for src, dst in layer.get("copy_host") or []:
        path, label = Path(src), f"{ext}{PurePosixPath(dst).parent}"
        if not path.is_absolute() or not path.exists():
            raise ValueError(f"extension {ext!r}: image copy_host source {src} must be an existing absolute path")
        sources.append((label, path))
        lines.append(f"COPY {staged_name(label, path)} {dst}")
    for cmd in layer.get("run") or []:
        lines.append(f"RUN {cmd}")
    for k, v in (layer.get("env") or {}).items():
        if not ENV_VAR.fullmatch(str(k)) or "\n" in str(v):
            raise ValueError(f"extension {ext!r}: image env {k!r}: a name, and a value on one line")
        lines.append(f"ENV {k}={json.dumps(str(v), ensure_ascii=False)}")
    return lines, sources


def _stage(layer: dict) -> int:
    """0: early, 1: `stage: late`, 2: copies a host tree."""
    return 1 if layer.get("stage") else 2 if layer.get("copy_host") else 0


def render_dockerfile(
    base_tag: str, profile: HarnessProfile, comp: Composition, actx: AdapterContext,
) -> tuple[str | None, list[tuple[str, Path]]]:
    """(Dockerfile text, [(ext, staged source)]) for the derived image: the
    extensions' contributions, their late ones (`stage: late`, e.g. the
    toolchains, whose PATH never affects an earlier build step), the layers
    that copy host trees (a user's checkouts change often: an edit rebuilds
    nothing else), then the `corporate_ca` bundle (last: a new CA rebuilds no
    toolchain layer). (None, []) when nothing contributes: the session runs
    the base image."""
    lines = [f"# Generated by glove — derived image: {base_tag} + extensions.", f"FROM {base_tag}"]
    staged: list[tuple[str, Path]] = []

    env_set: dict[str, str] = {}  # image ENV name → the extension setting it

    def extension_layers(stage: int) -> None:
        for ext, layer in comp.image_layers:
            if _stage(layer) == stage:
                if both := sorted(k for k in layer.get("env") or {} if env_set.setdefault(k, ext) != ext):
                    raise ValueError(f"extension {ext!r}: image env {both} is already set by another extension")
                lines.append(f"# extension: {ext}")
                body, sources = _layer_lines(ext, layer, profile, comp.by_name(ext).manifest.path)
                lines.extend(body)
                staged.extend(sources)

    extension_layers(0)
    # the harness's own image contributions (e.g. Pi's `-e` extensions)
    body, sources = adapter_call(profile, "image_lines", actx, default=([], []))
    lines += body
    staged += sources
    for ext, src, dest in comp.skills:
        if src is not None:
            staged.append((ext, src))
            lines.append(f"# extension: {ext} (skill)")
            lines.append(f"COPY {staged_name(ext, src)} {dest}")
    extension_layers(1)
    extension_layers(2)
    if comp.corporate_ca is not None:  # validated (glove/cafile.py): certificates only
        from .cafile import CA_BUNDLE_PATH, SYSTEM_ROOTS

        staged.append(("corporate_ca", comp.corporate_ca))
        tmp = "/tmp/glove-corporate-ca.pem"
        lines += ["# corporate_ca: the image's roots, then the session's CA (cafile.CA_BUNDLE_ENV)",
                  f"COPY {staged_name('corporate_ca', comp.corporate_ca)} {tmp}",
                  f"RUN test -s {SYSTEM_ROOTS} && mkdir -p {Path(CA_BUNDLE_PATH).parent} "
                  f"&& cat {SYSTEM_ROOTS} {tmp} > {CA_BUNDLE_PATH} && chmod 0644 {CA_BUNDLE_PATH} && rm {tmp}"]
    if len(lines) == 2:
        return None, []
    seen: dict[str, Path] = {}
    for ext, src in staged:  # staged by name: two sources must not share one
        other = seen.setdefault(staged_name(ext, src), src)
        if other != src:
            raise ValueError(f"extension {ext!r}: {src} and {other} would both stage as {staged_name(ext, src)!r}; "
                             "rename one")
    return "\n".join(lines) + "\n", staged


def _stage_files(src: Path) -> list[Path]:
    """The files (and symlinks, never followed) `stage_context` copies from a
    directory, sorted; STAGE_IGNORE trees are pruned, not walked."""
    out: list[Path] = []
    for root, dirs, files in os.walk(src):
        dirs[:] = [d for d in dirs if d not in STAGE_IGNORE]
        out += [Path(root, d) for d in dirs if Path(root, d).is_symlink()]
        out += [Path(root, f) for f in files if f not in STAGE_IGNORE]
    return sorted(out)


def content_hash(dockerfile: str, staged: list[tuple[str, Path]]) -> str:
    h = hashlib.sha256(dockerfile.encode())
    for ext, src in staged:
        for f in [src] if src.is_file() else _stage_files(src):
            h.update(f"{ext}/{f.relative_to(src.parent)}".encode())
            # a symlink is staged as a link (never followed out of its tree)
            h.update(f"-> {os.readlink(f)}".encode() if f.is_symlink() else f.read_bytes())
    return h.hexdigest()[:10]


def stage_context(dest: Path, staged: list[tuple[str, Path]]) -> None:
    """Copy every staged source into the build context ``dest``."""
    for ext, src in staged:
        target = dest / staged_name(ext, src)
        target.parent.mkdir(parents=True, exist_ok=True)
        if src.is_dir():
            shutil.copytree(src, target, dirs_exist_ok=True, symlinks=True,
                            ignore=shutil.ignore_patterns(*STAGE_IGNORE))
        else:
            shutil.copy2(src, target)
