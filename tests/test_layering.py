"""Layering: core (``glove``) must never import ``extensions`` (v3 D1)."""

from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
LINT_IMPORTS = Path(sys.executable).parent / "lint-imports"

CONTRACT = """\
[importlinter]
root_packages =
    glove
    extensions

[importlinter:contract:core]
name = Core does not import extensions
type = forbidden
source_modules = glove
forbidden_modules = extensions
"""


def _run(cwd: Path, *args: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONPATH": str(cwd)}
    return subprocess.run(
        [str(LINT_IMPORTS), "--no-cache", *args], cwd=cwd, env=env, capture_output=True, text=True, check=False
    )


def test_core_does_not_import_extensions():
    r = _run(REPO)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "Core does not import extensions KEPT" in r.stdout


def test_contract_catches_a_core_to_extension_import(tmp_path):
    # The same contract over a toy tree with the forbidden edge: must break.
    (tmp_path / "glove").mkdir()
    (tmp_path / "glove" / "__init__.py").write_text("import extensions.vpn\n")
    (tmp_path / "extensions" / "vpn").mkdir(parents=True)
    (tmp_path / "extensions" / "__init__.py").write_text("")
    (tmp_path / "extensions" / "vpn" / "__init__.py").write_text("")
    (tmp_path / ".importlinter").write_text(CONTRACT)
    r = _run(tmp_path, "--config", ".importlinter")
    assert r.returncode != 0
    assert "BROKEN" in r.stdout


# --- Extension contracts. An AST scan of every non-test module under extensions/ and harnesses/:
# from core they import only `glove.api`; an extension imports another only if it requires it (any
# form, `when:` ignored); a harness adapter imports no extension.


def _imports(path: Path, root: Path) -> list[str]:
    """`top.second` of every module `path` imports (e.g. `glove.config`), relative imports resolved."""
    base = list(path.relative_to(root).parent.parts)
    out = []
    for node in ast.walk(ast.parse(path.read_text(), str(path))):
        if isinstance(node, ast.Import):
            out += [a.name for a in node.names]
        # (an import above the top package fails at run time; nothing to check)
        elif isinstance(node, ast.ImportFrom) and node.level <= len(base):
            mod = node.module
            if node.level:
                mod = ".".join(base[: len(base) - node.level + 1] + ([mod] if mod else []))
            out += [f"{mod}.{a.name}" for a in node.names]
    return list(dict.fromkeys(".".join(m.split(".")[:2]) for m in out))


def _requires(root: Path) -> dict[str, set[str]]:
    """Each extension's `requires` closure by extension name (slots and `when:` ignored)."""
    exts = {p.parent.name: p for p in (root / "extensions").glob("*/extension.yml")}
    direct = {}
    for name, p in exts.items():
        reqs = (yaml.safe_load(p.read_text()) or {}).get("requires") or []
        direct[name] = {r if isinstance(r, str) else r.get("extension") for r in reqs} & exts.keys()
    closure = {}
    for name in exts:
        seen, todo = set(), list(direct[name])
        while todo:
            n = todo.pop()
            if n not in seen:
                seen.add(n)
                todo += direct[n]
        closure[name] = seen
    return closure


def contract_violations(root: Path = REPO) -> set[str]:
    """`<file> -> <module>` for each import that breaks a contract."""
    reqs = _requires(root)
    out = set()
    for top in ("extensions", "harnesses"):
        for path in (root / top).rglob("*.py"):
            where = path.relative_to(root)
            if "tests" in where.parts:
                continue
            for mod in _imports(path, root):
                first, _, second = mod.partition(".")
                own = where.parts[1] if len(where.parts) > 2 else ""  # extensions/<own>/...
                if (
                    (first == "glove" and second != "api")
                    or (first == "extensions" and top == "harnesses")
                    or (first == "extensions" and own and second not in {own, *reqs.get(own, ())})
                ):
                    out.add(f"{where} -> {mod}")
    return out


def test_extensions_use_only_the_public_api_and_their_requirements():
    found = contract_violations()
    assert not found, (
        "imports break the extension contracts (from core, import only glove.api; import only "
        "extensions you require; adapters import no extension):\n" + "\n".join(sorted(found)))


def _toy(tmp_path: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return tmp_path


def test_contract_catches_private_core_and_adapter_imports(tmp_path):
    root = _toy(tmp_path, {
        "extensions/a/extension.yml": "name: a\n",
        "extensions/a/hooks.py": "from glove.api import secret\nimport glove.session\n",
        "extensions/a/tests/test_a.py": "from glove.session import x\n",
        "extensions/__init__.py": "from extensions.a import hooks\n",
        "extensions/b/extension.yml": "# nothing yet\n",
        "harnesses/h/adapter.py": "from glove import naming\nfrom extensions.a import hooks\n",
    })
    assert contract_violations(root) == {
        "extensions/a/hooks.py -> glove.session",
        "harnesses/h/adapter.py -> glove.naming",
        "harnesses/h/adapter.py -> extensions.a",
    }


def test_contract_allows_imports_along_requires_only(tmp_path):
    root = _toy(tmp_path, {
        "extensions/gate/extension.yml": "name: gate\n",
        "extensions/observe/extension.yml": "name: observe\nrequires: [gate, egress]\n",
        "extensions/filter/extension.yml": "name: filter\nrequires:\n  - {extension: observe, when: {x: 1}}\n",
        "extensions/filter/cli.py": "from extensions.gate.netgate import w\nfrom . import netrules\n",
        "extensions/observe/__init__.py": "from .hooks import x\nfrom ..gate import lib\n",
        "extensions/gate/lib.py": "from extensions.observe import hooks\n",
    })
    assert contract_violations(root) == {"extensions/gate/lib.py -> extensions.observe"}
