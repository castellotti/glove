"""Core-size ratchet (core-refinement P2): core may not grow past its budget unnoticed."""

from __future__ import annotations

from pathlib import Path

CORE = Path(__file__).resolve().parent.parent / "glove"

CORE_BUDGET = 9_798  # physical lines of glove/**/*.py; CLAUDE.md P2
SLACK = 50  # how far core may shrink before the budget must follow it down


def core_lines(root: Path = CORE) -> int:
    return sum(len(p.read_bytes().splitlines()) for p in root.rglob("*.py"))


def test_core_stays_within_its_budget():
    n = core_lines()
    assert n <= CORE_BUDGET, f"core is {n} lines, over CORE_BUDGET={CORE_BUDGET}: see CLAUDE.md P1 and P2"
    assert n >= CORE_BUDGET - SLACK, f"core shrank to {n} lines: lower CORE_BUDGET to {n}"


def test_core_lines_counts_every_module(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "a.py").write_text("x = 1\n\ny = 2\n")
    (tmp_path / "sub" / "b.py").write_text("z = 3")
    (tmp_path / "notes.txt").write_text("not\ncounted\n")
    assert core_lines(tmp_path) == 4
