"""Fixtures the commands' tests share."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _wide_console(monkeypatch):
    from glove.api.commands import console, err

    for c in (console, err):
        monkeypatch.setattr(c, "width", 400)  # no wrapping of long paths in assertions


@pytest.fixture
def home(tmp_path, monkeypatch):
    ghome = tmp_path / "ghome"
    monkeypatch.setenv("GLOVE_HOME", str(ghome))
    return ghome
