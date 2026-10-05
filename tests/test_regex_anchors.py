"""Validators anchor with `\\Z`, not `$`: `$` also matches before a trailing
newline, so `.match("ok\\n")` would accept a value that then adds a compose
line, an argv element or an env entry."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from glove import extensions, sessiondir, toolchains
from glove.extensions import load_module
from glove.runtimes import docker

ROOT = Path(__file__).resolve().parents[1]
SSH = load_module(ROOT / "extensions/ssh/hooks.py", "ssh_hooks")
VPN = load_module(ROOT / "extensions/vpn/hooks.py", "vpn")


@pytest.mark.parametrize("pattern,ok", [
    (sessiondir.ID_RE, "s-0a1b2c"),
    (docker._ENV_KEY, "PATH"),
    (extensions._NAME, "github"),
    (extensions._ENV_VAR, "GLOVE_X"),
    (toolchains._PACKAGE, "requests==2.32.3"),
    (SSH.USER, "agent"),
    (SSH.HOST, "lab.lan"),
    (VPN.WG_KEY, "A" * 43 + "="),
])
def test_a_trailing_newline_is_refused(pattern, ok):
    assert pattern.match(ok)
    assert not pattern.match(ok + "\n")


def test_no_validator_anchors_with_dollar():
    # MULTILINE patterns mean `$` (end of each line) on purpose
    bad = []
    for path in [*ROOT.glob("glove/**/*.py"), *ROOT.glob("extensions/**/*.py"), *ROOT.glob("harnesses/**/*.py")]:
        if "/tests/" in str(path):
            continue
        for n, line in enumerate(path.read_text().splitlines(), 1):
            if "re.compile(" in line and "MULTILINE" not in line and re.search(r'\$"\)', line):
                bad.append(f"{path.relative_to(ROOT)}:{n}")
    assert not bad, bad
