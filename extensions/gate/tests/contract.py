"""The Layman wire contract (v1) the gate tests check against: a tracked copy of
what the normative handoff brief specifies (the brief itself is a private
planning doc), in tests/fixtures/netobs-contract.json.

    uv run python -m extensions.gate.tests.contract   # rewrite it from the brief

Holds each schema's example record (flow, status.json, exit.ndjson, rules.json)
and the §6.1 states with the fixture or scenarios that show each."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CONTRACT_FILE = ROOT / "tests" / "fixtures" / "netobs-contract.json"
HANDOFF = ROOT / "docs" / "planning" / "network-observability-layman-handoff.md"
CONTRACT: dict = json.loads(CONTRACT_FILE.read_text())
# example records, by the brief's section heading
SECTIONS = {"flow": "## 2. Flow schema", "status": "### `status.json`", "exit": "### `exit.ndjson`",
            "rules": "## 3. Rules schema"}


def _jsonc_block(text: str, section: str) -> dict:
    """The first ```jsonc block after `section`."""
    block = re.search(r"```jsonc\n(.*?)```", text[text.index(section):], flags=re.S).group(1)
    block = re.sub(r"(?m)(^|\s)//.*$", "", block)  # strip // comments (not the // in URLs)
    return json.loads(block.replace("…", "x"))


def _named(text: str) -> list[str]:
    """Scenario names in `*(…scenario: `a`, `b`…)*` markers."""
    return [n for m in re.findall(r"\*\(([^)]*scenario[^)]*)\)\*", text) for n in re.findall(r"`([a-z-]+)`", m)]


def from_handoff(text: str) -> dict:
    """The contract as the brief states it."""
    table = text[text.index("### 6.1 States"):text.index("**Correlation with the transcript")]
    rows = [r for r in table.splitlines() if r.startswith("| ") and not r.startswith("| State") and "---" not in r]
    return {
        **{key: _jsonc_block(text, section) for key, section in SECTIONS.items()},
        "states": [{"state": row.split("|")[1].strip(), "fixture": "*(fixture" in row, "scenarios": _named(row)}
                   for row in rows],
    }


if __name__ == "__main__":
    CONTRACT_FILE.write_text(json.dumps(from_handoff(HANDOFF.read_text()), indent=1, ensure_ascii=False) + "\n")
    print(f"wrote {CONTRACT_FILE.relative_to(ROOT)}")
