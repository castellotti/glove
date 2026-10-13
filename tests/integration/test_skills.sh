#!/usr/bin/env bash
# Live: the `skills` extension — a Claude Code plugin (the fixture in
# fixtures/skills-plugin) baked into the harness image and used through the
# agent's own tools, against the tool-driving host stub.
#
#   bash tests/integration/test_skills.sh [harness] [enforcer]   (default: pi, the runtime's default)
#   RT=podman bash tests/integration/test_skills.sh pi nono
#
# See skills_live.py for the checks.
set -u
H="${1:-pi}"
ENF="${2:-$([ "${RT:-docker}" = podman ] && echo nono || echo nono+srt)}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT/tests/integration/lib_session.sh"
driver_init skills

MCP=""; [ "$H" != pi ] && MCP=", mcp: true, tools: {demo: [echo]}"
stub_session "$S" "$H" "$ENF" "  skills:\n    plugins:\n      demo: {path: skills/demo, skills: [greet]$MCP}\n" || exit 1
mkdir -p "$S/skills" && cp -R "$ROOT/tests/integration/fixtures/skills-plugin/demo" "$S/skills/demo"
( cd "$S" && STUB_LOG="$S.stub.log" uv run --quiet --project "$ROOT" python "$ROOT/tests/integration/skills_live.py" . )
