#!/usr/bin/env bash
# Live: Vibe's `harness_config.project_skills` opt-in (the repo's skills, read-only
# through the masked .vibe/ and .agents/; the rest still hidden), against the
# host llm stub.
#
#   bash tests/integration/test_vibe_skills.sh [enforcer]   (default: nono)
#   RT=podman bash tests/integration/test_vibe_skills.sh
#
# See vibe_skills_live.py for the checks.
set -u
ENF="${1:-nono}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT/tests/integration/lib_session.sh"
driver_init skills

stub_session "$S" vibe "$ENF" || exit 1
uv run --project "$ROOT" python "$ROOT/tests/integration/vibe_skills_live.py" "$S"
