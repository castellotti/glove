#!/usr/bin/env bash
# Live: `glove up` re-allocates and retries when another network takes the
# session's subnet between the plan and `compose up`, against the host llm stub.
#
#   bash tests/integration/test_subnet_race.sh          (pi, nono; RT=podman too)
#
# See subnet_race_live.py for the checks.
set -u
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT/tests/integration/lib_session.sh"
driver_init race

runtime_facts
stub_session "$S" pi nono || exit 1
uv run --project "$ROOT" python "$ROOT/tests/integration/subnet_race_live.py" "$S"
