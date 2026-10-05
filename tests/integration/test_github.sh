#!/usr/bin/env bash
# Live: the github relay in a real session (Claude Code by default) against the
# host model stub, under each enforcer (default nono and nono+srt).
#
#   bash tests/integration/test_github.sh [nono|nono+srt|srt ...]
#   HARNESS=pi|vibe …              # another harness's shell tool
#   OBSERVE=1 …                    # with observe: the relay's flows (client github)
#   GH_KEYCHAIN=<service> …        # a real token: gh api user / pr list / api, read-only
#   … GH_SCRATCH_REPO=<owner/repo> # and against that repo, a push of a throwaway branch
#
# See github_live.py for the checks. Without GH_KEYCHAIN the token is a fake
# (GitHub's public side still answers: ls-remote, clone, pull). The Keychain
# service and the scratch repository are the operator's, given at run time and
# never written to a tracked file. Uses a throwaway GLOVE_HOME; tears down.
set -u
RT="${RT:-docker}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PORT="${STUB_PORT:-18083}"
HARNESS="${HARNESS:-claude-code}"
ENFORCERS=("${@:-nono}")
[ "$#" -eq 0 ] && ENFORCERS=(nono nono+srt)
TMPROOT="$(mktemp -d)"; export GLOVE_HOME="$TMPROOT/gh"
. "$ROOT/tests/integration/lib_session.sh"
stub_llm "$HARNESS" "$PORT"
if [ -n "${GH_KEYCHAIN:-}" ]; then
  TOKEN="keychain:$GH_KEYCHAIN"
  export GH_REAL_TOKEN=1
else
  TOKEN="env:GLOVE_TEST_GH_TOKEN"
  export GLOVE_TEST_GH_TOKEN=ghp_glovetestnotasecret000000000000000000
fi
STUB=
trap '[ -n "$STUB" ] && kill $STUB 2>/dev/null; chmod -R u+w "$TMPROOT" 2>/dev/null; rm -rf "$TMPROOT"' EXIT
uv run --quiet --no-project python "$ROOT/tests/integration/stubs/$STUB_PY" "$PORT" > "$TMPROOT/stub.log" 2>&1 &
STUB=$!
sleep 1
OBS=""; [ -n "${OBSERVE:-}" ] && OBS="  observe: {}"
rc=0
for enf in "${ENFORCERS[@]}"; do
  S="$TMPROOT/gh-${enf/+/-}"
  mkdir -p "$S/work"
  cat > "$S/glove-session.yml" <<YAML
glove: 3
template: test
runtime: $RT
harness: $HARNESS
enforcer: $enf
extensions:
  llm: $LLM
  direct: {}
  github: {token: "$TOKEN"}
$OBS
YAML
  uv run --project "$ROOT" python "$ROOT/tests/integration/github_live.py" "$S" ${GH_SCRATCH_REPO:-} || rc=1
  SID="$(cat "$S/.glove/id" 2>/dev/null)"
  LEFT="$($RT ps -aq --filter name=glove-$SID-)$($RT volume ls -q --filter name=glove-$SID-)"
  if [ -n "$LEFT" ]; then echo "  FAIL leftovers: $LEFT"; rc=1; else echo "  PASS nothing left running"; fi
done
exit $rc
