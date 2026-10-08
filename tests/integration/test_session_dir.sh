#!/usr/bin/env bash
# Live (v3 M3): the session-directory lifecycle against a stub llama-server.
#
#   bash tests/integration/test_session_dir.sh            # Docker
#   RT=podman bash tests/integration/test_session_dir.sh  # Podman
#
#  1. `glove new minimal <tmp>/g1`, fill the llm <set-me>s → the stub, `glove check`
#  2. glove's launch path (tests/integration/llm_live.py --isolation): sidecars up,
#     `model: auto` resolved, Pi answers, and inside the harness container nothing
#     of the session dir but work/ and .glove/home is visible (`ls /work/..`,
#     `stat /etc/glove`, a find for .glove / glove-session.yml / effective.yml …)
#  3. `glove plan` shows the resolution recorded in .glove/effective.yml
#  4. `glove down`; delete the directory → only the registry row remains under
#     GLOVE_HOME (besides glove's own control/ and lock file); `glove ls` marks it
#     missing and `glove gc` removes it.
# Uses a throwaway GLOVE_HOME: never touches ~/.glove. Requires docker + `glove build pi`.
set -u
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RT="${RT:-docker}"
PORT="${STUB_PORT:-18081}"
. "$ROOT/tests/integration/lib_session.sh"
driver_init g1; G1="$S"
start_stub "$PORT" "$TMPROOT/stub.log" llm_stub.py || exit 1
glove() { uv run --quiet --project "$ROOT" glove "$@"; }
pass=0; fail=0
ok() { if eval "$2"; then echo "  PASS $1"; pass=$((pass+1)); else echo "  FAIL $1"; fail=$((fail+1)); fi; }

echo "== runtime: $RT"
echo "== glove new minimal $G1"
glove new minimal "$G1"
sed -i.bak -e 's/provider: <set-me> .*/provider: llama.cpp/' -e 's/location: <set-me> .*/location: host/' \
  -e "s/endpoint: <set-me> .*/endpoint: \"127.0.0.1:$PORT\"/" -e "s/^runtime: .*/runtime: $RT/" "$G1/glove-session.yml" && rm "$G1/glove-session.yml.bak"
SID="$(cat "$G1/.glove/id")"
ok "id is <dirname>-<6hex>" "echo '$SID' | grep -Eq '^g1-[0-9a-f]{6}$'"
ok ".glove is 0700" "[ \"\$(stat -f %Lp '$G1/.glove')\" = 700 ]"
echo "== glove check"
( cd "$G1" && glove check --no-container ) | sed 's/^/   /'
echo "== live launch path + isolation"
( cd "$G1" && uv run --quiet --project "$ROOT" python "$ROOT/tests/integration/llm_live.py" . "Say hello." --isolation ) \
  > "$TMPROOT/live.log" 2>&1
LIVE=$?
grep -v '^ Container\|Network \|^#\|^ ✔' "$TMPROOT/live.log"
ok "launch path + isolation exit 0" "[ $LIVE -eq 0 ]"
ok "model: auto resolved via the stub" "grep -q 'model: auto →' '$TMPROOT/live.log'"
ok "no session state visible in the harness" "grep -q 'ISOLATION: PASS' '$TMPROOT/live.log'"
echo "== glove plan (after launch)"
( cd "$G1" && glove plan ) > "$TMPROOT/plan.log" 2>&1; grep -E 'session:|resolved at last launch|subnet' "$TMPROOT/plan.log"
ok "plan shows the resolved model" "grep -q 'resolved at last launch' '$TMPROOT/plan.log'"
echo "== glove down; rm -rf $G1"
( cd "$G1" && glove down ) >/dev/null 2>&1
rm -rf "$G1"
echo "   GLOVE_HOME now holds:"; (cd "$GLOVE_HOME" && find . | sort | sed 's/^/     /')
ok "only the registry row (+ control/, lock) remains" \
  "[ \"\$(cd '$GLOVE_HOME' && find . -mindepth 1 | sort | tr '\n' ' ')\" = './control ./registry.json ./registry.json.lock ' ]"
ok "the row names $SID" "grep -q '\"$SID\"' '$GLOVE_HOME/registry.json'"
echo "== glove ls; glove gc"
glove ls
glove gc --yes
ok "gc removed the row" "! grep -q '\"$SID\"' '$GLOVE_HOME/registry.json'"
ok "no containers or networks left" "[ -z \"\$($RT ps -aq --filter name=glove-$SID)\" ] && [ -z \"\$($RT network ls -q --filter name=glove-$SID)\" ]"
echo "== stub request log"; cat "$TMPROOT/stub.log"
echo "== RESULT: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
