#!/usr/bin/env bash
# Live: `enforcer: nono+srt` in a real session against the host llm stub.
#
#   bash tests/integration/test_nono_srt.sh [pi|vibe|claude-code]      (default: pi)
#
# See nono_srt_live.py for the checks. Podman refuses nono+srt (its compose
# provider can't apply the relaxed seccomp profile), so where glove says srt
# can't run, the script checks the refusal instead.
set -u
HARNESS="${1:-pi}"
RT="${RT:-docker}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMPROOT="$(mktemp -d)"; S="$TMPROOT/nonosrt"; export GLOVE_HOME="$TMPROOT/gh"
. "$ROOT/tests/integration/lib_session.sh"
STUB=
trap '[ -n "$STUB" ] && kill $STUB 2>/dev/null; rm -rf "$TMPROOT"' EXIT

stub_session "$S" "$HARNESS" nono+srt || exit 1
mkdir -p "$S/work/.git/hooks" "$S/work/.vscode" "$S/work/sub"; : > "$S/work/.git/config"; : > "$S/work/.envrc"
echo 'PROBE-DOTENV=1' > "$S/work/.env"; echo 'PROBE-DOTENV=1' > "$S/work/sub/.env.local"

runtime_facts
if [ -n "$SRT_REFUSED" ]; then
  out="$(uv run --quiet --project "$ROOT" glove check "$S" --no-container 2>&1)"
  if echo "$out" | grep -q "enforcer 'nono+srt' is not supported"; then
    echo "  PASS: $RT refuses nono+srt: $(echo "$out" | grep -o "enforcer 'nono+srt' is not supported[^.]*")"
    exit 0
  fi
  echo "  FAIL: $RT did not refuse nono+srt"; echo "$out" | tail -20; exit 1
fi

uv run --project "$ROOT" python "$ROOT/tests/integration/nono_srt_live.py" "$S"
