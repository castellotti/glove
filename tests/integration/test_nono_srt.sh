#!/usr/bin/env bash
# Live: `enforcer: nono+srt` in a real session against the host llm stub.
#
#   bash tests/integration/test_nono_srt.sh [pi|vibe]      (default: pi)
#
# See nono_srt_live.py for the checks. Podman refuses nono+srt (its compose
# provider can't apply the relaxed seccomp profile), so RT=podman checks that.
set -u
HARNESS="${1:-pi}"
RT="${RT:-docker}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PORT="${STUB_PORT:-18080}"
TMPROOT="$(mktemp -d)"; S="$TMPROOT/nonosrt"; export GLOVE_HOME="$TMPROOT/gh"
STUB=
trap '[ -n "$STUB" ] && kill $STUB 2>/dev/null; rm -rf "$TMPROOT"' EXIT

uv run --quiet --project "$ROOT" glove new minimal "$S" >/dev/null
cat > "$S/glove-session.yml" <<YAML
glove: 3
template: minimal
runtime: $RT
harness: $HARNESS
enforcer: nono+srt
env: {FAKE_API_KEY: sk-probe-not-a-secret}
extensions:
  llm: {provider: llama.cpp, location: host, endpoint: "127.0.0.1:$PORT", model: auto}
YAML
mkdir -p "$S/work/.git/hooks" "$S/work/.vscode" "$S/work/sub"; : > "$S/work/.git/config"; : > "$S/work/.envrc"
echo 'PROBE-DOTENV=1' > "$S/work/.env"; echo 'PROBE-DOTENV=1' > "$S/work/sub/.env.local"

if [ "$RT" = podman ]; then
  out="$(uv run --quiet --project "$ROOT" glove check "$S" --no-container 2>&1)"
  if echo "$out" | grep -q "not supported on the podman runtime"; then
    echo "  PASS: podman refuses nono+srt: $(echo "$out" | grep -o "enforcer 'nono+srt' is not supported[^.]*")"
    exit 0
  fi
  echo "  FAIL: podman did not refuse nono+srt"; echo "$out" | tail -20; exit 1
fi

uv run --quiet --no-project python "$ROOT/tests/integration/stubs/llm_stub.py" "$PORT" > "$TMPROOT/stub.log" 2>&1 &
STUB=$!
sleep 1
uv run --project "$ROOT" python "$ROOT/tests/integration/nono_srt_live.py" "$S"
