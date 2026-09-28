#!/usr/bin/env bash
# Live: the `llm` extension at `location: host` against a stub llama-server on
# this Mac (tests/integration/stubs/llm_stub.py). Checks that `model: auto` and
# `capabilities: auto` resolve through the forwarder, that Pi's models.json gets
# the resolved model with `input: ["text","image"]`, and that Pi's answer comes
# from the stub through glove-<id>-llm → host.docker.internal.
#
# Usage:  bash tests/integration/test_llm_host_stub.sh
# Requires: docker + `glove build pi`.
set -u
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PORT="${STUB_PORT:-18080}"
TMPROOT="$(mktemp -d)"; WORK="$TMPROOT/llmstub"; mkdir "$WORK"; export GLOVE_HOME="$TMPROOT/gh"
python3 "$ROOT/tests/integration/stubs/llm_stub.py" "$PORT" > "$TMPROOT/stub.log" 2>&1 &
STUB=$!
trap 'kill $STUB 2>/dev/null; rm -rf "$TMPROOT"' EXIT
sleep 1
cd "$WORK" && uv run --project "$ROOT" glove init pi >/dev/null
cat >> "$GLOVE_HOME/envs/$(basename "$WORK")/glove.yaml" <<YAML
extensions:
  llm: {provider: llama.cpp, location: host, endpoint: "127.0.0.1:$PORT", model: auto, capabilities: auto}
YAML
uv run --project "$ROOT" python "$ROOT/tests/integration/llm_live.py" pi "Say hello."
rc=$?
echo "== stub request log"
cat "$TMPROOT/stub.log"; rm -f "$TMPROOT/stub.log"
exit $rc
