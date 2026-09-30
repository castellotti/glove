#!/usr/bin/env bash
# Live (v3 M6): ocr + rag end to end, offline.
#
#   RAG_MODELS_DIR=<fastembed cache> [RAG_OBSIDIAN_DIR=<claude-obsidian>] bash tests/integration/test_rag.sh
#   RT=podman …                                                    # Podman
#
# RAG_MODELS_DIR must already hold BAAI/bge-small-en-v1.5 (`glove rag
# fetch-model` fills one). A throwaway session dir (llm → the tool-driving stub;
# ocr + rag, no egress) with the OCR fixtures and a note in work/data/input runs
# tests/integration/rag_live.py: glove-ocr and kstore sync/ask as Pi bash tool
# calls in the nono tool sandbox, read-only model mount, no network, skills in
# Pi's prompt. Uses a throwaway GLOVE_HOME; tears everything down (KEEP=1
# leaves the stack up).
set -u
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RT="${RT:-docker}"
PORT="${STUB_PORT:-18084}"
MODELS="${RAG_MODELS_DIR:?set RAG_MODELS_DIR to a fastembed cache holding BAAI/bge-small-en-v1.5}"
TMPROOT="$(mktemp -d)"; S="$TMPROOT/rag"; export GLOVE_HOME="${GLOVE_HOME:-$TMPROOT/gh}"
python3 "$ROOT/tests/integration/stubs/llm_stub.py" "$PORT" > "$TMPROOT/stub.log" 2>&1 &
STUB=$!; disown "$STUB"
trap 'kill $STUB 2>/dev/null; rm -rf "$TMPROOT"' EXIT
sleep 1
mkdir -p "$S/work/data/input"
cp "$ROOT"/extensions/ocr/tests/fixtures/{sample.png,scanned.pdf,text-layer.pdf} "$S/work/data/input/"
printf '# Field notes\n\nGlove sandboxes coding agents; the knowledge store is offline.\n' > "$S/work/data/input/notes.md"
OBS=""; if [ -n "${RAG_OBSIDIAN_DIR:-}" ]; then OBS=", obsidian_dir: \"$RAG_OBSIDIAN_DIR\""; fi
printf 'glove: 3\ntemplate: test\nruntime: %s\nharness: pi\nlimits: { pids: 512, memory: 6g, cpus: 4 }\nextensions:\n  llm: {provider: llama.cpp, location: host, endpoint: "127.0.0.1:%s", model: auto}\n  ocr: {}\n  rag: {models_dir: "%s"%s}\n' \
  "$RT" "$PORT" "$MODELS" "$OBS" > "$S/glove-session.yml"
echo "== runtime $RT"
( cd "$S" && STUB_LOG="$TMPROOT/stub.log" uv run --quiet --project "$ROOT" python "$ROOT/tests/integration/rag_live.py" . )
RC=$?
SID="$(cat "$S/.glove/id" 2>/dev/null)"
LEFT="$($RT ps -aq --filter name=glove-$SID-)$($RT network ls -q --filter name=glove-$SID-)"
if [ -n "$LEFT" ] && [ -z "${KEEP:-}" ]; then echo "  FAIL leftovers: $LEFT"; RC=1; else echo "  PASS nothing left running"; fi
exit $RC
