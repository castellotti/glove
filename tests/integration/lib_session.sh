# Sourced by the integration scripts: a throwaway glove session directory.
#
#   new_session <dir> <harness> [extra top-level yaml]
#     writes <dir>/glove-session.yml (runtime $RT, default docker; stub llama.cpp
#     on the host as the model)
#     and renders it with `glove plan`; afterwards:
#       $S_ID        the session id (.glove/id)
#       $S_POLICIES  <dir>/.glove/enforcer   (ring-1 policies)
#       $S_COMPOSE   <dir>/.glove/compose.yml (compose project glove-$S_ID)
# Needs ROOT (the glove checkout) and GLOVE_HOME (a throwaway home) set.
new_session() {
  local dir="$1" harness="$2" extra="${3:-}"
  mkdir -p "$dir/work"
  printf 'glove: 3\ntemplate: test\nruntime: %s\nharness: %s\nextensions:\n  llm: {provider: llama.cpp, location: host, endpoint: "127.0.0.1:8080", model: test-model}\n%b' \
    "${RT:-docker}" "$harness" "$extra" > "$dir/glove-session.yml"
  uv run --quiet --project "$ROOT" glove plan "$dir" >/dev/null || return 1
  S_ID="$(cat "$dir/.glove/id")"
  S_POLICIES="$dir/.glove/enforcer"
  S_COMPOSE="$dir/.glove/compose.yml"
}

#   stub_llm <harness> <port>
#     sets STUB_PY (the stub under stubs/ to start on <port>) and LLM (the
#     session's llm entry for it): Claude Code speaks the Anthropic Messages API,
#     so it gets the anthropic stub and a fake key; every other harness llama.cpp.
stub_llm() {
  if [ "$1" = claude-code ]; then
    STUB_PY=anthropic_stub.py
    LLM="{provider: anthropic-compatible, location: host, endpoint: \"127.0.0.1:$2\", model: claude-stub, api_key: \"env:GLOVE_TEST_ANTHROPIC_KEY\"}"
    export GLOVE_TEST_ANTHROPIC_KEY=sk-ant-test-not-a-secret
  else
    STUB_PY=llm_stub.py
    LLM="{provider: llama.cpp, location: host, endpoint: \"127.0.0.1:$2\", model: auto}"
  fi
}

#   stub_session <dir> <harness> <enforcer> [extra top-level yaml]
#     a session at <dir> (`glove new minimal`, runtime $RT) whose llm is the
#     tool-driving host stub on $STUB_PORT (default 18080), started in the
#     background (STUB: its pid, for the caller's trap; its log <dir>.stub.log),
#     with a secret-shaped FAKE_API_KEY in its env
stub_session() {
  local dir="$1" harness="$2" enforcer="$3" extra="${4:-}" port="${STUB_PORT:-18080}"
  stub_llm "$harness" "$port"
  uv run --quiet --no-project python "$ROOT/tests/integration/stubs/$STUB_PY" "$port" > "$dir.stub.log" 2>&1 &
  STUB=$!
  uv run --quiet --project "$ROOT" glove new minimal "$dir" >/dev/null || return 1
  printf 'glove: 3\ntemplate: minimal\nruntime: %s\nharness: %s\nenforcer: %s\nenv: {FAKE_API_KEY: sk-probe-not-a-secret}\nextensions:\n  llm: %s\n%b' \
    "${RT:-docker}" "$harness" "$enforcer" "$LLM" "$extra" > "$dir/glove-session.yml"
  for _ in $(seq 50); do (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null && return 0; sleep 0.1; done
  echo "the llm stub is not listening on :$port ($dir.stub.log)" >&2; return 1
}

#   glove_image <harness> [srt]
#     the harness's base image tag (content-addressed, see glove/harness.py),
#     with the srt overlay's suffix when asked
glove_image() {
  uv run --quiet --project "$ROOT" python -c 'import sys
from glove.enforcers.base import srt_suffix
from glove.harness import base_image, get_profile
print(base_image(get_profile(sys.argv[1])) + (srt_suffix() if sys.argv[2:] == ["srt"] else ""))' "$@"
}

#   runtime_facts
#     what glove knows about runtime $RT (default docker): exports its compose
#     process env (`compose_cli_env`, e.g. Podman's banner off, for compose
#     output a script captures) and sets SRT_REFUSED to why srt can't run on it
#     ("" when it can)
runtime_facts() {
  eval "$(uv run --quiet --project "$ROOT" python -c 'import shlex, sys
from glove.runtimes import get_runtime
rt = get_runtime(sys.argv[1])
for k, v in rt.compose_cli_env.items():
    print(f"export {k}={shlex.quote(v)}")
print("SRT_REFUSED=" + shlex.quote(rt.unsupported_enforcer_reason("srt") or ""))' "${RT:-docker}")"
}
