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
