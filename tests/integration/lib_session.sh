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

#   driver_init [name]
#     a driver's throwaway state: TMPROOT (a fresh dir), S=$TMPROOT/<name>, a
#     fresh GLOVE_HOME under it (never the operator's: a driver ignores an
#     exported one), and an EXIT trap that stops the stub ($STUB) and removes
#     TMPROOT (`chmod -R u+w` first: a session dir holds read-only placeholders;
#     once more after a pause: Docker Desktop's file share can hold a bind's
#     source briefly after `compose down`)
driver_init() {
  TMPROOT="$(mktemp -d)"; S="$TMPROOT/${1:-session}"; export GLOVE_HOME="$TMPROOT/gh"; STUB=
  trap '[ -n "$STUB" ] && kill "$STUB" 2>/dev/null; chmod -R u+w "$TMPROOT" 2>/dev/null
        rm -rf "$TMPROOT" 2>/dev/null || { sleep 3; rm -rf "$TMPROOT"; }' EXIT
}

#   image_driver
#     driver_init for the drivers that run the harness image by hand: WORKDIR
#     and HOMEDIR (bound at /work and /home/agent) under TMPROOT
image_driver() {
  driver_init; WORKDIR="$TMPROOT/work"; HOMEDIR="$TMPROOT/home"; mkdir -p "$WORKDIR" "$HOMEDIR"
}

#   start_stub <port> <log> [stub]
#     starts stubs/<stub> (default $STUB_PY, see stub_llm) on <port> in the
#     background (STUB: its pid, for driver_init's trap) and waits until it
#     listens (wait_stub)
start_stub() {
  launch_stub "$@" && wait_stub "$1" "$2"
}

launch_stub() {
  uv run --quiet --no-project python "$ROOT/tests/integration/stubs/${3:-$STUB_PY}" "$1" > "$2" 2>&1 &
  STUB=$!; disown "$STUB"
}

#   wait_stub <port> <log>
#     until $STUB listens on <port>; a stub that exits (e.g. on a port another
#     run holds) fails here: the listener would be someone else's
wait_stub() {
  for _ in $(seq 300); do
    kill -0 "$STUB" 2>/dev/null || { echo "the llm stub exited (port $1 taken?): $2" >&2; return 1; }
    (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0; sleep 0.1
  done
  echo "the llm stub is not listening on :$1 ($2)" >&2; return 1
}

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
#     so it gets the anthropic stub, every other harness llama.cpp. Each has a
#     fake key (GLOVE_TEST_LLM_KEY, exported: glove resolves `env:` from it and
#     the stub, started after this, answers only requests carrying it), so
#     glove's llm-auth holds it and the harness a placeholder.
#     claude-code-oauth: Claude Code with a subscription token for the
#     provider itself (no STUB_PY: the driver stands in for it).
stub_llm() {
  export GLOVE_TEST_LLM_KEY=sk-test-llm-inject-1
  local key='api_key: "env:GLOVE_TEST_LLM_KEY"'
  STUB_PY=
  if [ "$1" = claude-code-oauth ]; then
    LLM="{provider: anthropic, auth: oauth, model: claude-stub, $key}"
  elif [ "$1" = claude-code ]; then
    STUB_PY=anthropic_stub.py
    LLM="{provider: anthropic-compatible, location: host, endpoint: \"127.0.0.1:$2\", model: claude-stub, $key}"
  else
    STUB_PY=llm_stub.py
    LLM="{provider: llama.cpp, location: host, endpoint: \"127.0.0.1:$2\", model: auto, $key}"
  fi
}

#   stub_session <dir> <harness> <enforcer> [extra yaml: top-level, or indented for more extensions]
#     a session at <dir> (`glove new minimal`, runtime $RT) whose llm is the
#     tool-driving host stub on $STUB_PORT (default 18080), started in the
#     background (start_stub; its log <dir>.stub.log),
#     with a secret-shaped FAKE_API_KEY in its env (claude-code-oauth: no stub,
#     see stub_llm)
stub_session() {
  local dir="$1" harness="$2" enforcer="$3" extra="${4:-}" port="${STUB_PORT:-18080}"
  stub_llm "$harness" "$port"
  [ -z "$STUB_PY" ] || launch_stub "$port" "$dir.stub.log"
  uv run --quiet --project "$ROOT" glove new minimal "$dir" >/dev/null || return 1
  printf 'glove: 3\ntemplate: minimal\nruntime: %s\nharness: %s\nenforcer: %s\nenv: {FAKE_API_KEY: sk-probe-not-a-secret}\nextensions:\n  llm: %s\n%b' \
    "${RT:-docker}" "${harness%-oauth}" "$enforcer" "$LLM" "$extra" > "$dir/glove-session.yml"
  [ -z "$STUB_PY" ] || wait_stub "$port" "$dir.stub.log"
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

#   ensure_image <harness> [srt]
#     glove_image's tag, built first (`glove build`, provider $RT) when the
#     runtime doesn't have it: the drivers that run the image directly
ensure_image() {
  local tag; tag="$(glove_image "$@")" || return 1
  if ! "${RT:-docker}" image inspect "$tag" >/dev/null 2>&1; then
    echo "building $tag" >&2
    uv run --quiet --project "$ROOT" glove build "$1" --provider "${RT:-docker}" ${2:+--enforcer nono+srt} >&2 || return 1
  fi
  echo "$tag"
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
