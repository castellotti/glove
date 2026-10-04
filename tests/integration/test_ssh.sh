#!/usr/bin/env bash
# Live: the ssh relay in a real session (Claude Code by default) against the
# host model stub and a LAN host the operator names, under each enforcer
# (default nono and nono+srt).
#
#   SSH_TEST_HOST=<host> SSH_TEST_USER=<user> SSH_KEYCHAIN=<service> \
#     bash tests/integration/test_ssh.sh [nono|nono+srt|srt ...]
#   SSH_TEST_PORT=<port> (default 22)   HARNESS=pi|vibe …   OBSERVE=1 …
#
# The Keychain item holds a private key (PEM, or base64 of it) authorized on
# that host. known_hosts comes from ssh-keyscan into the throwaway session's
# local/. The host, user and service are given at run time and never written to
# a tracked file. See ssh_live.py for the checks. Throwaway GLOVE_HOME; tears down.
set -u
: "${SSH_TEST_HOST:?set SSH_TEST_HOST (a LAN host)}" "${SSH_TEST_USER:?set SSH_TEST_USER}" \
  "${SSH_KEYCHAIN:?set SSH_KEYCHAIN (the Keychain service holding the key)}"
PORT_SSH="${SSH_TEST_PORT:-22}"
RT="${RT:-docker}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PORT="${STUB_PORT:-18085}"
HARNESS="${HARNESS:-claude-code}"
ENFORCERS=("${@:-nono}")
[ "$#" -eq 0 ] && ENFORCERS=(nono nono+srt)
TMPROOT="$(mktemp -d)"; export GLOVE_HOME="$TMPROOT/gh"
if [ "$HARNESS" = claude-code ]; then
  LLM="{provider: anthropic-compatible, location: host, endpoint: \"127.0.0.1:$PORT\", model: claude-stub, api_key: \"env:GLOVE_TEST_ANTHROPIC_KEY\"}"
  export GLOVE_TEST_ANTHROPIC_KEY=sk-ant-test-not-a-secret
  STUB_PY=anthropic_stub.py
else
  LLM="{provider: llama.cpp, location: host, endpoint: \"127.0.0.1:$PORT\", model: auto}"
  STUB_PY=llm_stub.py
fi
STUB=
trap '[ -n "$STUB" ] && kill $STUB 2>/dev/null; chmod -R u+w "$TMPROOT" 2>/dev/null; rm -rf "$TMPROOT"' EXIT
uv run --quiet --no-project python "$ROOT/tests/integration/stubs/$STUB_PY" "$PORT" > "$TMPROOT/stub.log" 2>&1 &
STUB=$!
sleep 1
OBS=""; [ -n "${OBSERVE:-}" ] && OBS="  observe: {}"
rc=0
for enf in "${ENFORCERS[@]}"; do
  S="$TMPROOT/ssh-${enf/+/-}"
  mkdir -p "$S/work" "$S/local"
  ssh-keyscan -p "$PORT_SSH" "$SSH_TEST_HOST" > "$S/local/known_hosts" 2>/dev/null
  [ -s "$S/local/known_hosts" ] || { echo "ssh-keyscan found no host key at $SSH_TEST_HOST:$PORT_SSH"; exit 2; }
  cat > "$S/glove-session.yml" <<YAML
glove: 3
template: test
runtime: $RT
harness: $HARNESS
enforcer: $enf
extensions:
  llm: $LLM
  ssh:
    key: "keychain:$SSH_KEYCHAIN"
    hosts: [{name: lanbox, to: "$SSH_TEST_HOST:$PORT_SSH", user: "$SSH_TEST_USER"}]
    known_hosts: local/known_hosts
$OBS
YAML
  uv run --project "$ROOT" python "$ROOT/tests/integration/ssh_live.py" "$S" lanbox "$SSH_TEST_USER" || rc=1
  SID="$(cat "$S/.glove/id" 2>/dev/null)"
  LEFT="$($RT ps -aq --filter name=glove-$SID-)$($RT volume ls -q --filter name=glove-$SID-)"
  if [ -n "$LEFT" ]; then echo "  FAIL leftovers: $LEFT"; rc=1; else echo "  PASS nothing left running"; fi
done
exit $rc
