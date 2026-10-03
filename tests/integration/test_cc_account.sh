#!/usr/bin/env bash
# Live, opt-in: Claude Code on a real Anthropic account (spends a little usage).
#
#   GLOVE_CC_TOKEN_SERVICE=<keychain service> bash tests/integration/test_cc_account.sh [model] [enforcer]
#   OBSERVE=1 …   also turn on observe (flows + transcripts exported for Layman)
#
# The Keychain item holds a token from `claude setup-token` (`glove keychain set
# <service>`); glove reads it at launch, in memory. See cc_account_live.py.
set -u
: "${GLOVE_CC_TOKEN_SERVICE:?set GLOVE_CC_TOKEN_SERVICE to the Keychain service holding a claude setup-token token}"
MODEL="${1:-claude-haiku-4-5}"
ENFORCER="${2:-nono+srt}"
RT="${RT:-docker}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMPROOT="$(mktemp -d)"; S="$TMPROOT/ccacct"; export GLOVE_HOME="$TMPROOT/gh"
trap 'chmod -R u+w "$TMPROOT" 2>/dev/null; rm -rf "$TMPROOT"' EXIT
mkdir -p "$S/work"
cat > "$S/glove-session.yml" <<YAML
glove: 3
template: test
runtime: $RT
harness: claude-code
enforcer: $ENFORCER
extensions:
  llm: {provider: anthropic, model: $MODEL, auth: oauth, api_key: "keychain:$GLOVE_CC_TOKEN_SERVICE"}
YAML
[ "${OBSERVE:-0}" = 1 ] && printf '  observe: {}\n' >> "$S/glove-session.yml"
uv run --project "$ROOT" python "$ROOT/tests/integration/cc_account_live.py" "$S"
