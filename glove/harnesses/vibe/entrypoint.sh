#!/usr/bin/env bash
# glove harness entrypoint (PLAN §4.2).
#
# Validates the ring-1 enforcer policies (if present), then execs the compose
# `command` — which for enforcer=nono is `nono run --profile harness.json -- <TUI>`
# and for enforcer=none is the bare TUI. Fail-closed: if policies exist but are
# invalid, refuse to start (a broken policy must never silently downgrade to no
# sandbox), unless GLOVE_ENFORCER_FAIL_OPEN=1.
set -euo pipefail

ENF_DIR=/etc/glove/enforcer
FAIL_OPEN="${GLOVE_ENFORCER_FAIL_OPEN:-0}"

if [ -d "$ENF_DIR" ] && command -v nono >/dev/null 2>&1; then
  for p in harness.json tool.json; do
    if [ -f "$ENF_DIR/$p" ]; then
      if ! nono profile validate "$ENF_DIR/$p" >/dev/null 2>&1; then
        echo "glove: enforcer policy $p failed validation" >&2
        if [ "$FAIL_OPEN" != "1" ]; then
          echo "glove: refusing to start without a valid sandbox (set GLOVE_ENFORCER_FAIL_OPEN=1 to override)" >&2
          exit 90
        fi
      fi
    fi
  done
  # Best-effort readiness check; never fatal (setup is for host installs).
  nono setup --check-only >/dev/null 2>&1 || true
fi

exec "$@"
