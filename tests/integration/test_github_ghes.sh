#!/usr/bin/env bash
# Live: `github` with GitHub Enterprise hosts only — two stand-in hosts
# (ghes.test, ghes2.test: stubs/ghes_stub.py, HTTPS from a throwaway CA given
# as the session's corporate_ca), a token each, behind the `corporate` egress
# that admits just them; git limited to fetch, clone and ls-remote.
#
#   bash tests/integration/test_github_ghes.sh [harness] [enforcer]   (default: pi, the runtime's default)
#   RT=podman bash tests/integration/test_github_ghes.sh pi nono
#
# The stub runs in the relay image on a network of its own, started once the
# session is up; the corporate proxy joins that network (its DNS then finds the
# stub's names).
# Fake tokens (env: references), throwaway everything. See github_ghes_live.py
# for the checks.
set -u
H="${1:-pi}"
RT="${RT:-docker}"
ENF="${2:-$([ "$RT" = podman ] && echo nono || echo nono+srt)}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT/tests/integration/lib_session.sh"
driver_init github-ghes
export GHES_TOKEN_A=ghes-tok-a-1 GHES_TOKEN_B=ghes-tok-b-2
# the stand-in's own network: a private range the corporate egress must allow
# by CIDR too (a name alone never passes its guard to a private address)
export GHES_FIXTURE="$TMPROOT/fixture" GHES_SUBNET="${GHES_SUBNET:-10.213.77.0/24}"
FX="$GHES_FIXTURE"
mkdir -p "$FX"

# a throwaway CA, and the stub's certificate for both names (and their subdomains)
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=glove test GHES CA" \
  -keyout "$FX/ca.key" -out "$FX/ca.pem" 2>/dev/null || exit 1
openssl req -newkey rsa:2048 -nodes -subj "/CN=ghes.test" -keyout "$FX/stub.key" -out "$FX/stub.csr" 2>/dev/null
printf 'subjectAltName=DNS:ghes.test,DNS:*.ghes.test,DNS:ghes2.test,DNS:*.ghes2.test\n' > "$FX/san.ext"
openssl x509 -req -in "$FX/stub.csr" -CA "$FX/ca.pem" -CAkey "$FX/ca.key" -CAcreateserial -days 1 \
  -extfile "$FX/san.ext" -out "$FX/stub.pem" 2>/dev/null || exit 1
# the repository both hosts serve
git init -q --bare -b main "$FX/repo.git"
git init -q -b main "$FX/src" && echo "hello from ghes" > "$FX/src/README"
git -C "$FX/src" add README && git -C "$FX/src" -c user.name=t -c user.email=t@t commit -qm init
git -C "$FX/src" push -q "$FX/repo.git" main || exit 1

stub_session "$S" "$H" "$ENF" "$(cat <<YML
  corporate:
    allow_domains: [ghes.test, "*.ghes.test", ghes2.test, "*.ghes2.test"]
    allow_cidrs: ["$GHES_SUBNET"]
  github:
    hosts:
      - {host: ghes.test, token: "env:GHES_TOKEN_A"}
      - {host: ghes2.test, token: "env:GHES_TOKEN_B"}
    allow: [api, repo view]
    git: [fetch, clone, ls-remote]
YML
)
" || exit 1
mkdir -p "$S/local" && cp "$FX/ca.pem" "$S/local/ca.pem"
printf 'corporate_ca: local/ca.pem\n' >> "$S/glove-session.yml"

( cd "$S" && uv run --quiet --project "$ROOT" python "$ROOT/tests/integration/github_ghes_live.py" . )
exit $?
