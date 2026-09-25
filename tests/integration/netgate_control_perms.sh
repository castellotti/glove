#!/usr/bin/env bash
# Who can read and write net/ and control/<env>/<name>/rules.json, live?
# (docs/planning/network-observability-layman-followup.md item 2)
#
# Runs as the NON-ROOT host user that would run `glove`, against one container
# runtime, and reports what actually happens when:
#   - the collector (glove's gate flags: --user <host uid:gid>, cap_drop ALL,
#     no-new-privileges, read-only rootfs, network none; + userns keep-id under
#     rootless podman) writes net/ and reads control/…/rules.json;
#   - the host CLI (glove.netrules, glove's real code) writes rules.json;
#   - "Layman" (a container running as root, like Layman's, with control/
#     bind-mounted rw) writes rules.json by atomic rename, in several ways;
#   - "Layman" creates a missing control/<env>/<name>/ itself.
# Each line is `RESULT <id> <value>`; the contract checks at the end PASS/FAIL.
#
# Usage:  RT=docker|podman GATE_IMAGE=glove/netgate:<tag> bash tests/integration/netgate_control_perms.sh
#         RT may be a wrapper (e.g. a script running `sudo podman "$@"` for rootful podman).
#         On an SELinux-enforcing host, binds get `:z`, as glove renders them on podman.
# Requires: python3, the runtime, GATE_IMAGE present locally. Throwaway state only.
# On Linux, run it on the host itself (rootful docker; rootless podman as the user).
set -u

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RT="${RT:-docker}"
IMG="${GATE_IMAGE:?set GATE_IMAGE}"
U="$(id -u)" G="$(id -g)"
[ "$U" = 0 ] && { echo "run as the non-root host user, not root"; exit 2; }
T="$(mktemp -d "${TMPDIR:-/tmp}/ngperm.XXXXXX")"
H="$T/glove"                          # stands in for ~/.glove
E=pe                                  # env id == default session name == token
NET="$H/envs/$E/sessions/$E/net"
CTL="$H/control/$E/$E"
TAG="ngperm$$"
PASS=0 FAIL=0
res()   { echo "RESULT $1 $2"; }
ok()    { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad()   { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }
hostpy() { PYTHONPATH="$ROOT" python3 -c "$@"; }
owner() { stat -c '%u:%g %a' "$1" 2>/dev/null || stat -f '%u:%g %Lp' "$1"; }

USERNS=()
EU="$U" EG="$G"                      # the events tmpfs owner, as the mount option sees ids
if "$RT" --version 2>/dev/null | grep -qi podman \
   && [ "$("$RT" info --format '{{.Host.Security.Rootless}}')" = true ]; then
  USERNS=(--userns keep-id)          # what glove renders for rootless podman
  EU=0 EG=0                          # ...and namespace root is the host user
fi
Z=""
[ "$(getenforce 2>/dev/null)" = Enforcing ] && Z=":z"   # glove renders `selinux: z` on podman
GATE=("$RT" run --user "$U:$G" ${USERNS[@]+"${USERNS[@]}"} --cap-drop ALL --security-opt no-new-privileges
      --read-only --pids-limit 64 --memory 256m)
# "Layman": root in its container, control/ rw, the rest of ~/.glove ro.
LAYMAN=("$RT" run --rm --user 0 -v "$H:/root/.glove:ro${Z:+,z}" -v "$H/control:/root/.glove/control$Z"
        --entrypoint sh "$IMG" -c)

cleanup() {
  "$RT" rm -f "$TAG-col" >/dev/null 2>&1
  "$RT" volume rm -f "$TAG-events" >/dev/null 2>&1
  "${LAYMAN[@]}" "rm -rf /root/.glove/control/$E" >/dev/null 2>&1
  chmod -R u+rwx "$T" 2>/dev/null; rm -rf "$T"
}
trap cleanup EXIT

echo "== platform: $RT on $(uname -s) $(uname -r); host user $U:$G; gate image $IMG"
res platform "$RT/$(uname -s)/uid=$U/userns=${USERNS[*]+${USERNS[*]}}/selinux=${Z:-off}"

# --- glove's render-time layout, by glove's own code paths -----------------------
hostpy "
import os, sys
from pathlib import Path
from glove.netgate.writer import write_json_atomic
for p in ('$NET', '$CTL'):   # observe.ensure_net_dir
    Path(p).mkdir(mode=0o700, parents=True, exist_ok=True); os.chmod(p, 0o700)
write_json_atomic('$NET/session.json', {'v': 1, 'type': 'session', 'env': '$E', 'session': '$E'})
"
cli() {  # the glove CLI's load → edit → save cycle (glove net block), by its real code
  hostpy "
import sys
from pathlib import Path
from glove.netrules import block_rule, load, save
from glove.netgate.policy import PolicyError
p = Path('$1/rules.json')
try:
    d = load(p, '$E', '${2:-$E}'); d['rules'].append(block_rule('$3', port=None, terminate=False, note=None))
    save(p, d, '$E', '${2:-$E}')
except (PolicyError, OSError) as e:
    print(f'ERR {e}'); sys.exit(1)
print('OK')
"
}
sha() { hostpy "import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" "$1" 2>/dev/null \
        || echo unreadable; }
status_rules() { hostpy "import json; r=json.load(open('$NET/status.json'))['rules']; print(r['ok'], r.get('sha256'), r['error'])" 2>&1; }
res layout "net=$(owner "$NET") control-leaf=$(owner "$CTL") control-env=$(owner "$H/control/$E")"

# --- 1. host CLI writes; the gate reads it and writes net/ ---------------------------
res cli-write "$(cli "$CTL" "$E" a.example)"
H0="$(sha "$CTL/rules.json")"
res cli-file "$(owner "$CTL/rules.json")"

"$RT" volume create --driver local --opt type=tmpfs --opt device=tmpfs \
  --opt o="size=1m,mode=0700,uid=$EU,gid=$EG${Z:+,context=\"system_u:object_r:container_file_t:s0\"}" \
  "$TAG-events" >/dev/null
"${GATE[@]}" -d --name "$TAG-col" --network none \
  -v "$NET:/var/lib/glove/net$Z" -v "$TAG-events:/run/glove-netgate" \
  -v "$CTL:/etc/glove/netgate-control:ro${Z:+,z}" \
  "$IMG" collect --net-dir /var/lib/glove/net --events /run/glove-netgate/events.sock \
  --rules /etc/glove/netgate-control/rules.json >/dev/null
for _ in $(seq 20); do [ -s "$NET/status.json" ] && break; sleep 0.5; done
res gate-in-container-id "$("$RT" exec "$TAG-col" id 2>&1 | tr ' ' ,)"
res gate-sees-control "$("$RT" exec "$TAG-col" sh -c 'stat -c "%u:%g %a" /etc/glove/netgate-control /etc/glove/netgate-control/rules.json' 2>&1 | tr '\n' ' ')"
res net-written-by-gate "$( [ -s "$NET/status.json" ] && owner "$NET/status.json" || echo NO)"
res gate-reads-cli-file "$(status_rules)"
check "collector writes net/ as the host user" '[ -s "$NET/status.json" ]'
check "gate enforces the host CLI's file" '[ "$(status_rules)" = "True $H0 None" ]'

"$RT" exec "$TAG-col" python -c "
import socket, json
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.sendto(json.dumps({'v':1,'type':'flow','phase':'open','id':'f_x','service':'p'}).encode(), '/run/glove-netgate/events.sock')"
sleep 1
res flows-written "$( [ -s "$NET/flows.ndjson" ] && owner "$NET/flows.ndjson" || echo NO)"
res layman-reads-net "$("${LAYMAN[@]}" "cat /root/.glove/envs/$E/sessions/$E/net/flows.ndjson >/dev/null && cat /root/.glove/control/$E/$E/rules.json >/dev/null && echo yes" 2>&1)"
check "a root Layman can read net/ and the CLI's rules.json" \
  '[ "$("${LAYMAN[@]}" "cat /root/.glove/envs/$E/sessions/$E/net/status.json >/dev/null && echo y" 2>/dev/null)" = y ]'

# --- 2. "Layman" (container root) writes rules.json, several ways ----------------------
layman_write() {  # $1 label, $2 shell prefix run before the write (umask/chown policy)
  local host="$3"
  "${LAYMAN[@]}" "
    set -e; d=/root/.glove/control/$E/$E; $2
    printf '%s\n' '{\"v\":1,\"env\":\"$E\",\"session\":\"$E\",\"updated_by\":\"layman\",\"rules\":[{\"id\":\"r_layman$1\",\"action\":\"block\",\"match\":{\"host\":\"$host\"}}]}' > \$d/rules.json.tmp
    \${CHOWN:-true} \$d/rules.json.tmp
    mv \$d/rules.json.tmp \$d/rules.json" 2>&1
}
wait_poll() { sleep 6; }  # the collector re-reads rules.json every status_interval (5 s)
for mode in 0600 0644 chown; do
  case $mode in
    0600)  pre='umask 077' ;;
    0644)  pre='umask 022' ;;
    chown) pre='umask 077; CHOWN="chown $(stat -c %u:%g $d)"' ;;
  esac
  out="$(layman_write "$mode" "$pre" "l$mode.example")"
  [ -n "$out" ] && res "layman-$mode-write-error" "$(echo "$out" | tr '\n' ' ')"
  H1="$(sha "$CTL/rules.json")"
  res "layman-$mode-file" "$(owner "$CTL/rules.json") host-sha=$H1"
  wait_poll
  res "layman-$mode-gate" "$(status_rules) layman-sha=$H1"
  ok_write=no
  [ -z "$out" ] && case "$(status_rules)" in "True $H1 None") ok_write=yes ;; esac
  c="$(cli "$CTL" "$E" "cli-after-$mode.example")"
  res "layman-$mode-cli-edit" "$(echo "$c" | tr '\n' ' ')"
  eval "CLI_$mode=\$c WROTE_$mode=\$ok_write"
  rm -f "$CTL/rules.json"   # the host user owns the dir, so it can always remove the file
done
check "contract (Layman chowns to the dir's owner, 0600): the gate enforces Layman's write, the CLI can edit it" \
  '[ "$WROTE_chown" = yes ] && [ "$CLI_chown" = OK ]'
res "without-chown" "0600: gate-enforced=$WROTE_0600 cli=$CLI_0600 | 0644: gate-enforced=$WROTE_0644 cli=$CLI_0644"

# --- 3. "Layman" creates a missing control/<env>/<name>/ ------------------------------
"${LAYMAN[@]}" "mkdir -p /root/.glove/control/$E/other" 2>&1
res layman-mkdir "$(owner "$H/control/$E/other")"
res glove-render-after-layman-mkdir "$(hostpy "
import os
from pathlib import Path
p = Path('$H/control/$E/other')
try:
    p.mkdir(mode=0o700, parents=True, exist_ok=True); os.chmod(p, 0o700); print('OK')
except OSError as e:
    print(f'ERR {e}')")"
res cli-into-layman-dir "$(cli "$H/control/$E/other" "$E-other" y.example | tr '\n' ' ')"

# --- 4. an unreadable rules.json fails closed, live (item 1) ----------------------------
cli "$CTL" "$E" live.example >/dev/null
wait_poll
BEFORE="$(status_rules)"
chmod 000 "$CTL/rules.json"
wait_poll
AFTER="$(status_rules)"
chmod 600 "$CTL/rules.json"
res unreadable-before "$BEFORE"
res unreadable-after "$AFTER"
check "an unreadable rules.json is reported ok:false, not treated as absent" \
  'case "$AFTER" in "False "*"cannot read rules.json: permission denied") true ;; *) false ;; esac'
res gate-stderr "$("$RT" logs "$TAG-col" 2>&1 | tail -3 | tr '\n' ' ')"

echo
echo "$PASS passed, $FAIL failed ($RT)"
[ "$FAIL" = 0 ]
