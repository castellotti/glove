#!/usr/bin/env bash
# Followup item 6, live: does a clean `glove down` record the close of every
# open flow, and can a reader tell flows cut by a crashed gate?
#
# A compose project with glove's gate stanzas (hardening, depends_on, volumes,
# tmpfs events volume, as compose.yml.j2 renders them) plus a stub origin and a
# client that holds one flow open. Then:
#   A  `compose -p <project> down` WITHOUT -f — exactly glove's teardown —
#      must leave: flow close (gate_shutdown), forward stop, collect stop,
#      status.json state "stopped";
#   B  SIGKILL the forwarder (`docker kill`): no close is written, and Docker
#      does NOT restart it (a kill counts as a manual stop for unless-stopped).
#      The collector notices the silence (no heartbeat for 30 s) and writes an
#      inferred `gate stop`, so `glove net status`'s reader counts the flow as
#      cut (inferred), not active — and still does once the forwarder is back.
#
# Usage:  bash tests/integration/test_netgate_shutdown.sh      (docker; podman untested)
set -u

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RT="${RT:-docker}"
IMG="$(cd "$ROOT" && uv run python -c 'from glove.observe import build_netgate; print(build_netgate("'"$RT"'"))' | tail -1)"
T="$(mktemp -d /tmp/ngsd.XXXXXX)"
P="ngsd$$"
PASS=0 FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }
cleanup() { "$RT" compose -p "$P" -f "$T/compose.yml" down -v >/dev/null 2>&1; rm -rf "$T"; }
trap cleanup EXIT

mkdir -p "$T/net" "$T/control"
chmod 700 "$T/net" "$T/control"
echo '{"v":1,"type":"session","env":"sd","session":"sd"}' > "$T/net/session.json"
U="$(id -u)" G="$(id -g)"
cat > "$T/compose.yml" <<EOF
name: $P
x-gate: &gate
  image: $IMG
  user: "$U:$G"
  cap_drop: [ALL]
  security_opt: ["no-new-privileges:true"]
  read_only: true
  pids_limit: 64
  mem_limit: 256m
  restart: unless-stopped
services:
  origin:
    image: $IMG
    entrypoint: ["python", "-c"]
    command:
      - |
        import asyncio
        async def h(r, w):
            while True:
                w.write(b"x" * 512); await w.drain(); await asyncio.sleep(0.5)
        async def main():
            await (await asyncio.start_server(h, "0.0.0.0", 9000)).serve_forever()
        asyncio.run(main())
    networks: [n]
  fwd:
    <<: *gate
    command: ["forward", "--service", "llm", "--mode", "tcp", "--listen", "8080", "--upstream", "tcp:origin:9000",
              "--route", "tcp", "--env", "sd", "--session", "sd", "--events", "/run/glove-netgate/events.sock",
              "--rules", "/etc/glove/netgate-control/rules.json", "--scope", "local", "--tool", "llm"]
    volumes:
      - {type: volume, source: events, target: /run/glove-netgate}
      - {type: bind, source: "$T/control", target: /etc/glove/netgate-control, read_only: true}
    depends_on: [col]
    networks: [n]
  col:
    <<: *gate
    command: ["collect", "--net-dir", "/var/lib/glove/net", "--events", "/run/glove-netgate/events.sock",
              "--rules", "/etc/glove/netgate-control/rules.json"]
    network_mode: none
    volumes:
      - {type: bind, source: "$T/net", target: /var/lib/glove/net}
      - {type: volume, source: events, target: /run/glove-netgate}
      - {type: bind, source: "$T/control", target: /etc/glove/netgate-control, read_only: true}
  client:
    image: $IMG
    entrypoint: ["python", "-c"]
    command:
      - |
        import socket, time
        while True:
            try:
                s = socket.create_connection(("fwd", 8080)); s.sendall(b"hi")
                while s.recv(65536): pass
            except OSError: pass
            time.sleep(1)
    networks: [n]
networks:
  n: {}
volumes:
  events:
    driver: local
    driver_opts: {type: tmpfs, device: tmpfs, o: "size=1m,mode=0700,uid=$U,gid=$G"}
EOF

recs() { cat "$T"/net/flows*.ndjson 2>/dev/null; }
summ() { uv run --project "$ROOT" python -c "
import json; from glove.netview import summarize
f = summarize('$T/net')['flows']; print(f['active'], f['cut_inferred'])"; }
wait_update() {
  for _ in $(seq 40); do recs | grep -q '"phase":"update"' && return 0; sleep 0.5; done; return 1
}

echo "== A: clean teardown the way glove does it (compose -p <project> down, no -f)"
"$RT" compose -p "$P" -f "$T/compose.yml" up -d --quiet-pull >/dev/null 2>&1
check "a flow is open and updating" wait_update
"$RT" compose -p "$P" down 2>&1 | sed 's/^/    /'
python3 - "$T/net/flows.ndjson" <<'EOF' > "$T/a.txt"
import json, sys
recs = [json.loads(x) for x in open(sys.argv[1])]
print(" ".join(f"{r['type']}:{r.get('phase') or r.get('event')}:{r.get('role') or r.get('close_reason') or ''}" for r in recs[-4:]))
opened = {r["id"] for r in recs if r["type"] == "flow"}
closed = {r["id"] for r in recs if r["type"] == "flow" and r["phase"] == "close"}
print("unclosed", len(opened - closed))
EOF
cat "$T/a.txt" | sed 's/^/    /'
check "every flow has a close after a clean teardown" 'grep -q "^unclosed 0$" "$T/a.txt"'
check "close(gate_shutdown), forward stop, collect stop are the last records" \
  'grep -q "flow:close:gate_shutdown gate:stop:forward gate:stop:collect" "$T/a.txt"'
check "status.json state is stopped" 'grep -q "\"state\": \"stopped\"" "$T/net/status.json"'

echo "== B: the forwarder is SIGKILLed mid-flow (a crash)"
rm -f "$T"/net/flows*.ndjson "$T/net/status.json"
"$RT" compose -p "$P" -f "$T/compose.yml" up -d >/dev/null 2>&1
check "a flow is open and updating" wait_update
FWD="$("$RT" compose -p "$P" -f "$T/compose.yml" ps -q fwd)"
RUN1="$(recs | grep '"type":"flow"' | head -1 | python3 -c 'import json,sys; print(json.loads(sys.stdin.readline())["run"])')"
"$RT" kill "$FWD" >/dev/null
sleep 4
echo "    forwarder after SIGKILL: $("$RT" inspect -f '{{.State.Status}} restarts={{.RestartCount}}' "$FWD")"
check "no close was written for the killed run's open flow" \
  '! recs | grep "\"run\":\"$RUN1\"" | grep -q "\"phase\":\"close\""'
for _ in $(seq 60); do recs | grep '"inferred":true' | grep -q "$RUN1" && break; sleep 1; done
recs | grep '"inferred":true' | sed 's/^/    /'
check "the collector wrote an inferred stop for the silent run" 'recs | grep "\"inferred\":true" | grep -q "$RUN1"'
echo "    netview after the inferred stop: active cut_inferred = $(summ)"
check "the killed run's flow is cut (inferred), not active" '[ "$(summ)" = "0 1" ]'
"$RT" compose -p "$P" -f "$T/compose.yml" up -d fwd >/dev/null 2>&1
for _ in $(seq 20); do recs | grep '"event":"start"' | grep -v "$RUN1" | grep -q '"role":"forward"' && break; sleep 0.5; done
wait_update
echo "    after the forwarder is back: active cut_inferred = $(summ)"
check "the old flow stays cut once a new run is live" '[ "$(summ | cut -d" " -f2)" -ge 1 ]'

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
