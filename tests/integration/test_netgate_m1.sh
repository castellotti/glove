#!/usr/bin/env bash
# Network observability M1 — the netgate as a drop-in socat replacement, live.
# (docs/planning/network-observability.md §8 M1)
#
# Reproduces the glove-pi-search topology with stubs, entirely in throwaway
# state (never touches ~/.glove or the pi-search stack):
#   - `llm`  → a host-side stub OpenAI endpoint via host.docker.internal
#              (host_gateway, like pi-search's llm service);
#   - `docs` → a stub HTTP backend on an external bridge the forwarder joins
#              (join_network, like pi-search's search/proxy services).
# Then drives the REAL Pi harness (nono-wrapped, hardened container) and a raw
# byte-counting client through the gate, and checks:
#   acceptance  Pi reaches the LLM through the gate; flows.ndjson records the LLM
#               connection with byte counts equal to what the client sent/received
#   parity      the same requests through plain socat return identical bytes
#   invariants  no API on the internal net; no NET_ADMIN / harness namespaces /
#               harness home; net/ invisible to the harness; telemetry fails open
#   contract    rotation + a --follow tailer across it; SIGTERM → gate_shutdown
#
# Usage:  bash tests/integration/test_netgate_m1.sh
# Requires: docker (Docker Desktop or Linux), python3, uv, the `glove/pi` image
# (`glove build pi`). Podman: untested.
set -u

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
T="$(mktemp -d /tmp/ngm1.XXXXXX)"
export GLOVE_HOME="$T/ghome"
NET="glove-ngm1-egress-$$"
BACKEND="glove-ngm1-docs-$$"
PASS=0 FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }
glove() { uv run --project "$ROOT" glove "$@"; }

cleanup() {
  [ -n "${FOLLOW:-}" ] && kill "$FOLLOW" 2>/dev/null
  docker compose -p glove-wd -f "$GLOVE_HOME/envs/wd/sessions/wd/docker-compose.yml" down -v >/dev/null 2>&1
  docker compose -p glove-wd-socat -f "$GLOVE_HOME/envs/wd/sessions/socat/docker-compose.yml" down -v >/dev/null 2>&1
  docker rm -f "$BACKEND" >/dev/null 2>&1
  docker network rm "$NET" >/dev/null 2>&1
  [ -n "${STUB_PID:-}" ] && kill "$STUB_PID" 2>/dev/null
  chmod -R u+rwx "$T" 2>/dev/null; rm -rf "$T"
}
trap cleanup EXIT

# --- stubs -------------------------------------------------------------------
mkdir -p "$T/wd" "$T/work" "$T/docsroot"
LLM_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
cat > "$T/stub_llm.py" <<'EOF'
import json, sys, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass
    def _send(self, body, ctype="application/json"):
        self.send_response(200); self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        if self.path.startswith("/blob/"):
            return self._send(b"L" * int(self.path.rsplit("/", 1)[1]), "application/octet-stream")
        self._send(json.dumps({"data": [{"id": "stub", "object": "model"}]}).encode())
    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        words = ("netgate-ok " * 40).split()
        if req.get("stream"):
            self.send_response(200); self.send_header("Content-Type", "text/event-stream")
            self.send_header("Connection", "close"); self.end_headers()
            for i, w in enumerate(words):
                d = {"role": "assistant", "content": w + " "} if i == 0 else {"content": w + " "}
                c = {"id": "c", "object": "chat.completion.chunk", "created": 0, "model": "stub",
                     "choices": [{"index": 0, "delta": d, "finish_reason": None}]}
                self.wfile.write(f"data: {json.dumps(c)}\n\n".encode()); self.wfile.flush(); time.sleep(0.02)
            c = {"id": "c", "object": "chat.completion.chunk", "created": 0, "model": "stub",
                 "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                 "usage": {"prompt_tokens": 5, "completion_tokens": 40, "total_tokens": 45}}
            self.wfile.write(f"data: {json.dumps(c)}\n\ndata: [DONE]\n\n".encode()); self.wfile.flush()
            self.close_connection = True
            return
        self._send(json.dumps({"id": "c", "object": "chat.completion", "created": 0, "model": "stub",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": " ".join(words)},
                         "finish_reason": "stop"}]}).encode())
ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
EOF
python3 "$T/stub_llm.py" "$LLM_PORT" & STUB_PID=$!
head -c 300000 /dev/urandom > "$T/docsroot/blob.bin"
docker network create "$NET" >/dev/null
docker run -d --name "$BACKEND" --network "$NET" --network-alias docs-backend \
  -v "$T/docsroot:/srv:ro" -w /srv python:3.12-alpine python -m http.server 8000 >/dev/null

# Raw TCP client: exact bytes sent/received + body hash (runs in the harness).
cat > "$T/work/client.js" <<'EOF'
const net = require("net"), crypto = require("crypto");
const [host, port, path, hold] = process.argv.slice(2);
const req = `GET ${path} HTTP/1.0\r\nHost: ${host}\r\nX-Pad: ${"p".repeat(1000)}\r\n\r\n`;
const s = net.connect(+port, host); const chunks = [];
s.on("connect", () => { if (!hold) s.write(req); });
s.on("error", e => console.log(JSON.stringify({error: e.code})));
s.on("data", d => chunks.push(d));
s.on("end", () => { const a = Buffer.concat(chunks); const i = a.indexOf("\r\n\r\n") + 4;
  console.log(JSON.stringify({sent: Buffer.byteLength(req), received: a.length,
    sha: crypto.createHash("sha256").update(a.subarray(i)).digest("hex")})); });
EOF

cat > "$T/observe.yaml" <<EOF
harness: pi
model: stub
llm_api_key: "stub-not-a-secret"
net: [service]
observe: {enabled: true, rotate_mb: 0.004, keep: 3}
services:
  - { name: llm,  to: "host.docker.internal:$LLM_PORT", port: 8080, host_gateway: true }
  - { name: docs, to: "docs-backend:8000", port: 8080, join_network: $NET }
EOF
sed 's/^observe: .*/observe: {enabled: false}/' "$T/observe.yaml" > "$T/plain.yaml"

# --- render via the real CLI ---------------------------------------------------
echo "== render (glove init pi; glove pi --config … --dry-run) =="
glove build >/dev/null 2>&1 || { echo "glove build failed"; exit 1; }
( cd "$T/wd" && glove init pi >/dev/null \
  && glove run pi --config "$T/observe.yaml" --workdir "$T/work" --dry-run >/dev/null 2>&1 \
  && glove run pi --name socat --config "$T/plain.yaml" --workdir "$T/work" --dry-run >/dev/null 2>&1 )
S="$GLOVE_HOME/envs/wd/sessions/wd"; C="$S/docker-compose.yml"; N="$S/net"
C2="$GLOVE_HOME/envs/wd/sessions/socat/docker-compose.yml"
check "observed session renders gate forwarders + collector" \
  "grep -q 'glove-wd-netgate:' '$C' && [ \$(grep -c 'image: glove/netgate' '$C') -eq 3 ]"
check "unobserved session still renders plain socat, no net/" \
  "[ \$(grep -c 'image: glove/forwarder' '$C2') -eq 2 ] && [ ! -e '$GLOVE_HOME/envs/wd/sessions/socat/net' ]"
check "net/ is 0700 and session.json 0600" \
  "[ \"\$(stat -f %Lp '$N' 2>/dev/null || stat -c %a '$N')\" = 700 ] && [ \"\$(stat -f %Lp '$N/session.json' 2>/dev/null || stat -c %a '$N/session.json')\" = 600 ]"

docker compose -p glove-wd -f "$C" up -d glove-wd-netgate glove-wd-llm glove-wd-docs >/dev/null 2>&1
docker compose -p glove-wd-socat -f "$C2" up -d glove-wd-socat-llm glove-wd-socat-docs >/dev/null 2>&1
sleep 2

in_harness() {  # $1 project, $2 compose file, $3 service, rest: command (nono-wrapped)
  local p="$1" f="$2" s="$3"; shift 3
  # </dev/null: `pi -p` reads a piped stdin as extra prompt and would wait for EOF.
  docker compose -p "$p" -f "$f" run --rm -T "$s" \
    nono run -s --allow-cwd --profile /etc/glove/enforcer/harness.json -- "$@" </dev/null 2>/dev/null
}
field() { python3 -c "import sys,json; print(json.loads(sys.stdin.read().strip().splitlines()[-1])['$1'])"; }
last_close() {  # $1 service → "up down reason client" of its latest close record
  python3 - "$N" "$1" <<'EOF'
import sys, json, pathlib
recs = []
for p in sorted(pathlib.Path(sys.argv[1]).glob("flows-*.ndjson")) + [pathlib.Path(sys.argv[1]) / "flows.ndjson"]:
    if p.exists():
        recs += [json.loads(l) for l in p.read_text().splitlines() if l.strip()]
c = [r for r in recs if r["phase"] == "close" and r["service"] == sys.argv[2]][-1]
print(c["bytes"]["up"], c["bytes"]["down"], c["close_reason"], c["client"], c["dest"]["resolution"])
EOF
}

# --- acceptance: the real harness through the gate -----------------------------
echo "== acceptance: Pi (nono-wrapped) → gate → LLM =="
out="$(in_harness glove-wd "$C" glove-wd-harness pi -e /opt/glove/pi-extensions/enforcer -p 'Reply with one word.')"
check "Pi got the stub LLM's answer through the gate" "echo \"\$out\" | grep -q netgate-ok"
sleep 1
read -r up down reason client res <<<"$(last_close llm)"
echo "    llm flow: up=$up down=$down close=$reason client=$client resolution=$res"
check "flows.ndjson records the LLM connection (client=harness, eof, bytes>0)" \
  "[ '$client' = harness ] && [ '$reason' = eof ] && [ $up -gt 0 ] && [ $down -gt 0 ]"
check "no host lookup for a display IP (tcp mode: resolution=disabled, by design)" "[ '$res' = disabled ]"

echo "== byte counts: raw client vs flow record =="
r="$(in_harness glove-wd "$C" glove-wd-harness node /work/client.js glove-wd-llm 8080 /blob/5000000)"
sleep 1; read -r up down reason _ _ <<<"$(last_close llm)"
echo "    client sent=$(echo "$r" | field sent) received=$(echo "$r" | field received) | flow up=$up down=$down"
check "llm: flow up/down == client sent/received, exactly" \
  "[ $up -eq $(echo "$r" | field sent) ] && [ $down -eq $(echo "$r" | field received) ]"
r="$(in_harness glove-wd "$C" glove-wd-harness node /work/client.js glove-wd-docs 8080 /blob.bin)"
sleep 1; read -r up down reason _ _ <<<"$(last_close docs)"
check "docs: flow counts exact and body sha256 matches the source" \
  "[ $up -eq $(echo "$r" | field sent) ] && [ $down -eq $(echo "$r" | field received) ] && [ $(echo "$r" | field sha) = $(shasum -a 256 "$T/docsroot/blob.bin" | cut -c1-64) ]"
GATE_SHA="$(echo "$r" | field sha)"; GATE_RX="$(echo "$r" | field received)"

echo "== parity with socat =="
r2="$(in_harness glove-wd-socat "$C2" glove-wd-socat-harness node /work/client.js glove-wd-socat-docs 8080 /blob.bin)"
check "socat and netgate deliver identical bytes" \
  "[ $(echo "$r2" | field sha) = $GATE_SHA ] && [ $(echo "$r2" | field received) -eq $GATE_RX ]"
out2="$(in_harness glove-wd-socat "$C2" glove-wd-socat-harness pi -e /opt/glove/pi-extensions/enforcer -p 'Reply with one word.')"
check "Pi works identically through socat" "echo \"\$out2\" | grep -q netgate-ok"

# --- invariants, from the live containers ----------------------------------------
echo "== invariants (docker inspect / /proc of the running gates) =="
for c in glove-wd-netgate glove-wd-llm glove-wd-docs; do
  insp="$(docker inspect "$c" --format '{{.HostConfig.CapAdd}}|{{.HostConfig.CapDrop}}|{{.HostConfig.Privileged}}|{{.HostConfig.ReadonlyRootfs}}|{{.HostConfig.PidMode}}|{{.HostConfig.NetworkMode}}|{{range .Mounts}}{{.Destination}},{{end}}')"
  echo "    $c: $insp"
  check "$c: no caps added, ALL dropped, unprivileged, ro rootfs, own PID ns" \
    "echo '$insp' | grep -qE '^\[\]\|\[ALL\]\|false\|true\|\|'"
  check "$c: never on the harness's netns, never mounts /home/agent" \
    "! echo '$insp' | grep -qE 'service:|container:|/home/agent'"
done
mounts="$(docker inspect glove-wd-netgate --format '{{.HostConfig.NetworkMode}}{{range .Mounts}} {{.Destination}}={{.RW}}{{end}}' | tr ' ' '\n' | sort | tr '\n' ' ')"
echo "    collector: $mounts"
check "collector: network_mode none; mounts exactly net/ (rw), event socket (rw), rules dir (READ-ONLY)" \
  "[ \"$mounts\" = '/etc/glove/netgate-control=false /run/glove-netgate=true /var/lib/glove/net=true none ' ]"
listens() { docker exec "$1" python -c "
rows=[l.split() for f in ('/proc/net/tcp','/proc/net/tcp6') for l in open(f).read().splitlines()[1:]]
# 0100007F / 0B00007F = 127.0.0.x: Docker's embedded-DNS stub (every container), not ours
print(sorted({int(r[1].split(':')[1],16) for r in rows if r[3]=='0A' and not r[1].startswith(('0100007F','0B00007F'))}))"; }
check "llm forwarder listens on exactly its forward port [8080]" "[ \"\$(listens glove-wd-llm)\" = '[8080]' ]"
check "docs forwarder listens on exactly its forward port [8080]" "[ \"\$(listens glove-wd-docs)\" = '[8080]' ]"
check "collector listens on nothing and has no eth interface" \
  "[ \"\$(listens glove-wd-netgate)\" = '[]' ] && ! docker exec glove-wd-netgate grep -q eth /proc/net/dev"
vis="$(docker compose -p glove-wd -f "$C" run --rm -T glove-wd-harness sh -c 'ls /var/lib/glove /run/glove-netgate 2>&1; grep -c netgate /proc/self/mountinfo' </dev/null 2>/dev/null)"
check "harness cannot see net/ or the event socket volume" \
  "echo \"\$vis\" | grep -q 'No such file' && [ \"\$(echo \"\$vis\" | tail -1)\" = 0 ]"

echo "== telemetry fails open =="
before="$(cat "$N"/flows*.ndjson | wc -l)"
docker stop glove-wd-netgate >/dev/null
r="$(in_harness glove-wd "$C" glove-wd-harness node /work/client.js glove-wd-llm 8080 /blob/200000)"
check "collector stopped: traffic still flows (200156 bytes)" "[ $(echo "$r" | field received) -eq 200156 ]"
check "collector stopped: records dropped, not queued" "[ \$(cat '$N'/flows*.ndjson | wc -l) -eq $before ]"
docker start glove-wd-netgate >/dev/null; sleep 1
mkdir -p "$T/aside"; mv "$N"/flows*.ndjson "$T/aside/"; chmod 500 "$N"
docker restart glove-wd-netgate >/dev/null; sleep 1
r="$(in_harness glove-wd "$C" glove-wd-harness node /work/client.js glove-wd-llm 8080 /blob/300000)"
check "net/ unwritable: traffic still flows (300156 bytes)" "[ $(echo "$r" | field received) -eq 300156 ]"
check "net/ unwritable: the collector logs that it is dropping" \
  "docker logs glove-wd-netgate 2>&1 | grep -q 'DROPPING records'"
chmod 700 "$N"; sleep 1
in_harness glove-wd "$C" glove-wd-harness node /work/client.js glove-wd-llm 8080 /blob/10 >/dev/null
check "writes recover once net/ is writable again" "docker logs glove-wd-netgate 2>&1 | grep -q 'flow writes recovered'"

echo "== rotation + a --follow tailer across it =="
# exec: $! must be the tailer itself, not a subshell (killing a subshell orphans it)
( cd "$T/wd" && exec "$ROOT/.venv/bin/glove" net flows --tail 0 --follow --json > "$T/follow.out" 2>&1 ) &
FOLLOW=$!
sleep 3
for _ in 1 2 3 4 5 6; do in_harness glove-wd "$C" glove-wd-harness node /work/client.js glove-wd-docs 8080 /blob.bin >/dev/null; done
sleep 3; kill "$FOLLOW" 2>/dev/null; wait "$FOLLOW" 2>/dev/null
ls -l "$N" | awk 'NR>1 {print "    " $1, $5, $NF}'
check "flows rotated to flows-<ts>.ndjson (mode 0600) and a live flows.ndjson exists" \
  "ls '$N' | grep -qE '^flows-[0-9]{8}T[0-9]{9}Z.ndjson$' && [ -f '$N/flows.ndjson' ]"
check "follow saw all 6 flows (open+close each) across rotations" \
  "[ \$(grep -c '\"phase\":\"close\"' '$T/follow.out') -eq 6 ] && [ \$(grep -c '\"phase\":\"open\"' '$T/follow.out') -eq 6 ]"

echo "== SIGTERM: live flows close with gate_shutdown =="
( in_harness glove-wd "$C" glove-wd-harness node /work/client.js glove-wd-llm 8080 / hold >/dev/null & )
sleep 4
t0=$(date +%s); docker stop -t 10 glove-wd-llm >/dev/null; t1=$(date +%s)
sleep 1
read -r _ _ reason _ _ <<<"$(last_close llm)"
check "forwarder stops promptly on SIGTERM ($((t1-t0))s < 5s)" "[ $((t1-t0)) -lt 5 ]"
check "the open flow was closed with close_reason=gate_shutdown" "[ '$reason' = gate_shutdown ]"

echo "== glove net status =="
( cd "$T/wd" && glove net status )
echo "== glove net flows --tail 4 =="
( cd "$T/wd" && glove net flows --tail 4 )

echo
echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
