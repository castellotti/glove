#!/usr/bin/env bash
# Network observability M2 — http-proxy mode, chain: upstream, SSRF guard, live.
# (docs/planning/network-observability.md §8 M2)
#
# Reproduces glove-pi-search's web_fetch path with stubs, in throwaway state
# (never touches ~/.glove or the pi-search stack):
#
#   harness ──CONNECT──▶ glove-wd-proxy (netgate, http-proxy mode, route: vpn)
#                           │  net: $EGRESS  (stand-in for pi-search-egress)
#                           ▼  chain:http://egress-proxy:8888, BY HOSTNAME
#                        stub upstream proxy [alias egress-proxy]  (gluetun's role;
#                           │  resolves names via Docker DNS, logs every request line)
#                           ▼  net: $ORIGIN  (the gate is NOT on this network)
#                        www.origin.test  (nginx: http :80 + https :443, self-signed)
#
# A raw node client in the real harness container speaks CONNECT exactly as
# undici's ProxyAgent (pi-search's web_fetch) does, then TLS inside the tunnel.
# A test-only sniffer (NET_RAW, sharing the gate's netns — never part of glove)
# records every DNS query name the gate emits, to show the destination is never
# resolved by the gate (invariant 4), measured rather than asserted.
#
# Usage:  bash tests/integration/test_netgate_m2.sh
# Requires: docker, python3, uv, openssl, the `glove/pi` image, nginx:alpine and
# python:3.12-alpine. Podman: untested.
set -u

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
T="$(mktemp -d /tmp/ngm2.XXXXXX)"
export GLOVE_HOME="$T/ghome"
EGRESS="glove-ngm2-egress-$$"
ORIGIN_NET="glove-ngm2-origin-$$"
UP="glove-ngm2-upstream-$$"
ORIGIN="glove-ngm2-origin-$$"
SNIFF="glove-ngm2-sniff-$$"
PASS=0 FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }
glove() { uv run --project "$ROOT" glove "$@"; }

cleanup() {
  docker compose -p glove-wd -f "$GLOVE_HOME/envs/wd/sessions/wd/docker-compose.yml" down -v >/dev/null 2>&1
  docker rm -f "$UP" "$ORIGIN" "$SNIFF" >/dev/null 2>&1
  docker network rm "$EGRESS" "$ORIGIN_NET" >/dev/null 2>&1
  chmod -R u+rwx "$T" 2>/dev/null; rm -rf "$T"
}
trap cleanup EXIT

# --- stubs -------------------------------------------------------------------
mkdir -p "$T/wd" "$T/work" "$T/srv" "$T/certs"
head -c 300000 /dev/urandom > "$T/srv/blob.bin"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=www.origin.test \
  -keyout "$T/certs/key.pem" -out "$T/certs/cert.pem" >/dev/null 2>&1
cat > "$T/nginx.conf" <<'EOF'
events {}
http { server { listen 80; listen 443 ssl;
  ssl_certificate /certs/cert.pem; ssl_certificate_key /certs/key.pem; root /srv; } }
EOF
cat > "$T/upstream.py" <<'EOF'
# Stub upstream HTTP proxy (gluetun's role): resolves via Docker DNS, logs requests.
import asyncio, sys
async def handle(r, w):
    try:
        head = await r.readuntil(b"\r\n\r\n")
    except Exception:
        w.close(); return
    line = head.split(b"\r\n", 1)[0].decode()
    print("REQ", line, flush=True)
    method, target, _ = line.split(" ")
    try:
        if method == "CONNECT":
            host, port = target.rsplit(":", 1)
            o_r, o_w = await asyncio.open_connection(host, int(port))
            w.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        else:
            rest = target.split("://", 1)[1]
            auth, _, path = rest.partition("/")
            host, _, port = auth.rpartition(":")
            o_r, o_w = await asyncio.open_connection(host, int(port or 80))
            o_w.write(head.replace(target.encode(), b"/" + path.encode(), 1))
    except OSError as e:
        print("ERR", line, e, flush=True)
        w.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"); await w.drain(); w.close(); return
    async def pipe(a, b):
        try:
            while d := await a.read(65536):
                b.write(d); await b.drain()
        finally:
            if b.can_write_eof(): b.write_eof()
    await asyncio.gather(pipe(r, o_w), pipe(o_r, w), return_exceptions=True)
    w.close(); o_w.close()
async def main():
    s = await asyncio.start_server(handle, "0.0.0.0", 8888)
    async with s: await s.serve_forever()
asyncio.run(main())
EOF
cat > "$T/sniff.py" <<'EOF'
# Test-only: every DNS query name leaving this netns (incl. Docker's 127.0.0.11).
import json, socket, sys, time
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
s.settimeout(0.5)
names, end = [], time.time() + float(sys.argv[1])
def qname(b, i):
    out = []
    while i < len(b) and b[i]:
        n = b[i]; out.append(b[i + 1:i + 1 + n].decode(errors="replace")); i += 1 + n
    return ".".join(out)
while time.time() < end:
    try:
        pkt, addr = s.recvfrom(65535)
    except socket.timeout:
        continue
    if addr[2] != socket.PACKET_OUTGOING or pkt[12:14] != b"\x08\x00":
        continue
    ip = pkt[14:]
    if ip[9] != 17:
        continue
    udp = ip[(ip[0] & 15) * 4:]
    dns = udp[8:]
    dst = socket.inet_ntoa(ip[16:20])
    if (dst == "127.0.0.11" or int.from_bytes(udp[2:4], "big") == 53) and len(dns) > 12 and not dns[2] & 0x80:
        names.append(qname(dns, 12))
print(json.dumps(sorted(set(names))), flush=True)
EOF
cat > "$T/work/pclient.js" <<'EOF'
// Raw proxy client (runs in the harness). Modes:
//   tunnel <proxy> <port> <host:port> <path>  CONNECT then TLS GET (as undici ProxyAgent)
//   absolute <proxy> <port> <url>             absolute-form GET
//   probe <proxy> <port> <host:port>          CONNECT only; print the status line
const net = require("net"), tls = require("tls"), crypto = require("crypto");
const [mode, ph, pp, target, path] = process.argv.slice(2);
const s = net.connect(+pp, ph);
const done = (o) => { console.log(JSON.stringify({...o, raw_sent: s.bytesWritten, raw_received: s.bytesRead})); };
function body(buf) { const i = buf.indexOf("\r\n\r\n") + 4;
  return {status: buf.subarray(0, buf.indexOf("\r\n")).toString(), body_len: buf.length - i,
          body_sha: crypto.createHash("sha256").update(buf.subarray(i)).digest("hex")}; }
if (mode === "absolute") {
  s.on("connect", () => s.write(`GET ${target} HTTP/1.1\r\nHost: ${new URL(target).host}\r\nConnection: keep-alive\r\n\r\n`));
  const c = []; s.on("data", d => c.push(d)); s.on("end", () => done(body(Buffer.concat(c))));
} else {
  let head = Buffer.alloc(0), tunneled = false;
  s.on("connect", () => s.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`));
  s.on("data", (d) => {
    if (tunneled) return;
    head = Buffer.concat([head, d]);
    const i = head.indexOf("\r\n\r\n"); if (i < 0) return;
    const status = head.subarray(0, head.indexOf("\r\n")).toString();
    if (mode === "probe" || !status.includes(" 200 ")) { s.on("end", () => done({status})); return; }
    tunneled = true;
    const t = tls.connect({socket: s, servername: target.split(":")[0], rejectUnauthorized: false});
    const c = [];
    t.on("secureConnect", () => t.write(`GET ${path} HTTP/1.1\r\nHost: ${target.split(":")[0]}\r\nConnection: close\r\n\r\n`));
    t.on("data", x => c.push(x)); t.on("end", () => { done(body(Buffer.concat(c))); s.end(); });
  });
  s.on("error", e => console.log(JSON.stringify({error: e.code})));
}
EOF

docker network create "$EGRESS" >/dev/null
docker network create "$ORIGIN_NET" >/dev/null
docker run -d --name "$ORIGIN" --network "$ORIGIN_NET" --network-alias www.origin.test \
  -v "$T/srv:/srv:ro" -v "$T/certs:/certs:ro" -v "$T/nginx.conf:/etc/nginx/nginx.conf:ro" nginx:alpine >/dev/null
docker run -d --name "$UP" --network "$EGRESS" --network-alias egress-proxy \
  -v "$T/upstream.py:/u.py:ro" python:3.12-alpine python /u.py >/dev/null
docker network connect "$ORIGIN_NET" "$UP"

cat > "$T/observe.yaml" <<EOF
harness: pi
model: stub
net: [service]
observe: {enabled: true}
services:
  - { name: proxy, to: "egress-proxy:8888", join_network: $EGRESS,
      observe: { mode: http-proxy, route: vpn } }
EOF

echo "== render (glove pi --config … --dry-run) =="
glove build >/dev/null 2>&1 || { echo "glove build failed"; exit 1; }
( cd "$T/wd" && glove init pi >/dev/null && glove run pi --config "$T/observe.yaml" --workdir "$T/work" --dry-run >/dev/null 2>&1 )
S="$GLOVE_HOME/envs/wd/sessions/wd"; C="$S/docker-compose.yml"; N="$S/net"
check "proxy service renders as an http-proxy gate chaining to egress-proxy by name" \
  "grep -q '\"--mode\", \"http-proxy\"' '$C' && grep -q 'chain:http://egress-proxy:8888' '$C' && grep -q '\"--route\", \"vpn\"' '$C'"
docker compose -p glove-wd -f "$C" up -d glove-wd-netgate glove-wd-proxy >/dev/null 2>&1
sleep 2
check "the gate is not on the origin network (it could not resolve the destination if it tried)" \
  "! docker inspect glove-wd-proxy --format '{{range \$k,\$v := .NetworkSettings.Networks}}{{\$k}} {{end}}' | grep -q '$ORIGIN_NET'"

# test-only sniffer in the gate's netns, for the duration of the client runs
docker run -d --name "$SNIFF" --network container:glove-wd-proxy --cap-drop ALL --cap-add NET_RAW \
  -v "$T/sniff.py:/s.py:ro" python:3.12-alpine python /s.py 45 >/dev/null
sleep 2

client() {
  docker compose -p glove-wd -f "$C" run --rm -T glove-wd-harness \
    nono run -s --allow-cwd --profile /etc/glove/enforcer/harness.json -- node /work/pclient.js "$@" \
    </dev/null 2>/dev/null | grep '^{'
}
field() { python3 -c "import sys,json; print(json.loads(sys.stdin.read().strip().splitlines()[-1]).get('$1'))"; }
flow_for() {  # $1 dest host, $2 port → the latest close record for it, as JSON
  python3 - "$N" "$1" "$2" <<'EOF'
import json, pathlib, sys
recs = []
for p in sorted(pathlib.Path(sys.argv[1]).glob("flows*.ndjson")):
    recs += [json.loads(l) for l in p.read_text().splitlines() if l.strip()]
c = [r for r in recs if r["phase"] == "close" and r["dest"]["host"] == sys.argv[2] and r["dest"]["port"] == int(sys.argv[3])]
print(json.dumps(c[-1] if c else {}))
EOF
}
fv() {  # fv '<json>' a.b.c → that field (no shell quoting inside checks)
  python3 -c 'import sys, json
d = json.loads(sys.argv[1])
for k in sys.argv[2].split("."):
    d = d[k]
print(d)' "$1" "$2"
}
listen_ports() { docker exec "$1" python -c "
rows=[l.split() for f in ('/proc/net/tcp','/proc/net/tcp6') for l in open(f).read().splitlines()[1:]]
# 127.0.0.x listeners are Docker's embedded-DNS stub (every container), not ours
print(sorted({int(r[1].split(':')[1],16) for r in rows if r[3]=='0A' and not r[1].startswith(('0100007F','0B00007F'))}))"; }

echo "== acceptance: web_fetch-style CONNECT through the gate =="
r="$(client tunnel glove-wd-proxy 8888 www.origin.test:443 /blob.bin)"
sleep 1; f="$(flow_for www.origin.test 443)"
echo "    client: $(echo "$r" | field status) body=$(echo "$r" | field body_len)B raw_sent=$(echo "$r" | field raw_sent) raw_received=$(echo "$r" | field raw_received)"
echo "    flow:   $(fv "$f" proto) $(fv "$f" tool) client=$(fv "$f" client) scope=$(fv "$f" scope) route=$(fv "$f" route) bytes=$(fv "$f" bytes) close=$(fv "$f" close_reason)"
check "HTTPS fetch through the chain succeeds, body intact (sha256 matches)" \
  "[ \"\$(echo '$r' | field body_sha)\" = $(shasum -a 256 "$T/srv/blob.bin" | cut -c1-64) ]"
got="$(fv "$f" dest.host):$(fv "$f" dest.port) $(fv "$f" proto) $(fv "$f" tool) $(fv "$f" client)"
check "flow: dest www.origin.test:443, proto http-connect, tool web_fetch, client harness ($got)" \
  "[ '$got' = 'www.origin.test:443 http-connect web_fetch harness' ]"
got="$(fv "$f" scope) $(fv "$f" route.kind) $(fv "$f" route.upstream) $(fv "$f" dest.resolution)"
check "flow: scope tunnelled, route vpn via http://egress-proxy:8888, resolution unavailable ($got)" \
  "[ '$got' = 'tunnelled vpn http://egress-proxy:8888 unavailable' ]"
up="$(fv "$f" bytes.up)"; down="$(fv "$f" bytes.down)"
check "flow bytes == raw bytes the client put on / took off the wire, exactly" \
  "[ $up -eq $(echo "$r" | field raw_sent) ] && [ $down -eq $(echo "$r" | field raw_received) ]"
pct="$(python3 -c "print(round(100*($down-300000)/300000, 2))")"
echo "    bytes.down vs 300000-byte response body: +$pct% (TLS framing + headers)"
check "bytes.down within a few percent of the response size ($pct%)" "python3 -c 'import sys; sys.exit(0 if 0 <= $pct < 5 else 1)'"

echo "== absolute-form request (plain http) =="
r="$(client absolute glove-wd-proxy 8888 http://www.origin.test/blob.bin)"
sleep 1; f="$(flow_for www.origin.test 80)"
check "absolute-form GET succeeds, body intact" \
  "[ \"\$(echo '$r' | field body_sha)\" = $(shasum -a 256 "$T/srv/blob.bin" | cut -c1-64) ]"
check "upstream got the canonical request line, not the client's bytes" \
  "docker logs $UP 2>&1 | grep -q 'REQ GET http://www.origin.test:80/blob.bin HTTP/1.1'"
got="$(fv "$f" proto) $(fv "$f" dest.port) $(fv "$f" bytes.up) $(fv "$f" bytes.down)"
check "flow: proto http, port 80, bytes exact ($got)" \
  "[ '$got' = 'http 80 $(echo "$r" | field raw_sent) $(echo "$r" | field raw_received)' ]"

echo "== SSRF guard =="
for tgt in 169.254.169.254:80 egress-proxy:8888 gluetun:8000 2130706433:80 '[::ffff:127.0.0.1]:80' host.docker.internal:8080 localhost:80; do
  st="$(client probe glove-wd-proxy 8888 "$tgt" | field status)"
  check "CONNECT $tgt → $st" "echo '$st' | grep -q '403'"
done
check "the upstream proxy never saw any refused destination" \
  "! docker logs $UP 2>&1 | grep -E 'REQ CONNECT (169\.254|egress-proxy|gluetun|2130706433|\[|host\.docker|localhost)'"
blocked="$(cat "$N"/flows*.ndjson | python3 -c "
import sys, json
rs=[json.loads(l) for l in sys.stdin if l.strip()]
print(sum(1 for r in rs if r['phase']=='close' and r['verdict']=='block' and r['rule']=='builtin:ssrf-guard' and r['close_reason']=='blocked'))")"
check "each refusal is recorded (verdict block, rule builtin:ssrf-guard): $blocked/7" "[ $blocked -eq 7 ]"

echo "== invariant 4, measured: DNS queries leaving the gate's netns =="
sleep 1
docker wait "$SNIFF" >/dev/null 2>&1 || true
names="$(docker logs "$SNIFF" 2>&1 | tail -1)"
echo "    queried: $names"
check "sniffer works (it saw the gate resolve its configured upstream, egress-proxy)" "echo '$names' | grep -q egress-proxy"
check "the gate NEVER resolved the agent's destination (www.origin.test)" "! echo '$names' | grep -q origin"
check "nor any refused destination name" "! echo '$names' | grep -qE 'gluetun|localhost'"

echo "== the gate in proxy mode exposes only its forward port =="
ports="$(listen_ports glove-wd-proxy)"; caps="$(docker inspect glove-wd-proxy --format '{{.HostConfig.CapAdd}}')"
check "listens on exactly [8888] ($ports), no caps added ($caps)" "[ '$ports' = '[8888]' ] && [ '$caps' = '[]' ]"

echo "== glove net flows =="
( cd "$T/wd" && glove net flows )
echo "== glove net status =="
( cd "$T/wd" && glove net status )

echo
echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
