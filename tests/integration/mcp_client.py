"""A stdlib Streamable-HTTP MCP client for live tests (one session, several calls).

    python3 mcp_client.py <url> <host header> '<json list of [tool, args]>'

`["tools/list", {}]` lists the tools; `["sleep", {"s": 5}]` waits (so something
else can happen mid-session, e.g. a VNC click). Prints one line per step.
"""

import json
import sys
import time
import urllib.error
import urllib.request

url, host, steps = sys.argv[1], sys.argv[2], json.loads(sys.argv[3])
sid = None


def rpc(method, params, id_=1):
    global sid
    h = {"Host": host, "content-type": "application/json", "accept": "application/json, text/event-stream"}
    if sid:
        h["mcp-session-id"] = sid
    body = {"jsonrpc": "2.0", "method": method, "params": params}
    if id_ is not None:
        body["id"] = id_
    try:
        r = urllib.request.urlopen(urllib.request.Request(url, json.dumps(body).encode(), h), timeout=120)
    except urllib.error.HTTPError as e:
        print("HTTP", e.code, e.read()[:200].decode(errors="replace"), flush=True)
        sys.exit(1)
    sid = r.headers.get("mcp-session-id") or sid
    text = r.read().decode()
    for line in text.splitlines():
        if line.startswith("data:"):
            return json.loads(line[5:])
    return json.loads(text) if text.strip() else None


init = rpc("initialize", {"protocolVersion": "2025-03-26", "capabilities": {},
                          "clientInfo": {"name": "glove-live", "version": "0"}})
print("server:", init["result"]["serverInfo"]["name"], init["result"]["serverInfo"]["version"], flush=True)
rpc("notifications/initialized", {}, None)
for name, args in steps:
    if name == "sleep":
        time.sleep(float(args.get("s", 1)))
        continue
    if name == "tools/list":
        r = rpc("tools/list", {}, 2)
        print("tools:", ",".join(t["name"] for t in r["result"]["tools"]), flush=True)
        continue
    r = rpc("tools/call", {"name": name, "arguments": args}, 3)
    out = "\n".join(c.get("text", "[" + c.get("type", "") + "]") for c in r["result"]["content"])
    print(f"{name}:", out[:1500].replace("\n", " | "), flush=True)
