"""glove-mcp-bridge against a stand-in Streamable-HTTP MCP server (stdlib only).

The unit test runs the bridge on this python; tests/integration/test_mcp_bridge.sh
runs this file in the Vibe image (`python3 test_mcp_bridge.py <bridge>`), the
bridge by its baked path and shebang. Speaking MCP over the bridge's stdio as
Vibe does: one session (one `initialize`, then its session id and protocol
version on every message), JSON and SSE answers, a slow call that doesn't hold
up the next, a failed POST answered with an error and the bridge still serving,
a server's JSON-RPC error relayed, an SSE event without data skipped, a lost
session (the server restarted: 404) re-opened with Vibe's `initialize` and the
call sent again (and if that fails, the call answered with an error and the next
call trying again), only MCP on stdout, and stdin's end sends `DELETE` and exits.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar

BRIDGE = Path(__file__).resolve().parent.parent / "image" / "mcp_bridge.py"
VERSION = "2025-03-26"


class StandIn(BaseHTTPRequestHandler):
    seen: ClassVar[list[tuple[str, str, str | None, str | None]]] = []  # (verb, method, session id, version)
    live: ClassVar[set[str]] = set()  # the sessions it knows: a restart forgets them
    opened: ClassVar[list[str]] = []  # every session it opened (ids never reused)
    release: ClassVar[threading.Event] = threading.Event()  # holds a call that says `hold`
    refuse: ClassVar[list[None]] = []  # refuse one initialize (a restarting server) per item

    def log_message(self, *_):
        pass

    def _reply(self, code: int, body: bytes = b"", ctype: str = "application/json", sid: str = "") -> None:
        self.send_response(code)
        self.send_header("content-type", ctype)
        if sid:
            self.send_header("mcp-session-id", sid)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _note(self, verb: str, method: str = "") -> None:
        self.seen.append((verb, method, self.headers.get("mcp-session-id"), self.headers.get("mcp-protocol-version")))

    def do_GET(self):  # no server-initiated stream
        self._reply(405)

    def do_DELETE(self):
        self._note("DELETE")
        self._reply(200)

    def do_POST(self):
        msg = json.loads(self.rfile.read(int(self.headers["content-length"])))
        self._note("POST", msg.get("method", ""))
        if msg.get("method") == "initialize":
            if self.refuse:
                self.refuse.pop()
                return self._reply(500, b"starting", "text/plain")
            sid = f"sess-{len(self.opened) + 1}"
            self.opened.append(sid)
            self.live.add(sid)
            return self._reply(200, json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {
                "protocolVersion": VERSION, "capabilities": {"tools": {}},
                "serverInfo": {"name": "stand-in", "version": "0"}}}).encode(), sid=sid)
        if self.headers.get("mcp-session-id") not in self.live:
            return self._reply(404, b"no such session", "text/plain")
        if "id" not in msg:  # a notification
            return self._reply(202)
        args = msg["params"].get("arguments") or {}
        if args.get("fail"):
            return self._reply(500, b"boom", "text/plain")
        if args.get("bad"):
            return self._reply(400, json.dumps({"jsonrpc": "2.0", "id": msg["id"], "error": {
                "code": -32602, "message": "bad params"}}).encode())
        if args.get("hold"):
            self.release.wait(30)
        answer = {"jsonrpc": "2.0", "id": msg["id"], "result": {"content": [{"type": "text",
                                                                              "text": f"echo:{args.get('n')}"}]}}
        if args.get("sse"):  # a priming event (no data), a progress notification, then the answer
            note = {"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progress": 1}}
            body = "id: 0\ndata:\n\n" + "".join(f"event: message\ndata: {json.dumps(m)}\n\n" for m in (note, answer))
            return self._reply(200, body.encode(), "text/event-stream")
        self._reply(200, json.dumps(answer).encode())


def exercise(cmd: list[str]) -> list[tuple[str, bool, str]]:
    StandIn.seen, StandIn.live, StandIn.release, StandIn.refuse, StandIn.opened = [], set(), threading.Event(), [], []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), StandIn)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    p = subprocess.Popen([*cmd, f"http://127.0.0.1:{srv.server_address[1]}/mcp"], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    timer = threading.Timer(60, p.kill)  # a hung bridge fails the checks, never the run
    timer.start()
    out: list[str] = []

    def send(id_: int | None, method: str, params: dict) -> None:
        msg = {"jsonrpc": "2.0", "method": method, "params": params} | ({"id": id_} if id_ is not None else {})
        p.stdin.write(json.dumps(msg) + "\n")
        p.stdin.flush()

    def answers(*ids: int) -> dict[int, dict]:
        got: dict[int, dict] = {}
        while set(ids) - set(got) and (line := p.stdout.readline()):
            out.append(line)
            msg = json.loads(line)
            if msg.get("id") in ids:
                got[msg["id"]] = msg
        return got

    def call(id_: int, **args) -> None:
        send(id_, "tools/call", {"name": "echo", "arguments": args})

    send(1, "initialize", {"protocolVersion": VERSION, "capabilities": {},
                           "clientInfo": {"name": "check", "version": "0"}})
    init = answers(1).get(1, {})
    send(None, "notifications/initialized", {})
    call(2, n=1, sse=True)
    sse = answers(2).get(2, {})
    call(3, n="held", hold=True)
    call(4, n=2)
    unheld = answers(4).get(4, {})  # while 3 is still held
    StandIn.release.set()
    held = answers(3).get(3, {})
    call(5, fail=True)
    call(6, n=3)
    call(7, bad=True)
    after = answers(5, 6, 7)
    StandIn.live, StandIn.refuse = set(), [None]  # the server restarts, and refuses the first initialize
    call(8, n=4)
    refused = answers(8).get(8, {})
    call(9, n=5)
    again = answers(9).get(9, {})
    p.stdin.close()
    rc = p.wait()
    timer.cancel()
    srv.shutdown()
    err = p.stderr.read()

    seen = StandIn.seen
    posts = [(m, s, v) for verb, m, s, v in seen if verb == "POST"]
    inits = [i for i, (m, _, _) in enumerate(posts) if m == "initialize"]
    first = [(s, v) for m, s, v in posts[1:inits[1]]]
    after_restart = [(s, v) for m, s, v in posts[inits[-1] + 1:]]
    return [
        ("initialize is relayed and answered",
         init.get("result", {}).get("serverInfo", {}).get("name") == "stand-in", str(init)[:200]),
        ("an SSE answer is relayed, with what came before it (an event without data skipped)",
         "echo:1" in json.dumps(sse) and any("notifications/progress" in x for x in out), str(out)[:300]),
        ("a slow call doesn't hold up the next", "echo:2" in json.dumps(unheld) and "echo:held" in json.dumps(held),
         f"{unheld}; {held}"),
        ("a failed POST is answered with an error",
         "glove-mcp-bridge" in after.get(5, {}).get("error", {}).get("message", ""), str(after.get(5))[:200]),
        ("…and the bridge still serves the next call", "echo:3" in json.dumps(after.get(6)), str(after.get(6))),
        ("a server's JSON-RPC error (HTTP 400) is relayed as sent",
         after.get(7, {}).get("error", {}).get("message") == "bad params", str(after.get(7))[:200]),
        ("one HTTP session serves every call: its id and protocol version on each",
         len(first) > 5 and all(x == ("sess-1", VERSION) for x in first), str(first)),
        ("a lost session (404) whose new one fails answers the call with an error",
         "a new one failed" in refused.get("error", {}).get("message", ""), str(refused)[:200]),
        ("…and the next call re-opens it with Vibe's initialize and is answered",
         len(inits) == 3 and "echo:5" in json.dumps(again)
         and after_restart and all(x == ("sess-2", VERSION) for x in after_restart), f"{posts[-4:]}; {again}"),
        ("…and the new session's initialize answer isn't passed to Vibe",
         sum(json.loads(x).get("id") == 1 for x in out) == 1, str(out)[-300:]),
        ("stdout is only MCP (JSON-RPC lines)", all(json.loads(x).get("jsonrpc") == "2.0" for x in out),
         str(out)[:200]),
        ("stdin's end sends DELETE for the session", ("DELETE", "", "sess-2", VERSION) in seen, str(seen[-2:])),
        ("…and the bridge exits 0", rc == 0, f"rc {rc}; stderr {err[-300:]}"),
    ]


def test_bridge_relays_one_session():
    failed = [f"{label}: {detail}" for label, ok, detail in exercise([sys.executable, str(BRIDGE)]) if not ok]
    assert not failed, "\n".join(failed)


if __name__ == "__main__":
    results = exercise(sys.argv[1:] or [sys.executable, str(BRIDGE)])
    for label, ok, detail in results:
        print(f"  {'PASS' if ok else 'FAIL'} {label}" + ("" if ok else f"  ({detail})"), flush=True)
    sys.exit(1 if any(not ok for _, ok, _ in results) else 0)
