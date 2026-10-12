#!/usr/local/bin/python3
"""glove-mcp-bridge <url>: one stdio MCP server relaying to one Streamable-HTTP MCP session.

Vibe opens a new MCP session for every call to an HTTP server (and ends it with
`DELETE`), but keeps a stdio server's process for its whole session. A server
that holds state per session (Playwright's pages) needs the latter, so glove's
Vibe adapter renders each HTTP server as this bridge: JSON-RPC messages pass
through unchanged both ways, over one HTTP session for the process's life. When
Vibe closes stdin, the bridge ends the session (`DELETE`) and exits.

Each request is its own POST (a thread, so a long tool call never holds up the
next); the answer, JSON or an SSE stream, goes to stdout as it arrives. A
request whose POST fails is answered with a JSON-RPC error and the bridge keeps
serving (the `mcp` SDK's client would end the whole session). A server that
lost the session (404: it restarted) gets a new one, opened with Vibe's own
`initialize`, and the request is sent again once. Not relayed: the
server's optional GET stream. Stdlib only, on the image's python (as the hook);
it writes nothing but MCP to stdout and ignores any proxy in its environment.
"""

from __future__ import annotations

import contextlib
import json
import sys
import threading
import urllib.error
import urllib.request

TIMEOUT = 1800  # as Vibe's api_timeout: a long tool call holds its POST open
_open = urllib.request.build_opener(urllib.request.ProxyHandler({})).open


def is_request(msg: dict) -> bool:
    """A request expects an answer; a notification or a response doesn't."""
    return "method" in msg and msg.get("id") is not None


class Bridge:
    def __init__(self, url: str) -> None:
        self.url = url
        self.session: dict[str, str] = {}  # mcp-session-id / mcp-protocol-version, once initialized
        self._out, self._reinit = threading.Lock(), threading.Lock()
        self._init: dict = {}  # Vibe's initialize, replayed if the server loses the session

    def emit(self, msg: dict) -> None:
        with self._out:
            sys.stdout.write(json.dumps(msg) + "\n")
            sys.stdout.flush()

    def _request(self, data: bytes | None = None, method: str = "POST") -> urllib.request.Request:
        return urllib.request.Request(self.url, data, method=method, headers={
            "content-type": "application/json", "accept": "application/json, text/event-stream", **self.session})

    def _send(self, msg: dict, relay) -> None:
        """POST one message and relay each message of the answer (JSON, or an SSE
        stream until `relay` returns true: the request is answered). An
        `initialize` answer also opens the session: its id and protocol version."""
        with _open(self._request(json.dumps(msg).encode()), timeout=TIMEOUT) as r:
            if msg.get("method") == "initialize":
                if r.headers.get("mcp-session-id"):
                    self.session["mcp-session-id"] = r.headers["mcp-session-id"]
                inner = relay

                def relay(m: dict) -> bool:
                    if "result" in m:
                        self.session["mcp-protocol-version"] = m["result"].get("protocolVersion", "")
                    return inner(m)
            if r.headers.get_content_type() == "text/event-stream":
                data: list[str] = []
                for raw in r:
                    line = raw.decode().rstrip("\r\n")
                    if line.startswith("data:"):
                        data.append(line[5:].removeprefix(" "))
                    elif not line and data:
                        if relay(json.loads("\n".join(data))):
                            break
                        data = []
            elif body := r.read().strip():
                relay(json.loads(body))

    def _reinitialize(self, stale: str) -> None:
        """The server lost the session (a 404: it restarted, or expired it): open a
        new one as Vibe opened the first, once for every caller that saw it."""
        with self._reinit:
            if self.session.get("mcp-session-id") != stale:
                return  # another call already did
            self.session.clear()
            self._send(self._init, lambda m: True)  # the answer is the bridge's, not Vibe's
            self._send({"jsonrpc": "2.0", "method": "notifications/initialized"}, lambda m: True)

    def post(self, msg: dict, retry: bool = True) -> None:
        """Relay one client message; a request is answered, by the server or with an error."""
        rid, answered = msg.get("id"), not is_request(msg)
        if msg.get("method") == "initialize":
            self._init = msg

        def relay(m: dict) -> bool:
            nonlocal answered
            answered = answered or (m.get("id") == rid and ("result" in m or "error" in m))
            self.emit(m)
            return answered

        stale = self.session.get("mcp-session-id")
        try:
            self._send(msg, relay)
            error = "the server sent no answer"
        except urllib.error.HTTPError as e:
            if e.code == 404 and stale and retry:
                try:
                    self._reinitialize(stale)
                except Exception as e2:  # noqa: BLE001
                    error = f"the session ended and a new one failed: {e2}"
                else:
                    return self.post(msg, retry=False)
            else:
                error = str(e)
                with contextlib.suppress(ValueError):  # a JSON-RPC error the server sent with the status
                    body = json.loads(e.read())
                    if isinstance(body, dict) and body.get("id") == rid and "error" in body:
                        relay(body)
        except Exception as e:  # noqa: BLE001 — any failure answers the request, never ends the bridge
            error = str(e)
        if not answered:
            self.emit({"jsonrpc": "2.0", "id": rid, "error": {"code": -32603, "message": f"glove-mcp-bridge: {error}"}})

    def end(self) -> None:
        if "mcp-session-id" in self.session:
            try:
                _open(self._request(method="DELETE"), timeout=10).close()
            except Exception:  # noqa: BLE001 — the server ends an abandoned session itself
                pass

    def serve(self, lines) -> None:
        for line in lines:
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            if not isinstance(msg, dict):
                continue
            if msg.get("method") in ("initialize", "notifications/initialized"):
                self.post(msg)  # in order: the session opens before anything else is sent
            else:
                threading.Thread(target=self.post, args=(msg,), daemon=True).start()
        self.end()  # stdin closed: Vibe is done with this server


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: glove-mcp-bridge <url>")
    Bridge(sys.argv[1]).serve(sys.stdin)
