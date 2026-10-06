"""Anthropic Messages look-alike for the Claude Code integration checks (stdlib only).

`CALL <tool> <json>` in the last user text → a tool_use; a tool_result → text
"TOOL RESULT: <first 400 chars>". A request without tools (Claude Code's
WebFetch summariser, title generation) → "ECHO: <the user text, from the
first `---`>". Everything else → a fixed sentence. Logs each
request path, the auth header names present and which key arrived (never
values: `key=`, see llm_stub.key_kind) and tool names. With GLOVE_TEST_LLM_KEY
set, a request without that key (`x-api-key`, or `Authorization: Bearer`) gets
a 401, as Anthropic's API would.
"""

from __future__ import annotations

import json
import re
import sys
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from llm_stub import KEY, key_kind, refused

REPLY = "hello from the glove anthropic stub"


def _last_user(msgs):
    for m in reversed(msgs):
        if m.get("role") == "user":
            return m.get("content")
    return None


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        names = [h for h in ("x-api-key", "authorization", "anthropic-beta") if self.headers.get(h)]
        print(f"stub: {self.command} {self.path} headers={names} key={self._key()}", flush=True)

    def _key(self) -> str:
        return key_kind(self.headers.get("x-api-key") or self.headers.get("authorization"), KEY)

    def _refused(self) -> bool:
        return refused(self, self._key(), b'{"type": "error", "error": {"type": "authentication_error"}}')

    def _json(self, obj, status=200):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self._refused():
            return None
        if self.path.startswith("/v1/models"):
            return self._json({"data": [{"id": "claude-stub", "type": "model", "display_name": "stub"}]})
        self._json({}, 404)

    def do_POST(self):
        n = int(self.headers.get("content-length") or 0)
        req = json.loads(self.rfile.read(n) or b"{}")
        if self._refused():
            return None
        if "count_tokens" in self.path:
            return self._json({"input_tokens": 10})
        if not self.path.startswith("/v1/messages"):
            return self._json({}, 404)
        tools = [t.get("name") for t in req.get("tools") or []]
        print(f"stub: tools={tools}", flush=True)
        content = _last_user(req.get("messages") or [])
        blocks = content if isinstance(content, list) else [{"type": "text", "text": content or ""}]
        result = next((b for b in blocks if b.get("type") == "tool_result"), None)
        text = " ".join(b.get("text", "") for b in blocks if b.get("type") == "text")
        out: list[dict]
        if result is not None:
            c = result.get("content")
            c = c if isinstance(c, str) else " ".join(x.get("text", "") for x in c or [] if isinstance(x, dict))
            print(f"stub: tool_result is_error={result.get('is_error')} {c[:400]!r}", flush=True)
            out = [{"type": "text", "text": "TOOL RESULT: " + c[:400]}]
        elif (m := re.search(r"CALL (\w+) (\{.*\})", text, re.S)):
            out = [{"type": "tool_use", "id": "toolu_" + uuid.uuid4().hex[:20], "name": m.group(1),
                    "input": json.loads(m.group(2))}]
        elif not tools:
            out = [{"type": "text", "text": "ECHO: " + text[text.find("---"):][:1200]}]
        else:
            out = [{"type": "text", "text": REPLY}]
        stop = "tool_use" if out[0]["type"] == "tool_use" else "end_turn"
        if not req.get("stream"):
            return self._json({"id": "msg_stub", "type": "message", "role": "assistant", "model": req.get("model"),
                               "content": out, "stop_reason": stop, "usage": {"input_tokens": 10, "output_tokens": 5}})
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("connection", "close")
        self.end_headers()

        def ev(name, data):
            self.wfile.write(f"event: {name}\ndata: {json.dumps(data)}\n\n".encode())

        ev("message_start", {"type": "message_start", "message": {
            "id": "msg_stub", "type": "message", "role": "assistant", "model": req.get("model"), "content": [],
            "stop_reason": None, "usage": {"input_tokens": 10, "output_tokens": 1}}})
        for i, b in enumerate(out):
            if b["type"] == "text":
                ev("content_block_start", {"type": "content_block_start", "index": i,
                                           "content_block": {"type": "text", "text": ""}})
                ev("content_block_delta", {"type": "content_block_delta", "index": i,
                                           "delta": {"type": "text_delta", "text": b["text"]}})
            else:
                ev("content_block_start", {"type": "content_block_start", "index": i, "content_block": {
                    "type": "tool_use", "id": b["id"], "name": b["name"], "input": {}}})
                delta = {"type": "input_json_delta", "partial_json": json.dumps(b["input"])}
                ev("content_block_delta", {"type": "content_block_delta", "index": i, "delta": delta})
            ev("content_block_stop", {"type": "content_block_stop", "index": i})
        ev("message_delta", {"type": "message_delta", "delta": {"stop_reason": stop}, "usage": {"output_tokens": 5}})
        ev("message_stop", {"type": "message_stop"})
        self.wfile.flush()
        self.close_connection = True


if __name__ == "__main__":
    port = int(sys.argv[1])
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
