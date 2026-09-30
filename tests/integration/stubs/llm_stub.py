"""A tiny llama-server look-alike for live tests (stdlib only).

Serves /v1/models (one model), /props (llama.cpp's capability fields) and a
streaming /v1/chat/completions that answers with a fixed sentence. Logs every
request line (and whether an Authorization header was present, never its
value) and the names of the tools offered to stdout.

Tool driving (egress tests): when the last user message contains
`CALL <tool> <json-args>` the stub answers with that tool call; when the last
message is a tool result it answers `TOOL RESULT: <first 300 chars>`. So a
`pi -p "CALL web_fetch {...}"` exercises the real tool path end to end.
The skill directories Pi lists in its system prompt are logged as `skills=`.
"""

from __future__ import annotations

import json
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODEL = "stub-qwen-vision"
PROPS = {
    "default_generation_settings": {"n_ctx": 65536},
    "modalities": {"vision": True, "video": False, "audio": False},
    "chat_template_caps": {"supports_preserve_reasoning": False},
}
REPLY = "hello from the glove llm stub"


class H(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        auth = "auth=yes" if self.headers.get("Authorization") else "auth=no"
        print(f"stub: {self.command} {self.path} {auth}", flush=True)

    def _json(self, obj, status=200):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/v1/models":
            return self._json({"object": "list", "data": [{"id": MODEL, "object": "model"}]})
        if self.path == "/props":
            return self._json(PROPS)
        return self._json({"error": "not found"}, 404)

    def do_POST(self):
        n = int(self.headers.get("content-length") or 0)
        req = json.loads(self.rfile.read(n) or b"{}")
        if self.path != "/v1/chat/completions":
            return self._json({"error": "not found"}, 404)
        tools = [t.get("function", {}).get("name") for t in req.get("tools") or []]
        print(f"stub: chat model={req.get('model')} stream={req.get('stream')} tools={','.join(tools)}", flush=True)
        system = " ".join(_text(m.get("content")) for m in req.get("messages") or [] if m.get("role") == "system")
        skills = sorted(set(re.findall(r"(/[\w./-]+)/SKILL\.md", system)))
        if skills:
            print(f"stub: skills={','.join(skills)}", flush=True)
        base = {"id": "c1", "object": "chat.completion.chunk", "created": 0, "model": MODEL}
        reply, call = REPLY, None
        msgs = req.get("messages") or []
        last = msgs[-1] if msgs else {}
        text = _text(last.get("content"))
        if last.get("role") == "tool":
            reply = "TOOL RESULT: " + " ".join(text.split())[:300]
        elif last.get("role") == "user" and (m := re.search(r"CALL (\w+) (\{.*\})", text, re.S)):
            call = {"index": 0, "id": "call_1", "type": "function",
                    "function": {"name": m.group(1), "arguments": m.group(2)}}
        print(f"stub: -> {'call ' + call['function']['name'] if call else reply[:120]}", flush=True)
        if not req.get("stream"):
            msg = {"role": "assistant", "content": None if call else reply}
            if call:
                msg["tool_calls"] = [{k: v for k, v in call.items() if k != "index"}]
            return self._json({**base, "object": "chat.completion", "choices": [
                {"index": 0, "message": msg, "finish_reason": "tool_calls" if call else "stop"}]})
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.end_headers()
        steps = ((({"role": "assistant", "content": None, "tool_calls": [call]}, None), ({}, "tool_calls"))
                 if call else (({"role": "assistant", "content": ""}, None), ({"content": reply}, None), ({}, "stop")))
        for delta, fin in steps:
            chunk = {**base, "choices": [{"index": 0, "delta": delta, "finish_reason": fin}]}
            self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode())
        usage = {**base, "choices": [], "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}
        self.wfile.write(f"data: {json.dumps(usage)}\n\ndata: [DONE]\n\n".encode())


def _text(content) -> str:
    if isinstance(content, list):
        return " ".join(str(p.get("text", "")) for p in content if isinstance(p, dict))
    return str(content or "")


if __name__ == "__main__":
    port = int(sys.argv[1])
    print(f"stub: listening on 127.0.0.1:{port}", flush=True)
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
