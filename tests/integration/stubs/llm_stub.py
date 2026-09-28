"""A tiny llama-server look-alike for live tests (stdlib only).

Serves /v1/models (one model), /props (llama.cpp's capability fields) and a
streaming /v1/chat/completions that answers with a fixed sentence. Logs every
request line (and whether an Authorization header was present, never its
value) to stdout.
"""

from __future__ import annotations

import json
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
        print(f"stub: chat model={req.get('model')} stream={req.get('stream')}", flush=True)
        base = {"id": "c1", "object": "chat.completion.chunk", "created": 0, "model": MODEL}
        if not req.get("stream"):
            return self._json({**base, "object": "chat.completion", "choices": [
                {"index": 0, "message": {"role": "assistant", "content": REPLY}, "finish_reason": "stop"}]})
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.end_headers()
        for delta, fin in (({"role": "assistant", "content": ""}, None), ({"content": REPLY}, None), ({}, "stop")):
            chunk = {**base, "choices": [{"index": 0, "delta": delta, "finish_reason": fin}]}
            self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode())
        usage = {**base, "choices": [], "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}
        self.wfile.write(f"data: {json.dumps(usage)}\n\ndata: [DONE]\n\n".encode())


if __name__ == "__main__":
    port = int(sys.argv[1])
    print(f"stub: listening on 127.0.0.1:{port}", flush=True)
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
