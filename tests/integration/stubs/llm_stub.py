"""A tiny llama-server look-alike for live tests (stdlib only).

Serves /v1/models (one model), /props (llama.cpp's capability fields) and a
streaming /v1/chat/completions that answers with a fixed sentence. Logs every
request line (and which key arrived, never its value: `key=`, see
`key_kind`) and the names of the tools offered to stdout. With
GLOVE_TEST_LLM_KEY set it is `llama-server --api-key`: a request without
`Authorization: Bearer <that key>` gets a 401 (glove's llm-auth must have
swapped the harness's placeholder for it).

Tool driving (egress tests): when the last user message contains
`CALL <tool> <json-args>` the stub answers with that tool call; when the last
message is a tool result it answers `TOOL RESULT: <first 1500 chars>` (Vibe 2.26 puts the
wrapped command and stderr before stdout). So a
`pi -p "CALL web_fetch {...}"` exercises the real tool path end to end.
`SEQ [[<tool>, <json>], …]` in the first user message makes those tool calls one
after another in one turn, then answers "TOOL RESULTS: <each result's first 400
chars, joined by |||>" (as the anthropic stub; live_common.LiveSession.seq).
The skill directories Pi lists in its system prompt are logged as `skills=`.
"""

from __future__ import annotations

import json
import os
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
KEY = os.environ.get("GLOVE_TEST_LLM_KEY", "")


def key_kind(value: str | None, key: str) -> str:
    """What credential a request carried, never its value: none, real (the
    expected key), placeholder (glove's `glove-injected`) or other."""
    if not value:
        return "none"
    token = value.removeprefix("Bearer ")
    return "real" if key and token == key else "placeholder" if token == "glove-injected" else "other"


def refused(handler, kind: str, body: bytes) -> bool:
    """With KEY set, a request not carrying it (`kind` is not real) gets a
    JSON 401 with `body`: True."""
    if not KEY or kind == "real":
        return False
    handler.send_response(401)
    handler.send_header("content-type", "application/json")
    handler.send_header("content-length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)
    return True


class H(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"stub: {self.command} {self.path} key={self._key()}", flush=True)

    def _key(self) -> str:
        return key_kind(self.headers.get("Authorization"), KEY)

    def _refused(self) -> bool:
        return refused(self, self._key(), b'{"error": "invalid api key"}')

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
        if self.path == "/v1/models":
            return self._json({"object": "list", "data": [{"id": MODEL, "object": "model"}]})
        if self.path == "/props":
            return self._json(PROPS)
        return self._json({"error": "not found"}, 404)

    def do_POST(self):
        n = int(self.headers.get("content-length") or 0)
        req = json.loads(self.rfile.read(n) or b"{}")
        if self._refused():
            return None
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
        first = next((m for m in msgs if m.get("role") == "user"), {})
        done = [_text(m.get("content")) for m in msgs if m.get("role") == "tool"]
        step = seq_step(_text(first.get("content")), done) if tools else None
        if isinstance(step, tuple):
            call = {"index": 0, "id": f"call_{len(done) + 1}", "type": "function",
                    "function": {"name": step[0], "arguments": json.dumps(step[1])}}
        elif step is not None:
            reply = step
        elif last.get("role") == "tool":
            reply = "TOOL RESULT: " + " ".join(text.split())[:1500]
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


def seq_step(first_user: str, done: list[str]) -> tuple[str, dict] | str | None:
    """A `SEQ` turn's next tool call (name, args), its closing "TOOL RESULTS: …"
    text once every step has a result in `done`, or None (no SEQ)."""
    m = re.search(r"SEQ (\[.*\])", first_user, re.S)
    if not m:
        return None
    steps = json.loads(m.group(1))
    if len(done) < len(steps):
        name, args = steps[len(done)]
        return name, args
    return "TOOL RESULTS: " + " ||| ".join(d[:400] for d in done)


def _text(content) -> str:
    if isinstance(content, list):
        return " ".join(str(p.get("text", "")) for p in content if isinstance(p, dict))
    return str(content or "")


if __name__ == "__main__":
    port = int(sys.argv[1])
    print(f"stub: listening on 127.0.0.1:{port}", flush=True)
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
