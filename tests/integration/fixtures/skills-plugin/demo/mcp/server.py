#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""A stdio MCP server (newline-delimited JSON-RPC) with two tools: `echo`, and
`secret`, which a session keeps off its allowlist. `echo` also reports the
server's argv, and dials a `host:port` message (`net=open` or `net=closed`).
Every `tools/call` that arrives is appended to `$DEMO_DATA/calls.log`."""
import json
import os
import socket
import sys

TOOL = {"name": "echo", "description": "Echo a message back.",
        "inputSchema": {"type": "object", "properties": {"message": {"type": "string"}}, "required": ["message"]}}
SECRET = {**TOOL, "name": "secret", "description": "A tool the session does not allow."}


def reply(rid, result):
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid, "result": result}) + "\n")
    sys.stdout.flush()


for line in sys.stdin:
    msg = json.loads(line)
    method, rid = msg.get("method"), msg.get("id")
    if method == "initialize":
        reply(rid, {"protocolVersion": msg["params"].get("protocolVersion", "2025-06-18"),
                    "capabilities": {"tools": {}}, "serverInfo": {"name": "demo", "version": "0.1.0"}})
    elif method == "tools/list":
        reply(rid, {"tools": [TOOL, SECRET]})
    elif method == "tools/call":
        name, message = msg["params"]["name"], str(msg["params"]["arguments"].get("message"))
        try:  # the log is for the checks; echo answers without it
            with open(os.path.join(os.environ.get("DEMO_DATA", "/tmp"), "calls.log"), "a") as log:
                log.write(f"{name} {message}\n")
        except OSError:
            pass
        if name == "secret":
            reply(rid, {"content": [{"type": "text", "text": f"SECRET-REACHED {message}"}]})
            continue
        text = (f"ECHO {message} root={os.environ.get('CLAUDE_PLUGIN_ROOT')} data={os.environ.get('DEMO_DATA')}"
                f" argv={'|'.join(sys.argv[1:])}")
        if ":" in message:
            host, _, port = message.rpartition(":")
            try:
                socket.create_connection((host, int(port)), 3).close()
                text += " net=open"
            except OSError:
                text += " net=closed"
        reply(rid, {"content": [{"type": "text", "text": text}]})
    elif rid is not None:
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": method}}) + "\n")
        sys.stdout.flush()
