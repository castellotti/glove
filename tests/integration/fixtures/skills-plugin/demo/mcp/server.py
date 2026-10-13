#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""A stdio MCP server with one tool, `echo` (newline-delimited JSON-RPC). A
`host:port` message is also dialled: `net=open` or `net=closed`."""
import json
import os
import socket
import sys

TOOL = {"name": "echo", "description": "Echo a message back.",
        "inputSchema": {"type": "object", "properties": {"message": {"type": "string"}}, "required": ["message"]}}


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
        reply(rid, {"tools": [TOOL]})
    elif method == "tools/call":
        message = str(msg["params"]["arguments"].get("message"))
        text = f"ECHO {message} root={os.environ.get('CLAUDE_PLUGIN_ROOT')} data={os.environ.get('DEMO_DATA')}"
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
