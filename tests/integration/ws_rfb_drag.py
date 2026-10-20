"""RFB over noVNC's WebSocket, the way a browser tab running noVNC talks to
`glove playwright view|solve`: one drag, then close.

    uv run --no-project --with pycryptodome python tests/integration/ws_rfb_drag.py <x0> <y0> <x1> <y1>   (URL on stdin)

Reads the viewer URL (`http://127.0.0.1:<port>/vnc.html#…&password=…`) from
stdin (it carries the password: never argv), opens the WebSocket with this
listener's Host and Origin, authenticates (VncAuth), presses button 1 at
(x0, y0), moves to (x1, y1) in 20 steps, releases, and closes. Prints
`auth ok` / `auth failed`.
"""

from __future__ import annotations

import base64
import os
import re
import socket
import struct
import sys
import time

from rfb_click import handshake


class WS:
    def __init__(self, port: int) -> None:
        self.s = socket.create_connection(("127.0.0.1", port), timeout=20)
        key = base64.b64encode(os.urandom(16)).decode()
        me = f"127.0.0.1:{port}"
        self.s.sendall((f"GET /websockify HTTP/1.1\r\nHost: {me}\r\nOrigin: http://{me}\r\nUpgrade: websocket\r\n"
                        f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
                        "Sec-WebSocket-Protocol: binary\r\n\r\n").encode())
        head = b""
        while b"\r\n\r\n" not in head:
            head += self.s.recv(1)
        if b" 101 " not in head.split(b"\r\n", 1)[0]:
            raise SystemExit(f"no websocket: {head[:80]!r}")
        self.buf = b""

    def _frame(self, opcode: int, data: bytes) -> None:
        mask = os.urandom(4)
        n = len(data)
        head = bytes([0x80 | opcode]) + (bytes([0x80 | n]) if n < 126 else bytes([0xFE]) + struct.pack(">H", n))
        self.s.sendall(head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))

    def send(self, data: bytes) -> None:
        self._frame(2, data)

    def _recv_exact(self, n: int) -> bytes:
        out = b""
        while len(out) < n:
            chunk = self.s.recv(n - len(out))
            if not chunk:
                raise EOFError("closed")
            out += chunk
        return out

    def read(self, n: int) -> bytes:
        while len(self.buf) < n:
            b0, b1 = self._recv_exact(2)
            ln = b1 & 0x7F
            if ln == 126:
                ln = struct.unpack(">H", self._recv_exact(2))[0]
            elif ln == 127:
                ln = struct.unpack(">Q", self._recv_exact(8))[0]
            payload = self._recv_exact(ln)
            if b0 & 0x0F in (0, 1, 2):
                self.buf += payload
            elif b0 & 0x0F == 8:
                raise EOFError("closed by the server")
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def close(self) -> None:
        self._frame(8, struct.pack(">H", 1000))
        self.s.close()


def main(x0: int, y0: int, x1: int, y1: int) -> int:
    url = sys.stdin.readline().strip()
    port = int(re.search(r"127\.0\.0\.1:(\d+)/", url).group(1))
    password = re.search(r"[#&]password=([^&]+)", url).group(1)
    ws = WS(port)
    if not handshake(ws.read, ws.send, password):
        return 1
    ws.send(struct.pack(">BBHH", 5, 0, x0, y0))
    time.sleep(0.3)
    ws.send(struct.pack(">BBHH", 5, 1, x0, y0))
    time.sleep(0.2)
    for i in range(1, 21):
        ws.send(struct.pack(">BBHH", 5, 1, x0 + (x1 - x0) * i // 20, y0 + (y1 - y0) * i // 20))
        time.sleep(0.03)
    ws.send(struct.pack(">BBHH", 5, 0, x1, y1))
    time.sleep(1.0)
    ws.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(*map(int, sys.argv[1:5])))
