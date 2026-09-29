"""A minimal RFB (VNC) client for the novnc live test: authenticate, click once.

    uv run --no-project --with pycryptodome python tests/integration/rfb_click.py \
        <runtime> <container> <full|view> <x> <y>

Connects to the sidecar's Xvnc on its own loopback (5900) through
`<runtime> exec -i <container> socat` — the same kind of path `glove
playwright view` uses — reading the password the sidecar generated
(/tmp/vnc/<full|view>) into memory (never argv). Speaks RFB 3.8 with VncAuth, sends a left click at
(x, y) and exits: prints `auth ok` / `auth failed`. Whether the click *landed*
is for the caller to check (the page it clicked on).
"""

from __future__ import annotations

import struct
import subprocess
import sys
import time

from Crypto.Cipher import DES


def _key(password: str) -> bytes:
    # VNC's DES key: the first 8 bytes, each byte's bits reversed
    raw = password.encode("latin-1")[:8].ljust(8, b"\0")
    return bytes(int(f"{b:08b}"[::-1], 2) for b in raw)


def main(runtime: str, container: str, secret: str, x: int, y: int) -> int:
    pw = subprocess.run([runtime, "exec", container, "cat", f"/tmp/vnc/{secret}"],
                        capture_output=True, text=True, check=True).stdout.strip()
    p = subprocess.Popen([runtime, "exec", "-i", container, "socat", "STDIO", "TCP4:127.0.0.1:5900"],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    r, w = p.stdout, p.stdin

    def read(n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = r.read(n - len(buf))
            if not chunk:
                raise EOFError("server closed the connection")
            buf += chunk
        return buf

    def send(data: bytes) -> None:
        w.write(data)
        w.flush()

    try:
        assert read(12).startswith(b"RFB ")
        send(b"RFB 003.008\n")
        types = read(read(1)[0])
        if 2 not in types:
            print(f"no VncAuth offered: {list(types)}")
            return 1
        send(b"\x02")
        challenge = read(16)
        send(DES.new(_key(pw), DES.MODE_ECB).encrypt(challenge))
        if struct.unpack(">I", read(4))[0] != 0:
            print("auth failed")
            return 1
        print("auth ok")
        send(b"\x01")  # ClientInit: shared
        _w, _h = struct.unpack(">HH", read(4))
        read(16)  # pixel format
        read(struct.unpack(">I", read(4))[0])  # desktop name
        for mask in (0, 1, 0):  # move, press, release
            send(struct.pack(">BBHH", 5, mask, x, y))
            time.sleep(0.2)
        time.sleep(0.5)
        return 0
    finally:
        p.kill()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5])))
