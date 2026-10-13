"""A GitHub Enterprise stand-in for test_github_ghes.sh: HTTPS (a throwaway CA),
one token per host name, gh's REST user endpoint and git's smart HTTP (fetch
only) over one bare repository.

    python3 ghes_stub.py <port> <cert.pem> <key.pem> <bare-repo>    (GHES_TOKENS='{"host": "token", …}')

It runs in the relay image (Python and git). Per request it logs the host,
the path and whether the right token came, never the token:
  GET  /api/v3/user                          `Authorization: token <t>` → {"login": "user-<host>"}
  GET  /<o>/<r>.git/info/refs?service=git-upload-pack   Basic auth, the password <t>
  POST /<o>/<r>.git/git-upload-pack                     (likewise)
  GET  /bearer        `Authorization: Bearer <t>` → {"authenticated": true, "token": <t>}
                      (httpbin's echo, for test_skills_relay.sh with CORPORATE=1)
Anything else is a 404, a push (receive-pack) a 403: the relay never sends one.
"""

from __future__ import annotations

import base64
import gzip
import json
import os
import re
import ssl
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKENS: dict[str, str] = json.loads(os.environ.get("GHES_TOKENS") or "{}")
REPO = ""
GIT = re.compile(r"/[\w.-]+/[\w.-]+?(\.git)?/(info/refs|git-upload-pack|git-receive-pack)")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # the per-request line below instead
        pass

    def _host(self) -> str:
        return (self.headers.get("Host") or "").split(":")[0].lower()

    def _token(self) -> str:
        auth = self.headers.get("Authorization") or ""
        kind, _, value = auth.partition(" ")
        if kind.lower() in ("token", "bearer"):
            return value.strip()
        if kind.lower() == "basic":
            try:
                return base64.b64decode(value).decode().partition(":")[2]
            except ValueError:
                return ""
        return ""

    def _send(self, code: int, body: bytes, ctype: str = "application/json", **headers: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in headers.items():
            self.send_header(k.replace("_", "-"), v)
        self.end_headers()
        self.wfile.write(body)

    def _route(self, method: str) -> None:
        host, path = self._host(), self.path.split("?")[0]
        token = self._token()
        ok = host in TOKENS and token == TOKENS[host]
        print(f"{method} {host} {path} auth={'ok' if ok else ('wrong' if token else 'none')}", flush=True)
        if host not in TOKENS:
            return self._send(404, b'{"message": "Not Found"}')
        if path == "/api/v3/user" and method == "GET":
            if not ok:
                return self._send(401, b'{"message": "Bad credentials"}')
            return self._send(200, json.dumps({"login": f"user-{host}"}).encode(), X_OAuth_Scopes="repo")
        if path == "/bearer" and method == "GET":
            if not ok:
                return self._send(401, b'{"authenticated": false}')
            return self._send(200, json.dumps({"authenticated": True, "token": token}).encode())
        m = GIT.fullmatch(path)
        if not m:
            return self._send(404, b'{"message": "Not Found"}')
        if not ok:
            return self._send(401, b"auth needed\n", "text/plain", WWW_Authenticate='Basic realm="ghes"')
        env = {**os.environ, "GIT_PROTOCOL": self.headers.get("Git-Protocol") or ""}
        if m.group(2) == "info/refs":
            if "service=git-upload-pack" not in self.path:
                return self._send(403, b"fetch only\n", "text/plain")
            refs = subprocess.run(["git", "upload-pack", "--stateless-rpc", "--advertise-refs", REPO],
                                  capture_output=True, env=env, check=True).stdout
            head = b"# service=git-upload-pack\n"
            body = b"%04x" % (len(head) + 4) + head + b"0000" + refs
            return self._send(200, body, "application/x-git-upload-pack-advertisement", Cache_Control="no-cache")
        if m.group(2) == "git-receive-pack" or method != "POST":
            return self._send(403, b"fetch only\n", "text/plain")
        data = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if self.headers.get("Content-Encoding") == "gzip":
            data = gzip.decompress(data)
        out = subprocess.run(["git", "upload-pack", "--stateless-rpc", REPO], input=data, capture_output=True,
                             env=env, check=True).stdout
        return self._send(200, out, "application/x-git-upload-pack-result", Cache_Control="no-cache")

    def do_GET(self):  # noqa: N802
        self._route("GET")

    def do_POST(self):  # noqa: N802
        self._route("POST")


def main() -> None:
    global REPO
    port, cert, key, REPO = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    srv = ThreadingHTTPServer(("0.0.0.0", int(port)), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print(f"ghes stub on :{port} for {', '.join(TOKENS)}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
