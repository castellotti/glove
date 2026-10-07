"""glove `llm-auth`: the only holder of the session's LLM key.

The harness reaches its model through this sidecar (via the `llm` forwarder)
with a dummy key. For every request it:

- checks the method and path against an allowlist (the API's inference paths,
  the model list and the catalog's probe); anything else is a 403;
- drops the client's credentials (`Authorization`, `x-api-key`, `api-key`) and
  hop-by-hop headers, sets `Host` to the upstream's, and adds the real key in
  the provider's header;
- relays the request to the upstream forwarder (TLS to the provider's name when
  `LLM_AUTH_TLS_NAME` is set, certificate verified) and streams the answer back
  unbuffered (server-sent events).

Each request is parsed by the server, keep-alive included, so a second request
on one connection is checked like the first. A chunked request body is refused
(411). Logs name the method, path and status, never a header value.

With `LLM_AUTH_SERVE_TLS=1` (a Claude Code subscription, which must reach the
provider by its real name) it also serves TLS as `LLM_AUTH_TLS_NAME`: at start
it makes a session CA that may sign only that name (name constraints), signs a
leaf with it and deletes the CA key at once, then the leaf key once loaded
(both on its tmpfs). The CA certificate goes to `LLM_AUTH_CA_DIR/ca.pem` (a
read-only channel for the harness, which trusts it) before it listens.

Settings (env): LLM_AUTH_KEY (from glove at `compose up`, in memory),
LLM_AUTH_UPSTREAM (host:port), LLM_AUTH_TLS_NAME, LLM_AUTH_HOST,
LLM_AUTH_HEADER, LLM_AUTH_SCHEME, LLM_AUTH_ALLOW (JSON [[method, path], …];
`{model}` matches a model id, which may hold `/`: `publisher/model`), LLM_AUTH_PORT,
LLM_AUTH_SERVE_TLS, LLM_AUTH_CA_DIR.
"""

from __future__ import annotations

import contextlib
import http.client
import json
import os
import re
import ssl
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Never forwarded: the client's credentials (the harness holds a dummy) and
# hop-by-hop headers (RFC 9110 §7.6.1), which belong to one connection.
DROP = frozenset({
    "authorization", "x-api-key", "api-key", "proxy-authorization", "proxy-connection", "connection",
    "keep-alive", "te", "trailer", "transfer-encoding", "upgrade", "host", "content-length",
})
RESPONSE_DROP = frozenset({"connection", "keep-alive", "transfer-encoding", "trailer", "upgrade",
                           "proxy-authenticate", "content-length"})
MAX_BODY = 64 * 1024 * 1024  # a long conversation with images stays well below this
MAX_CONCURRENT = 32
CLIENT_IDLE = 120  # seconds a kept-alive client may sit between requests
UPSTREAM_TIMEOUT = 600  # per read: a slow model may think for minutes between tokens
CHUNK = 64 * 1024


class Config:
    def __init__(self, env: dict[str, str]):
        self.key = env.get("LLM_AUTH_KEY", "")
        if not self.key:
            raise SystemExit("llm-auth: LLM_AUTH_KEY is empty")
        host, _, port = env["LLM_AUTH_UPSTREAM"].rpartition(":")
        self.upstream = (host, int(port))
        self.tls_name = env.get("LLM_AUTH_TLS_NAME") or None
        self.tls = ssl.create_default_context() if self.tls_name else None  # the image's CA store, verify on
        # the last TLS session, resumed by the next connection (one handshake's
        # round trips and key exchange fewer per request)
        self.tls_session: ssl.SSLSession | None = None
        self.host = env["LLM_AUTH_HOST"]
        self.header = env["LLM_AUTH_HEADER"]
        scheme = env.get("LLM_AUTH_SCHEME", "")
        self.value = f"{scheme} {self.key}" if scheme else self.key
        self.allow = [(m.upper(), _pattern(p)) for m, p in json.loads(env["LLM_AUTH_ALLOW"])]
        self.port = int(env.get("LLM_AUTH_PORT", "8080"))
        # serves TLS as the provider's own name (LLM_AUTH_TLS_NAME)
        self.serve_tls = self.tls_name if env.get("LLM_AUTH_SERVE_TLS") else None
        self.ca_dir = env.get("LLM_AUTH_CA_DIR", "")
        if env.get("LLM_AUTH_SERVE_TLS") and not (self.tls_name and self.ca_dir):
            raise SystemExit("llm-auth: LLM_AUTH_SERVE_TLS needs LLM_AUTH_TLS_NAME and LLM_AUTH_CA_DIR")

    def allowed(self, method: str, path: str) -> bool:
        return any(m == method and p.fullmatch(path) for m, p in self.allow)


def _pattern(path: str) -> re.Pattern[str]:
    return re.compile("[^?#]+".join(re.escape(part) for part in path.split("{model}")))


CA_DAYS = 365  # its key is gone once the leaf is signed: nothing can mint more
EC = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes"]


def _openssl(cwd: str, *args: str) -> None:
    r = subprocess.run(["openssl", *args], cwd=cwd, capture_output=True, text=True)
    if r.returncode:
        raise SystemExit(f"llm-auth: openssl {args[0]} failed: {r.stderr.strip()[-300:]}")


def server_tls(name: str, ca_dir: str) -> ssl.SSLContext:
    """A TLS context serving `name` with a leaf from a fresh session CA that
    may sign `name` only; publishes the CA certificate to `ca_dir/ca.pem`.
    Both keys exist only on this container's tmpfs, and only until loaded."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    with tempfile.TemporaryDirectory(prefix="llm-auth-") as d:
        _openssl(d, "req", "-x509", *EC, "-keyout", "ca.key", "-out", "ca.pem", "-days", str(CA_DAYS),
                 "-subj", "/CN=glove session CA", "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                 "-addext", "keyUsage=critical,keyCertSign",
                 "-addext", f"nameConstraints=critical,permitted;DNS:{name}")
        _openssl(d, "req", "-x509", *EC, "-keyout", "leaf.key", "-out", "leaf.pem", "-days", str(CA_DAYS),
                 "-subj", f"/CN={name}", "-CA", "ca.pem", "-CAkey", "ca.key",
                 "-addext", f"subjectAltName=DNS:{name}", "-addext", "extendedKeyUsage=serverAuth",
                 "-addext", "basicConstraints=critical,CA:FALSE")
        os.remove(os.path.join(d, "ca.key"))  # the leaf is signed: the CA can sign nothing more
        ctx.load_cert_chain(os.path.join(d, "leaf.pem"), os.path.join(d, "leaf.key"))
        with open(os.path.join(d, "ca.pem"), "rb") as f:
            pem = f.read()
    tmp = os.path.join(ca_dir, ".ca.pem")
    with open(tmp, "wb") as f:
        f.write(pem)
    os.chmod(tmp, 0o644)
    os.replace(tmp, os.path.join(ca_dir, "ca.pem"))  # a reader never sees half a file
    return ctx


class _TLSConnection(http.client.HTTPConnection):
    """HTTPS to the forwarder's address, with SNI and the certificate checked
    against the provider's name (the forwarder only relays TCP)."""

    def __init__(self, host: str, port: int, cfg: Config, timeout: float):
        super().__init__(host, port, timeout=timeout)
        self.cfg = cfg

    def connect(self) -> None:
        super().connect()
        cfg = self.cfg
        self.sock = cfg.tls.wrap_socket(self.sock, server_hostname=cfg.tls_name, session=cfg.tls_session)
        cfg.tls_session = self.sock.session


def make_handler(cfg: Config, gate: threading.BoundedSemaphore) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        timeout = CLIENT_IDLE
        server_version = "glove-llm-auth"
        sys_version = ""

        def log_message(self, fmt, *args):  # the access log below names no header values
            pass

        def handle(self) -> None:
            with contextlib.suppress(ConnectionResetError, BrokenPipeError):  # the client went away
                if isinstance(self.connection, ssl.SSLSocket):
                    try:  # here, in the connection's thread, under its timeout
                        self.connection.do_handshake()
                    except (ssl.SSLError, OSError) as e:
                        print(f"llm-auth: tls handshake failed ({type(e).__name__})", flush=True)
                        return
                super().handle()

        def _log(self, status: int, note: str = "") -> None:
            path = self.path.split("?", 1)[0]
            print(f"llm-auth: {self.command} {path} {status}{' ' + note if note else ''}", flush=True)

        def _refuse(self, status: int, text: str) -> None:
            body = (text + "\n").encode()
            self.send_response(status)
            self.send_header("content-type", "text/plain; charset=utf-8")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
            self._log(status, text)

        def _handle(self) -> None:
            path = self.path.split("?", 1)[0]
            if not self.path.startswith("/") or not cfg.allowed(self.command, path):
                self.close_connection = True  # its body is unread: the connection can't be reused
                return self._refuse(403, f"glove llm-auth: {self.command} {path} is not an inference path")
            if "transfer-encoding" in self.headers:
                self.close_connection = True
                return self._refuse(411, "glove llm-auth: send a content-length body")
            try:
                length = int(self.headers.get("content-length") or 0)
            except ValueError:
                length = -1
            if length < 0 or length > MAX_BODY:
                self.close_connection = True
                return self._refuse(413, "glove llm-auth: bad or oversized body")
            body = self.rfile.read(length) if length else None
            if not gate.acquire(blocking=False):
                return self._refuse(503, "glove llm-auth: too many requests in flight")
            try:
                self._relay(body)
            finally:
                gate.release()

        def _relay(self, body: bytes | None) -> None:
            drop = DROP | {h.strip().lower() for h in self.headers.get("connection", "").split(",")}
            headers = {k: v for k, v in self.headers.items() if k.lower() not in drop}
            headers["Host"] = cfg.host
            headers[cfg.header] = cfg.value
            if body is not None:
                headers["Content-Length"] = str(len(body))
            host, port = cfg.upstream
            conn = (_TLSConnection(host, port, cfg, UPSTREAM_TIMEOUT) if cfg.tls
                    else http.client.HTTPConnection(host, port, timeout=UPSTREAM_TIMEOUT))
            try:
                conn.request(self.command, self.path, body=body, headers=headers)
                resp = conn.getresponse()
            except (OSError, http.client.HTTPException) as e:
                conn.close()
                return self._refuse(502, f"glove llm-auth: upstream unreachable ({type(e).__name__})")
            try:
                self._answer(resp)
            finally:
                conn.close()

        def _answer(self, resp: http.client.HTTPResponse) -> None:
            self.send_response(resp.status, resp.reason)
            for k, v in resp.getheaders():
                if k.lower() not in RESPONSE_DROP:
                    self.send_header(k, v)
            bodyless = self.command == "HEAD" or resp.status in (204, 304) or 100 <= resp.status < 200
            if bodyless:
                self.send_header("content-length", "0")
                self.end_headers()
                return self._log(resp.status)
            self.send_header("transfer-encoding", "chunked")
            self.end_headers()
            try:
                while chunk := resp.read1(CHUNK):
                    self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
                    self.wfile.flush()
                self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()
            except (OSError, http.client.HTTPException):
                self.close_connection = True  # the stream broke mid-answer: never reuse this connection
            self._log(resp.status)

        do_GET = do_POST = do_HEAD = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _handle

    return Handler


def serve(cfg: Config, host: str = "0.0.0.0") -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, cfg.port), make_handler(cfg, threading.BoundedSemaphore(MAX_CONCURRENT)))
    server.daemon_threads = True
    if cfg.serve_tls:
        ctx = server_tls(cfg.serve_tls, cfg.ca_dir)
        # the handshake runs in each connection's thread (`handle`), not in accept()
        server.socket = ctx.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
    return server


def main() -> None:
    cfg = Config(dict(os.environ))
    server = serve(cfg)
    via = f"tls {cfg.tls_name}" if cfg.tls_name else "http"
    listen = f"tls {cfg.serve_tls}" if cfg.serve_tls else "http"
    print(f"llm-auth: :{cfg.port} ({listen}) → {cfg.upstream[0]}:{cfg.upstream[1]} ({via}), "
          f"{len(cfg.allow)} allowed paths", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
