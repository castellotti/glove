#!/usr/bin/env python3
"""relayd — the sidecar half of a glove relay.

A relay runs a few named commands (e.g. `gh`, `git push`) on the harness's
behalf, in a sidecar that holds the credential, so neither the credential nor a
network route ever enters the sandbox. The harness side is `glove-relay`, a
bash client; the two meet in a *channel*: a directory (session tmpfs) mounted
at the same path in the harness and here. There is no socket: glove's seccomp
filter below srt forbids creating Unix sockets, so a request is files and
FIFOs, which every enforcer allows.

Protocol (one request):
  client  mkdir <channel>/req/<id>/ (0700), writes `argv` (NUL-terminated
          words) and `cwd`, makes FIFOs `1`, `2` and `rc`, writes "<id>\\n" to
          <channel>/door, then reads `1` → stdout, `2` → stderr, `rc` → exit code.
  relayd  reads ids from the door, opens the request dir without following
          links, asks the policy for the command to run (or a refusal), runs it
          with stdout/stderr on the FIFOs and stdin on /dev/null, and writes the
          exit code. Relayed commands get no stdin: a body or input goes in a
          file under /work.

The policy (`--policy`, a Python file loaded by path, owned by the consuming
extension) names its commands (`COMMANDS`), validates every argv (`prepare`,
raising its own `Refused` with the message to show), builds the children's
environment (`setup`) and names the hosts the egress fence lets through
(`HOSTS`; none: no fence and no proxy, e.g. ssh, whose only routes are its
per-host forwarders). relayd itself holds no credential knowledge.

Egress fence: children reach the network only through an in-process CONNECT
proxy on 127.0.0.1 that tunnels to the session's egress proxy (`--upstream`)
and refuses every host the policy does not name, whatever argv got through.

Standard library only.
"""

from __future__ import annotations

import argparse
import contextlib
import errno
import fcntl
import importlib.util
import json
import os
import re
import select
import shutil
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
import urllib.parse
from types import ModuleType

ID = re.compile(r"[0-9a-f]{16,64}")
MAX_SMALL = 256 * 1024  # argv / cwd files
MAX_FILE = 16 * 1024 * 1024  # a file argument (a PR body, an API query)
OPEN_DEADLINE = 10.0  # seconds for the client to open its FIFO ends
HEAD_TIMEOUT = 10.0  # seconds for a fence client to send its CONNECT request
REFUSED_RC = 126


class Refused(Exception):
    """The policy (or relayd) will not run this request; the message is shown."""


def log(msg: str) -> None:
    print(f"relayd: {msg}", flush=True)


def within(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


# --- one request -----------------------------------------------------------------


class Request:
    """What a policy sees: the argv, the (resolved) cwd under the work root, and
    helpers that open file arguments race-free inside it."""

    def __init__(self, argv: list[str], cwd_fd: int, work: str, settings: dict):
        self.argv = argv
        self.work = work
        self.settings = settings
        self.cwd_fd = cwd_fd
        self.cwd = os.readlink(f"/proc/self/fd/{cwd_fd}")
        self.fds: list[int] = [cwd_fd]

    def _abs(self, path: str) -> str:
        return path if path.startswith("/") else os.path.join(self.cwd, path)

    def file(self, path: str) -> str:
        """Open a file argument read-only and return `/dev/fd/<n>` for the child.
        What is checked is what was opened (its /proc link), so swapping in a
        symlink after the check changes nothing."""
        if path == "-":
            raise Refused("relayed commands get no stdin: write it to a file under /work and pass its path")
        if not self.work:
            raise Refused("this relay takes no file arguments")
        try:
            fd = os.open(self._abs(path), os.O_RDONLY | os.O_NOCTTY | os.O_NONBLOCK)
        except OSError as e:
            raise Refused(f"cannot open {path}: {e.strerror}") from None
        real = os.readlink(f"/proc/self/fd/{fd}")
        st = os.fstat(fd)
        if not within(real, self.work) or not stat.S_ISREG(st.st_mode) or st.st_size > MAX_FILE:
            os.close(fd)
            raise Refused(f"{path}: a file argument must be a regular file under {self.work} "
                          f"(at most {MAX_FILE // (1024 * 1024)} MiB)")
        fcntl.fcntl(fd, fcntl.F_SETFL, fcntl.fcntl(fd, fcntl.F_GETFL) & ~os.O_NONBLOCK)
        self.fds.append(fd)
        return f"/dev/fd/{fd}"

    def directory(self, path: str) -> str:
        """A destination directory (it may not exist yet) under the work root,
        as an absolute real path."""
        real = os.path.realpath(self._abs(path))
        if not self.work or not within(real, self.work):
            raise Refused(f"{path}: a destination must be under {self.work}")
        return real

    def close(self) -> None:
        for fd in self.fds:
            with contextlib.suppress(OSError):
                os.close(fd)


def _read_small(dfd: int, name: str) -> bytes:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_SMALL:
            raise Refused(f"bad request file {name}")
        return os.read(fd, MAX_SMALL)
    finally:
        os.close(fd)


def _open_fifo(dfd: int, name: str, deadline: float) -> int:
    """The write end of a client FIFO, once the client has opened its read end."""
    while True:
        try:
            fd = os.open(name, os.O_WRONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=dfd)
            break
        except OSError as e:
            if e.errno != errno.ENXIO or time.monotonic() > deadline:
                raise
            time.sleep(0.02)
    if not stat.S_ISFIFO(os.fstat(fd).st_mode):
        os.close(fd)
        raise OSError(errno.EINVAL, f"{name} is not a FIFO")
    fcntl.fcntl(fd, fcntl.F_SETFL, fcntl.fcntl(fd, fcntl.F_GETFL) & ~os.O_NONBLOCK)
    return fd


def _reader_gone(fd: int) -> bool:
    p = select.poll()
    p.register(fd, select.POLLOUT)
    return any(ev & (select.POLLERR | select.POLLHUP) for _, ev in p.poll(0))


class Relay:
    def __init__(self, channel: str, policy: ModuleType, env: dict[str, str], *, work: str, settings: dict,
                 timeout: int, max_active: int):
        self.channel = channel
        self.policy = policy
        self.env = env
        self.work = work  # "": a relay without a work root (ssh)
        self.settings = settings
        self.timeout = timeout
        self.slots = threading.BoundedSemaphore(max_active)
        # requests still waiting for the client to open its FIFOs: each holds a
        # thread for up to OPEN_DEADLINE, so a flood of ids is bounded here
        self.pending = threading.BoundedSemaphore(max_active * 4)
        self.refused = getattr(policy, "Refused", Refused)  # the policy's own refusal type

    def dispatch(self, rid: str) -> None:
        """Handle one request id from the door on its own thread, or drop it
        when too many requests are still opening their FIFOs."""
        if not self.pending.acquire(blocking=False):
            log(f"{rid[:8]}: dropped (too many requests waiting to start)")
            shutil.rmtree(os.path.join(self.channel, "req", rid), ignore_errors=True)
            return
        threading.Thread(target=self.handle, args=(rid,), daemon=True).start()

    def handle(self, rid: str) -> None:
        dfd = out = err = rcf = -1
        req: Request | None = None
        rc = REFUSED_RC
        what = "?"
        pending = True
        try:
            dfd = os.open(os.path.join(self.channel, "req", rid), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            if os.fstat(dfd).st_uid != os.getuid():
                return
            deadline = time.monotonic() + OPEN_DEADLINE
            # one at a time, so `finally` closes whichever opened before a failure
            out = _open_fifo(dfd, "1", deadline)
            err = _open_fifo(dfd, "2", deadline)
            rcf = _open_fifo(dfd, "rc", deadline)
            self.pending.release()
            pending = False
            if not self.slots.acquire(blocking=False):
                os.write(err, b"glove relay: busy (too many relayed commands at once); try again\n")
                return
            try:
                argv = [w.decode("utf-8", "surrogateescape") for w in _read_small(dfd, "argv").split(b"\0")[:-1]]
                cwd = _read_small(dfd, "cwd").decode("utf-8", "surrogateescape").rstrip("\n")
                what = " ".join(argv[:2])
                req = self._request(argv, cwd)
                rc = self._run(req, out, err)
            finally:
                self.slots.release()
        except (Refused, self.refused) as e:
            with contextlib.suppress(OSError):
                os.write(err, f"glove relay: refused: {e}\n".encode())
        except OSError as e:
            log(f"{rid[:8]}: dropped ({e})")
            return
        finally:
            if pending:
                self.pending.release()
            if req is not None:
                req.close()
            if rcf >= 0:
                with contextlib.suppress(OSError):
                    os.write(rcf, f"{rc}\n".encode())
            for fd in (out, err, rcf, dfd):
                if fd >= 0:
                    with contextlib.suppress(OSError):
                        os.close(fd)
            if dfd >= 0:  # the client's own cleanup does not run when it is killed
                shutil.rmtree(os.path.join(self.channel, "req", rid), ignore_errors=True)
        log(f"{rid[:8]}: {what} -> {rc}")

    def _request(self, argv: list[str], cwd: str) -> Request:
        if not argv or argv[0] not in self.policy.COMMANDS:
            raise Refused(f"this relay runs only {sorted(self.policy.COMMANDS)}")
        if not self.work:  # commands run in /tmp, and Request refuses file arguments
            return Request(argv, os.open("/tmp", os.O_RDONLY | os.O_DIRECTORY), "", self.settings)
        try:
            cfd = os.open(cwd if cwd.startswith("/") else self.work, os.O_RDONLY | os.O_DIRECTORY)
        except OSError:
            cfd = os.open(self.work, os.O_RDONLY | os.O_DIRECTORY)
        if not within(os.readlink(f"/proc/self/fd/{cfd}"), self.work):
            os.close(cfd)
            cfd = os.open(self.work, os.O_RDONLY | os.O_DIRECTORY)
        return Request(argv, cfd, self.work, self.settings)

    def _run(self, req: Request, out: int, err: int) -> int:
        argv = self.policy.prepare(req, dict(self.env))
        # the child changes into the very directory that was checked (its fd)
        p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=err, env=self.env,
                             cwd=f"/proc/self/fd/{req.cwd_fd}", pass_fds=tuple(req.fds), start_new_session=True)
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                rc = p.wait(timeout=0.5)
                return rc if rc >= 0 else 128 - rc
            except subprocess.TimeoutExpired:
                pass
            late = time.monotonic() > deadline
            if late or _reader_gone(out):
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(p.pid, signal.SIGKILL)
                p.wait()
                if late:
                    with contextlib.suppress(OSError):
                        os.write(err, f"glove relay: stopped after {self.timeout}s\n".encode())
                return 124 if late else 130

    def serve(self) -> None:
        req_dir = os.path.join(self.channel, "req")
        os.makedirs(req_dir, mode=0o700, exist_ok=True)
        door = os.path.join(self.channel, "door")
        with contextlib.suppress(FileNotFoundError):
            os.unlink(door)
        os.mkfifo(door, 0o600)
        fd = os.open(door, os.O_RDWR)  # also a writer: never EOF between clients
        log(f"serving {sorted(self.policy.COMMANDS)} on {self.channel}")
        buf = b""
        while True:
            chunk = os.read(fd, 4096)
            buf += chunk
            *lines, buf = buf.split(b"\n")
            buf = buf[-128:]
            for line in lines:
                rid = line.decode("ascii", "replace").strip()
                if ID.fullmatch(rid):
                    self.dispatch(rid)


# --- the egress fence -------------------------------------------------------------


def host_allowed(host: str, hosts) -> bool:
    host = host.lower().rstrip(".")
    return any(host == h or (h.startswith(".") and host.endswith(h)) for h in hosts)


class Fence:
    """CONNECT-only proxy on 127.0.0.1: tunnels to `upstream` (the session's
    egress proxy) for the policy's hosts on port 443, refuses everything else."""

    def __init__(self, upstream: str, hosts):
        u = urllib.parse.urlsplit(upstream)
        self.upstream = (u.hostname, u.port or 80)
        self.hosts = tuple(hosts)
        self.sock = socket.create_server(("127.0.0.1", 0))
        self.url = f"http://127.0.0.1:{self.sock.getsockname()[1]}"
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self) -> None:
        while True:
            conn, _ = self.sock.accept()
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    @staticmethod
    def _head(s: socket.socket) -> bytes:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = s.recv(4096)
            if not chunk or len(data) > 16384:
                break
            data += chunk
        return data

    def _serve(self, c: socket.socket) -> None:
        up = None
        try:
            c.settimeout(HEAD_TIMEOUT)  # a client that never finishes its CONNECT
            head = self._head(c)
            first = head.split(b"\r\n", 1)[0].decode("latin-1").split()
            if len(first) < 2 or first[0] != "CONNECT":
                return self._refuse(c, "only HTTPS (CONNECT) goes through this relay")
            host, _, port = first[1].rpartition(":")
            host = host.strip("[]")
            if port != "443" or not host_allowed(host, self.hosts):
                log(f"fence: refused {first[1]}")
                return self._refuse(c, f"{first[1]} is not a host this relay serves")
            up = socket.create_connection(self.upstream, timeout=30)
            up.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode())
            reply = self._head(up)
            c.sendall(reply)
            if reply.split(b"\r\n", 1)[0].split(b" ")[1:2] != [b"200"]:
                return None
            up.settimeout(None)
            c.settimeout(None)
            self._pipe(c, up)
        except OSError:
            pass
        finally:
            for s in (c, up):
                if s is not None:
                    with contextlib.suppress(OSError):
                        s.close()
        return None

    @staticmethod
    def _refuse(c: socket.socket, why: str) -> None:
        body = f"glove relay refused: {why}\n".encode()
        c.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nConnection: close\r\n"
                  + f"Content-Length: {len(body)}\r\n\r\n".encode() + body)

    @staticmethod
    def _pipe(a: socket.socket, b: socket.socket) -> None:
        peers = {a: b, b: a}
        while True:
            ready, _, _ = select.select(list(peers), [], [], 300)
            if not ready:
                return
            for s in ready:
                data = s.recv(65536)
                if not data:
                    return
                peers[s].sendall(data)


# --- main ------------------------------------------------------------------------


def load_policy(path: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location("relay_policy", path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"relayd: cannot load policy {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="relayd")
    ap.add_argument("--channel", required=True)
    ap.add_argument("--policy", required=True)
    ap.add_argument("--work", default="", help="the work root its commands run in; none by default")
    ap.add_argument("--upstream", default=os.environ.get("RELAY_UPSTREAM", ""))
    ap.add_argument("--timeout", type=int, default=int(os.environ.get("RELAY_TIMEOUT", "600")))
    ap.add_argument("--max", type=int, default=8)
    args = ap.parse_args(argv)
    if args.work and not os.path.isdir(args.work):
        raise SystemExit(f"relayd: the work root {args.work} is not a directory")
    work = os.path.realpath(args.work) if args.work else ""
    policy = load_policy(args.policy)
    settings = json.loads(os.environ.get("RELAY_SETTINGS") or "{}")
    fence = None
    if policy.HOSTS:  # a policy that names no hosts reaches none through a proxy (ssh: its forwarders only)
        if not args.upstream:
            raise SystemExit("relayd: no upstream proxy (--upstream / RELAY_UPSTREAM)")
        fence = Fence(args.upstream, policy.HOSTS)
    env = policy.setup({"proxy": fence.url if fence else None, "settings": settings, "work": work})
    Relay(args.channel, policy, env, work=work, settings=settings,
          timeout=args.timeout, max_active=args.max).serve()


if __name__ == "__main__":
    sys.exit(main())
