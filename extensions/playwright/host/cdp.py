"""A host Chrome driven over CDP on a pipe (`--remote-debugging-pipe`).

Chrome reads CDP from fd 3 and writes to fd 4, NUL-delimited JSON. There is
no debugging port, so no other local process can reach the browser (what
Playwright itself does). `glove playwright login` uses it to read the cookies
and localStorage of the browser the operator signed in with.
"""

from __future__ import annotations

import contextlib
import json
import os
import select
import subprocess
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit


class CDPError(RuntimeError):
    pass


class PipeChrome:
    def __init__(self, exe: str, args: list[str]):
        to_chrome, self._to = os.pipe()
        self._from, from_chrome = os.pipe()
        # above 4, so the child's dup2 onto 3 and 4 never clobbers the other end
        a, b = _high(to_chrome), _high(from_chrome)

        def child() -> None:
            os.dup2(a, 3)
            os.dup2(b, 4)

        try:
            self.proc = subprocess.Popen([exe, "--remote-debugging-pipe", *args], pass_fds=(3, 4),
                                         preexec_fn=child, stdin=subprocess.DEVNULL,
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                         start_new_session=True)
        finally:
            for fd in (to_chrome, from_chrome, a, b):
                os.close(fd)
        self._buf = b""
        self._id = 0

    def call(self, method: str, params: dict[str, Any] | None = None, session: str | None = None,
             timeout: float = 15) -> dict[str, Any]:
        """One CDP command's result; events in between are skipped."""
        self._id += 1
        msg: dict[str, Any] = {"id": self._id, "method": method, "params": params or {}}
        if session:
            msg["sessionId"] = session
        try:
            os.write(self._to, json.dumps(msg).encode() + b"\0")
        except OSError as e:
            raise CDPError(f"the browser is gone ({e.strerror})") from e
        deadline = time.monotonic() + timeout
        while True:
            while b"\0" not in self._buf:
                left = deadline - time.monotonic()
                if left <= 0 or not select.select([self._from], [], [], left)[0]:
                    raise CDPError(f"{method}: no answer from the browser")
                chunk = os.read(self._from, 1 << 16)
                if not chunk:
                    raise CDPError("the browser is gone (closed?)")
                self._buf += chunk
            line, self._buf = self._buf.split(b"\0", 1)
            reply = json.loads(line)
            if reply.get("id") == self._id:
                if "error" in reply:
                    raise CDPError(f"{method}: {reply['error'].get('message')}")
                return reply.get("result") or {}

    def close(self) -> None:
        with contextlib.suppress(CDPError):
            self.call("Browser.close", timeout=5)
        try:
            self.proc.wait(10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        for fd in (self._to, self._from):
            with contextlib.suppress(OSError):
                os.close(fd)


def _high(fd: int) -> int:
    """A copy of fd numbered above 4."""
    import fcntl

    return fcntl.fcntl(fd, fcntl.F_DUPFD, 5)


def cookies(chrome: PipeChrome) -> list[dict[str, Any]]:
    """Every cookie of the default browser context, HttpOnly ones included."""
    return chrome.call("Storage.getCookies").get("cookies") or []


def local_storage(chrome: PipeChrome, wanted: Callable[[str], bool]) -> dict[str, dict[str, str]]:
    """origin → its localStorage, for the open tabs whose origin is `wanted`
    (CDP reads an origin's storage only through a frame of it); no other
    tab is touched."""
    out: dict[str, dict[str, str]] = {}
    for t in chrome.call("Target.getTargets").get("targetInfos") or []:
        url = urlsplit(str(t.get("url", "")))
        if t.get("type") != "page" or url.scheme not in ("http", "https") or \
                not wanted(f"{url.scheme}://{url.netloc}"):
            continue
        try:
            session = chrome.call("Target.attachToTarget", {"targetId": t["targetId"], "flatten": True})["sessionId"]
            r = chrome.call("Runtime.evaluate", {"returnByValue": True, "expression":
                            "[location.origin, Object.entries(localStorage)]"}, session)
            chrome.call("Target.detachFromTarget", {"sessionId": session})
        except CDPError:
            continue  # a tab that went away, or an opaque origin
        value = (r.get("result") or {}).get("value")
        if isinstance(value, list) and len(value) == 2 and isinstance(value[0], str) and wanted(value[0]):
            out.setdefault(value[0], {}).update({str(k): str(v) for k, v in value[1]})
    return out
