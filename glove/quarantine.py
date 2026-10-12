"""macOS quarantine for what a session's sidecars saved (`outputs:`, e.g.
web_download's and the browser's downloads).

A file written through a bind carries no `com.apple.quarantine` attribute, so
Gatekeeper would never vet one the operator opens from Finder. `glove down`
and `glove downloads mark` stamp it host-side, as a browser does. A link is
never followed (a sidecar could plant one pointing anywhere, or swap a
directory for one mid-walk while the session runs): the walk holds each
directory open (`os.fwalk`), opens each entry relative to it with O_NOFOLLOW
and stamps the open descriptor, so no path is resolved twice. A file already
stamped keeps its attribute (XATTR_CREATE), so the operator's approval of one
survives. A no-op off macOS.
"""

from __future__ import annotations

import ctypes
import errno
import os
import stat
import sys
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

ATTR = b"com.apple.quarantine"
# <flags>;<hex time>;<agent>;<event id>: 0081 = downloaded, not yet approved (as Chrome writes it)
_FLAGS = "0081"
_XATTR_CREATE = 0x0002


@dataclass
class Marked:
    stamped: int = 0
    already: int = 0
    failed: list[tuple[Path, str]] = field(default_factory=list)


def supported() -> bool:
    return sys.platform == "darwin"


def mark(dirs: Iterable[Path]) -> Marked:
    """Stamp every file and directory under `dirs` (not the dirs themselves)."""
    out = Marked()
    if not supported():
        return out
    libc = ctypes.CDLL(None, use_errno=True)
    libc.fsetxattr.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t,
                               ctypes.c_uint32, ctypes.c_int]
    value = f"{_FLAGS};{int(time.time()):08x};glove;".encode()
    for d in dirs:
        if d.is_symlink() or not d.is_dir():
            continue
        # fwalk never follows a link, even one swapped in after the listing
        for root, dirnames, filenames, dirfd in os.fwalk(d):
            for name in (*dirnames, *filenames):
                try:
                    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dirfd)
                except OSError as e:
                    if e.errno != errno.ELOOP:  # ELOOP: a link, never followed
                        out.failed.append((Path(root, name), e.strerror or str(e)))
                    continue
                try:
                    if not stat.S_ISREG(m := os.fstat(fd).st_mode) and not stat.S_ISDIR(m):
                        continue  # a fifo, a socket, …
                    if libc.fsetxattr(fd, ATTR, value, len(value), 0, _XATTR_CREATE) == 0:
                        out.stamped += 1
                    elif (e := ctypes.get_errno()) == errno.EEXIST:
                        out.already += 1
                    else:
                        out.failed.append((Path(root, name), os.strerror(e)))
                finally:
                    os.close(fd)
    return out
