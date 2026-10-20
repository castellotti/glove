"""Landlock on a bind mount: does a rule on the mount actually confine *and*
allow the file operations a session needs there?

Run inside a hardened throwaway container (stdlib only, no glove imports):
``python3 landlock_probe.py <dir>...``. Each ``<dir>`` is tested in its own
forked child, which restricts itself with one Landlock rule (full access
beneath that dir) and then creates, writes, reads back, lists, mmaps, locks,
renames, hard-links and unlinks a file there. First, without Landlock, a
control run of the same steps tells a permission problem (file modes, SELinux,
uid mapping) from a Landlock one. Prints one JSON object:
``{"abi": n, "mounts": {dir: {"fstype": t, "control": {...}, "steps": {step: "ok" | error}}}}``.
"""

import ctypes
import fcntl
import json
import mmap
import os
import sys

libc = ctypes.CDLL(None, use_errno=True)
SYS_CREATE, SYS_ADD, SYS_RESTRICT = 444, 445, 446
STEPS = ("create", "write", "read", "list", "mmap", "lock", "rename", "link", "unlink")


class _Ruleset(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class _PathBeneath(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


def abi() -> int:
    r = libc.syscall(SYS_CREATE, None, 0, 1)
    return r if r >= 0 else -ctypes.get_errno()


def fs_access(version: int) -> int:
    bits = (1 << 13) - 1                 # EXECUTE..MAKE_SYM (ABI 1)
    if version >= 2:
        bits |= 1 << 13                  # REFER
    if version >= 3:
        bits |= 1 << 14                  # TRUNCATE
    if version >= 5:
        bits |= 1 << 15                  # IOCTL_DEV
    return bits


def restrict(path: str, version: int) -> None:
    access = fs_access(version)
    rs = _Ruleset(access)
    fd = libc.syscall(SYS_CREATE, ctypes.byref(rs), ctypes.sizeof(rs), 0)
    if fd < 0:
        raise OSError(ctypes.get_errno(), "landlock_create_ruleset")
    parent = os.open(path, os.O_PATH | os.O_CLOEXEC)
    rule = _PathBeneath(access, parent)
    if libc.syscall(SYS_ADD, fd, 1, ctypes.byref(rule), 0) < 0:
        raise OSError(ctypes.get_errno(), "landlock_add_rule")
    os.close(parent)
    if libc.prctl(38, 1, 0, 0, 0) < 0:   # PR_SET_NO_NEW_PRIVS
        raise OSError(ctypes.get_errno(), "prctl")
    if libc.syscall(SYS_RESTRICT, fd, 0) < 0:
        raise OSError(ctypes.get_errno(), "landlock_restrict_self")
    os.close(fd)


def run_steps(path: str) -> dict:
    name = os.path.join(path, f".glove-landlock-probe-{os.getpid()}")
    moved, linked = name + ".moved", name + ".link"
    data = b"glove landlock probe\n"
    out: dict = {}

    def step(key, fn):
        try:
            fn()
            out[key] = "ok"
        except OSError as e:
            out[key] = f"{type(e).__name__}: {e.strerror or e}"

    def create():
        os.close(os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))

    def write():
        with open(name, "wb") as f:
            f.write(data)

    def read():
        with open(name, "rb") as f:
            if f.read() != data:
                raise OSError(0, "read back differs")

    def lst():
        if os.path.basename(name) not in os.listdir(path):
            raise OSError(0, "file not listed")

    def mm():
        with open(name, "rb") as f, mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ) as m:
            if m[:len(data)] != data:
                raise OSError(0, "mmap read differs")

    def lock():
        with open(name, "r+b") as f:
            fcntl.lockf(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.lockf(f, fcntl.LOCK_UN)

    for key, fn in zip(STEPS[:6], (create, write, read, lst, mm, lock), strict=True):
        step(key, fn)
    step("rename", lambda: os.rename(name, moved))
    cur = moved if out["rename"] == "ok" else name
    step("link", lambda: (os.link(cur, linked), os.unlink(linked)))
    step("unlink", lambda: os.unlink(cur))
    return out


def fstype(path: str) -> str:
    """The filesystem type of the mount ``path`` is on (longest mount point)."""
    best, kind = "", "?"
    real = os.path.realpath(path)
    with open("/proc/self/mountinfo") as f:
        for line in f:
            pre, _, post = line.partition(" - ")
            mnt = pre.split()[4]
            if (real == mnt or real.startswith(mnt.rstrip("/") + "/")) and len(mnt) >= len(best):
                best, kind = mnt, post.split()[0]
    return kind


def probe(path: str, version: int) -> dict:
    control = run_steps(path)
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        try:
            restrict(path, version)
            res = run_steps(path)
        except OSError as e:
            res = {"restrict": f"{type(e).__name__}: {e.strerror or e}"}
        os.write(w, json.dumps(res).encode())
        os._exit(0)
    os.close(w)
    chunks = []
    while chunk := os.read(r, 65536):
        chunks.append(chunk)
    os.waitpid(pid, 0)
    return {"fstype": fstype(path), "control": control, "steps": json.loads(b"".join(chunks) or b"{}")}


def main(paths: list[str]) -> None:
    version = abi()
    report: dict = {"abi": version, "mounts": {}}
    for p in paths:
        report["mounts"][p] = probe(p, version) if version > 0 else {"fstype": fstype(p), "steps": {}}
    print(json.dumps(report))


if __name__ == "__main__":
    main(sys.argv[1:])
