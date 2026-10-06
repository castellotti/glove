"""A `via: lan` target is dialled only at a private IPv4 address. Core's
`lan_host` (plan time), the socat forwarder's entry script and netgate's
`--lan-only` (run time) each spell the private ranges — netgate and the script
ship in images without glove — so one table, derived from core's ranges, checks
all three."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import subprocess
from pathlib import Path

import pytest

from extensions.gate.netgate import forward
from glove.extensions import LAN_NETWORKS, lan_host
from glove.plan import FORWARDER_DIR


def _edges() -> list[tuple[str, bool]]:
    """Each range's first and last address, and the addresses just outside."""
    out = []
    for n in LAN_NETWORKS:
        for ip in (n.network_address, n.broadcast_address):
            out.append((str(ip), True))
        for ip in (n.network_address - 1, n.broadcast_address + 1):
            out.append((str(ip), any(ip in m for m in LAN_NETWORKS)))
    return [*out, ("127.0.0.1", False), ("100.64.0.1", False), ("93.184.216.34", False)]


EDGES = _edges()


def test_netgate_spells_the_same_ranges():
    assert forward.LAN_NETWORKS == LAN_NETWORKS


@pytest.mark.parametrize(("ip", "ok"), EDGES)
def test_lan_host(ip, ok):
    assert lan_host(ip) is ok


def _script(tmp_path: Path, answer: str) -> subprocess.CompletedProcess:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "getent").write_text(f"#!/bin/sh\n[ -n '{answer}' ] && echo '{answer} STREAM'\n")
    (bin_dir / "socat").write_text("#!/bin/sh\necho socat \"$@\"\n")
    for f in bin_dir.iterdir():
        f.chmod(0o755)
    return subprocess.run(["sh", str(FORWARDER_DIR / "lan-forward"), "22", "nas.lan", "2222"],
                          capture_output=True, text=True, env={"PATH": f"{bin_dir}:/usr/bin:/bin"})


@pytest.mark.parametrize(("ip", "ok"), [*EDGES, ("", False)])
def test_the_socat_entry_script(tmp_path, ip, ok):
    out = _script(tmp_path, ip)
    if ok:
        assert out.returncode == 0, out.stderr
        assert out.stdout.strip() == f"socat TCP4-LISTEN:22,fork,reuseaddr TCP4:{ip}:2222"
    else:
        assert out.returncode == 1 and "socat" not in out.stdout
        assert "not a private IPv4 address" in out.stderr


@pytest.mark.parametrize(("ip", "ok"), EDGES)
def test_netgate_lan_only(monkeypatch, ip, ok):
    async def resolve():
        loop = asyncio.get_running_loop()

        async def getaddrinfo(host, port, **kw):
            assert host == "nas.lan" and kw["family"] == socket.AF_INET
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]

        monkeypatch.setattr(loop, "getaddrinfo", getaddrinfo)
        return await forward.lan_address("nas.lan", 22)

    if ok:
        assert ipaddress.ip_address(asyncio.run(resolve())) == ipaddress.ip_address(ip)
    else:
        with pytest.raises(forward.NotLan, match="not a private IPv4 address"):
            asyncio.run(resolve())
