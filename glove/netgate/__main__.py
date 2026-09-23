"""``python -m netgate forward|collect`` — the gate container entrypoint."""

from __future__ import annotations

import argparse
import asyncio
import os
import signal
import sys

from . import EVENTS_SOCKET, GATE_VERSION, NET_DIR


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="netgate")
    p.add_argument("--version", action="version", version=GATE_VERSION)
    sub = p.add_subparsers(dest="role", required=True)

    f = sub.add_parser("forward", help="instrumented TCP forwarder (one per service)")
    f.add_argument("--service", required=True)
    f.add_argument("--listen", type=int, required=True, help="listen port")
    f.add_argument("--upstream", required=True, help="tcp:<host>:<port>")
    f.add_argument("--env", required=True)
    f.add_argument("--session", required=True)
    f.add_argument("--tool", default=None)
    f.add_argument("--scope", default="local", choices=["local", "tunnelled", "direct"])
    f.add_argument("--resolve", default="in-tunnel", choices=["in-tunnel", "none"])
    f.add_argument("--ingress-alias", default=None)
    f.add_argument("--events", default=EVENTS_SOCKET)

    c = sub.add_parser("collect", help="single writer of net/ (network_mode: none)")
    c.add_argument("--net-dir", default=NET_DIR)
    c.add_argument("--events", default=EVENTS_SOCKET)
    return p


def _parse_upstream(value: str) -> tuple[str, int]:
    scheme, _, rest = value.partition(":")
    host, _, port = rest.rpartition(":")
    if scheme != "tcp" or not host or not port.isdigit():
        raise SystemExit(f"netgate: unsupported upstream {value!r} (M1 supports tcp:<host>:<port>)")
    return host, int(port)


async def _run_forward(args) -> None:
    from .forward import EventSink, Forwarder, ForwardSpec

    host, port = _parse_upstream(args.upstream)
    spec = ForwardSpec(
        service=args.service,
        listen_port=args.listen,
        upstream_host=host,
        upstream_port=port,
        env=args.env,
        session=args.session,
        tool=args.tool,
        scope=args.scope,
        resolve=args.resolve,
        ingress_alias=args.ingress_alias,
    )
    sink = EventSink(args.events)
    fwd = Forwarder(spec, sink)
    stop = _stop_event()
    await fwd.start()
    print(f"netgate {GATE_VERSION}: forward {args.service} :{args.listen} -> {args.upstream}", flush=True)
    await stop.wait()
    await fwd.stop()
    sink.close()


async def _run_collect(args) -> None:
    from .collector import Collector

    os.umask(0o077)
    collector = Collector(args.net_dir, args.events)
    print(f"netgate {GATE_VERSION}: collect -> {args.net_dir}", flush=True)
    await collector.run(_stop_event())


def _stop_event() -> asyncio.Event:
    # PID 1 in a container ignores SIGTERM unless a handler is installed.
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    return stop


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    runner = _run_forward if args.role == "forward" else _run_collect
    asyncio.run(runner(args))
    return 0


if __name__ == "__main__":
    sys.exit(main())
