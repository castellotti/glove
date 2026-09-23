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
    f.add_argument("--mode", default="tcp", choices=["tcp", "http-proxy"])
    f.add_argument("--upstream", required=True, help="tcp:<host>:<port> | chain:http://<host>:<port>")
    f.add_argument("--route", default="tcp", choices=["tcp", "vpn", "tor", "direct"])
    f.add_argument("--no-sni", action="store_true", help="tcp mode: don't peek the ClientHello")
    f.add_argument("--env", required=True)
    f.add_argument("--session", required=True)
    f.add_argument("--tool", default=None)
    f.add_argument("--scope", default="local", choices=["local", "tunnelled", "direct"])
    f.add_argument("--resolve", default="in-tunnel", choices=["in-tunnel", "none"])
    f.add_argument("--ingress-alias", default=None)
    f.add_argument("--events", default=EVENTS_SOCKET)
    f.add_argument("--rules", default=None, help="rules.json path (in a read-only mount)")

    c = sub.add_parser("collect", help="single writer of net/ (network_mode: none)")
    c.add_argument("--net-dir", default=NET_DIR)
    c.add_argument("--events", default=EVENTS_SOCKET)
    c.add_argument("--rules", default=None, help="rules.json path, for status.json's load result")
    return p


def _parse_upstream(value: str, mode: str) -> tuple[str, int]:
    prefix = "chain:http://" if mode == "http-proxy" else "tcp:"
    host, _, port = value.removeprefix(prefix).rstrip("/").rpartition(":")
    if not value.startswith(prefix) or not host or not port.isdigit():
        raise SystemExit(f"netgate: {mode} mode needs upstream {prefix}<host>:<port>, got {value!r}")
    return host, int(port)


async def _run_forward(args) -> None:
    from .forward import EventSink, Forwarder, ForwardSpec

    host, port = _parse_upstream(args.upstream, args.mode)
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
        mode=args.mode,
        route_kind=args.route,
        sni=not args.no_sni,
    )
    sink = EventSink(args.events)
    policy = None
    if args.rules:
        from pathlib import Path

        from .policy import PolicyWatcher

        policy = PolicyWatcher(Path(args.rules), env=args.env, session=args.session)
    fwd = Forwarder(spec, sink, policy=policy)
    stop = _stop_event()
    await fwd.start()
    print(f"netgate {GATE_VERSION}: forward {args.service} ({args.mode}) :{args.listen} -> {args.upstream}",
          flush=True)
    await stop.wait()
    await fwd.stop()
    sink.close()


async def _run_collect(args) -> None:
    from .collector import Collector

    os.umask(0o077)
    collector = Collector(args.net_dir, args.events, rules_path=args.rules)
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
