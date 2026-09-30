"""``python -m netgate forward|collect`` — the gate container entrypoint."""

from __future__ import annotations

import argparse
import asyncio
import os
import signal
import sys

from . import CLIENTS, EVENTS_SOCKET, GATE_VERSION, MODES, NET_DIR, RECORD_MODES, RESOLVE_MODES, ROUTES, SCOPES


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="netgate")
    p.add_argument("--version", action="version", version=GATE_VERSION)
    sub = p.add_subparsers(dest="role", required=True)

    f = sub.add_parser("forward", help="instrumented TCP forwarder (one per service)")
    f.add_argument("--service", required=True)
    f.add_argument("--listen", type=int, required=True, help="listen port")
    f.add_argument("--mode", default="tcp", choices=MODES)
    f.add_argument("--upstream", required=True,
                   help="tcp:<host>:<port> | chain:http://<host>:<port> | direct (http-proxy: dial itself)")
    f.add_argument("--route", default="tcp", choices=("tcp", *ROUTES))
    f.add_argument("--no-sni", action="store_true", help="tcp mode: don't peek the ClientHello")
    f.add_argument("--env", required=True)
    f.add_argument("--session", required=True)
    f.add_argument("--tool", default=None)
    f.add_argument("--scope", default="local", choices=SCOPES)
    f.add_argument("--resolve", default="in-tunnel", choices=RESOLVE_MODES)
    f.add_argument("--ingress-alias", default=None)
    f.add_argument("--events", default=EVENTS_SOCKET)
    f.add_argument("--rules", default=None, help="rules.json path (in a read-only mount)")
    f.add_argument("--resolver", default=None, help="in-tunnel resolver: dns://h:p | tor-socks://h:p")
    f.add_argument("--exit-url", default=None, help="https IP-echo URL polled through the chain")
    f.add_argument("--client", default="unknown", choices=CLIENTS,
                   help="label for connections that did not arrive on the harness ingress")
    f.add_argument("--record", default="metadata", choices=RECORD_MODES)
    f.add_argument("--record-headers", action="store_true")
    # Operator-configured guard exceptions (the corporate allowlist). Only ever
    # from the command line — rules.json has no key that could widen the guard.
    f.add_argument("--guard-allow-host", action="append", default=[], help="host glob the SSRF guard lets through")
    f.add_argument("--guard-allow-cidr", action="append", default=[], help="private CIDR the SSRF guard lets through")
    f.add_argument("--deny-cidr", action="append", default=[], help="always refused, even inside an allowed CIDR")

    c = sub.add_parser("collect", help="single writer of net/ (network_mode: none)")
    c.add_argument("--net-dir", default=NET_DIR)
    c.add_argument("--events", default=EVENTS_SOCKET)
    c.add_argument("--rules", default=None, help="rules.json path, for status.json's load result")
    return p


def _parse_upstream(value: str, mode: str) -> tuple[str, int]:
    if value == "direct":
        if mode != "http-proxy":
            raise SystemExit("netgate: upstream direct needs --mode http-proxy")
        return "", 0
    prefix = "chain:http://" if mode == "http-proxy" else "tcp:"
    host, _, port = value.removeprefix(prefix).rstrip("/").rpartition(":")
    if not value.startswith(prefix) or not host or not port.isdigit():
        raise SystemExit(f"netgate: {mode} mode needs upstream {prefix}<host>:<port>, got {value!r}")
    return host, int(port)


async def _run_forward(args) -> None:
    from .forward import EventSink, Forwarder, ForwardSpec
    from .guard import parse_exceptions

    host, port = _parse_upstream(args.upstream, args.mode)
    direct = args.upstream == "direct"
    try:
        exceptions = parse_exceptions(args.guard_allow_host, args.guard_allow_cidr, args.deny_cidr)
    except ValueError as e:
        raise SystemExit(f"netgate: {e}") from e
    if direct and args.rules:
        raise SystemExit("netgate: a direct gate enforces only its static allowlist; it never reads --rules")
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
        resolver_url=args.resolver,
        exit_url=args.exit_url,
        client=args.client,
        record=args.record,
        record_headers=args.record_headers,
        exceptions=exceptions,
        direct=direct,
    )
    sink = EventSink(args.events)
    policy = None
    if direct:
        from .policy import StaticPolicy, baseline

        policy = StaticPolicy(baseline(exceptions))
    elif args.rules:
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
