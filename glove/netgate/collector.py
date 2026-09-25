"""The ``collect`` role: the single writer of ``net/``.

Runs as ``glove-<session>-netgate`` with ``network_mode: none`` — it has no
network interface at all, so it cannot expose an API on the internal network or
anywhere else. It receives flow records as datagrams on a Unix socket in a
tmpfs volume only the gate containers mount, and writes:

- ``flows.ndjson`` (rotated, via ``NdjsonWriter``);
- ``status.json`` (atomic rename, every ``status_interval`` seconds and on
  start/stop) — the handoff brief §2 shape, plus an additive ``telemetry`` block
  and a ``t`` heartbeat.

It reads ``session.json`` (written by glove at render time) for the record mode
and rotation settings; a missing or unreadable one falls back to defaults.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import socket
import sys
import time
from pathlib import Path

from . import GATE_VERSION, ROTATE_BYTES, ROTATE_KEEP, RUN_LOST_AFTER, SCHEMA_VERSION
from .policy import PolicyWatcher
from .records import GATE_EVENTS, gate_record, iso_utc, ulid
from .writer import NdjsonWriter, read_json_dict, write_json_atomic

_UNHEALTHY = {"upstream_unreachable", "timeout"}
MAX_DATAGRAM = 64 * 1024


class Collector:
    def __init__(
        self,
        net_dir: str | os.PathLike,
        socket_path: str,
        *,
        status_interval: float = 5.0,
        rules_path: str | os.PathLike | None = None,
    ):
        self.net_dir = Path(net_dir)
        self.socket_path = socket_path
        self.status_interval = status_interval
        self.facts = read_json_dict(self.net_dir / "session.json") or {}
        rotate = self.facts.get("rotate") or {}
        self.writer = NdjsonWriter(
            self.net_dir,
            "flows",
            max_bytes=int(rotate.get("max_bytes", ROTATE_BYTES)),
            keep=int(rotate.get("keep", ROTATE_KEEP)),
        )
        self.retain_s = rotate.get("retain_s")
        self.exits = NdjsonWriter(self.net_dir, "exit", max_bytes=1024 * 1024, keep=2)
        self.invalid = 0
        self.expired = 0
        self._resolver: dict[str, bool] = {}  # service -> last reported resolver health
        self.last_exit: dict | None = None  # current apparent origin, kept across rotation/expiry
        # service -> last known upstream outcome (True ok / False failed)
        self._upstream: dict[str, bool] = {}
        self._sock: socket.socket | None = None
        self._failing = False
        self.run_id = f"g_{ulid()}"
        # live forwarder runs: run -> (service, monotonic time last heard from)
        self._runs: dict[str, tuple[str | None, float]] = {}
        self._clock = time.monotonic
        # The collector validates rules.json with the same code the forwarders
        # use, purely to report the load result in status.json.
        self.policy = PolicyWatcher(
            Path(rules_path) if rules_path else None,
            env=self.facts.get("env"),
            session=self.facts.get("session"),
        )

    # --- ingest ------------------------------------------------------------

    def ingest(self, data: bytes) -> None:
        try:
            record = json.loads(data)
        except ValueError:
            self.invalid += 1
            return
        kind = record.get("type") if isinstance(record, dict) else None
        if kind == "exit":
            self.last_exit = record
            self.exits.write(record)
            self._carry_exit()  # this write may have size-rotated exit.ndjson
            return
        if kind == "gate":
            self._ingest_gate(record)
            return
        if kind == "health":
            res = record.get("resolver")
            if isinstance(record.get("service"), str) and isinstance(res, dict):
                self._resolver[record["service"]] = bool(res.get("healthy"))
            return
        if kind != "flow":
            self.invalid += 1
            return
        self._track_upstream(record)
        run = record.get("run")
        if isinstance(run, str) and run in self._runs:
            self._runs[run] = (self._runs[run][0], self._clock())
        self._write(record)

    def _write(self, record: dict) -> None:
        ok = self.writer.write(record)
        if ok == self._failing:
            # Log transitions only: status.json may itself be unwritable, so the
            # container log is the one place a drop is guaranteed to be visible.
            self._failing = not ok
            msg = "cannot write flows; DROPPING records (traffic unaffected)" if not ok else "flow writes recovered"
            print(f"netgate: {msg} (dropped so far: {self.writer.dropped})", file=sys.stderr, flush=True)

    def _ingest_gate(self, record: dict) -> None:
        """A forwarder's start/stop. Starts are re-sent periodically (so one
        lost at startup is recovered); write each run's first one only."""
        if (record.get("event") not in GATE_EVENTS or record.get("role") != "forward"
                or not isinstance(record.get("run"), str)):
            self.invalid += 1
            return
        run, service = record["run"], record.get("service")
        if record["event"] == "start":
            known = run in self._runs
            svc = service if isinstance(service, str) else None
            if not known and svc is not None:
                # A new run of the service replaces (ends) the old one: don't
                # later reap it into a stale inferred stop.
                for other, (other_svc, _) in list(self._runs.items()):
                    if other_svc == svc:
                        del self._runs[other]
            self._runs[run] = (svc, self._clock())
            if known:
                return
        else:
            self._runs.pop(run, None)
        self._write(record)

    def _reap_lost_runs(self) -> None:
        """A forwarder silent for RUN_LOST_AFTER is gone (SIGKILL, a crash with
        no restart): write the `stop` it never sent, marked inferred, so a
        reader can end its unclosed flows."""
        now = self._clock()
        for run, (service, last) in list(self._runs.items()):
            if now - last > RUN_LOST_AFTER:
                del self._runs[run]
                self._write(gate_record(event="stop", role="forward", run=run, service=service,
                                        env=self.facts.get("env"), session=self.facts.get("session"),
                                        t=time.time(), inferred=True))

    def _write_own(self, event: str) -> None:
        self._write(gate_record(event=event, role="collect", run=self.run_id, env=self.facts.get("env"),
                                session=self.facts.get("session"), t=time.time()))

    def _carry_exit(self) -> None:
        """Exit records are written only on change, so after ANY rotation (size
        or retention) the current origin is re-written as the first line of the
        fresh exit.ndjson: its latest line is always the present origin."""
        if self.last_exit is not None and self.exits.opened_at is None:
            self.exits.write(self.last_exit)

    def _track_upstream(self, record: dict) -> None:
        service = record.get("service")
        if not isinstance(service, str):
            return
        phase = record.get("phase")
        if phase == "update":
            self._upstream[service] = True
        elif phase == "close":
            self._upstream[service] = record.get("close_reason") not in _UNHEALTHY

    # --- status ------------------------------------------------------------

    def status(self, state: str) -> dict:
        healthy = all(self._upstream.values()) if self._upstream else None
        return {
            "v": SCHEMA_VERSION,
            "gate": GATE_VERSION,
            "state": state,
            "record": self.facts.get("record", "metadata"),
            "upstream": {"kind": self.facts.get("upstream_kind", "tcp"), "healthy": healthy},
            # null until a gate has used its in-tunnel resolver (or none is configured)
            "resolver": {"mode": self.facts.get("resolve", "in-tunnel"),
                         "healthy": all(self._resolver.values()) if self._resolver else None},
            # Load result of rules.json: `ok: false` + `error` is how a rejected
            # write comes back (the gate keeps its last known-good set).
            "rules": self.policy.status(),
            # Additive (readers ignore unknown fields): heartbeat + drop counters,
            # so a telemetry failure is visible without ever blocking traffic.
            "t": iso_utc(),
            "telemetry": {
                "written": self.writer.written,
                "dropped": self.writer.dropped,
                "invalid": self.invalid,
                "rotations": self.writer.rotations,
                "expired_files": self.expired,
            },
        }

    def write_status(self, state: str) -> bool:
        self.policy.poll()
        if state == "running":
            self._reap_lost_runs()
        if self.retain_s:
            self.expired += self.writer.expire(float(self.retain_s)) + self.exits.expire(float(self.retain_s))
            self._carry_exit()
        return write_json_atomic(self.net_dir / "status.json", self.status(state))

    # --- run ---------------------------------------------------------------

    def _bind(self) -> None:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(self.socket_path)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        old = os.umask(0o077)
        try:
            sock.bind(self.socket_path)
        finally:
            os.umask(old)
        with contextlib.suppress(OSError):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        sock.setblocking(False)
        self._sock = sock

    def _on_readable(self, limit: int | None = 256) -> None:
        assert self._sock is not None
        n = 0
        while limit is None or n < limit:
            try:
                data = self._sock.recv(MAX_DATAGRAM)
            except OSError:  # incl. BlockingIOError: drained
                return
            self.ingest(data)
            n += 1

    def _drain(self) -> None:
        """Everything already queued, however much (not the 256-per-wakeup cap)."""
        self._on_readable(limit=None)

    async def run(self, stop: asyncio.Event) -> None:
        loop = asyncio.get_running_loop()
        self._bind()
        assert self._sock is not None
        loop.add_reader(self._sock.fileno(), self._on_readable)
        self._write_own("start")
        self.write_status("running")
        try:
            while not stop.is_set():
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(stop.wait(), self.status_interval)
                self.write_status("running")
        finally:
            loop.remove_reader(self._sock.fileno())
            self._drain()
            self._sock.close()
            with contextlib.suppress(OSError):
                os.unlink(self.socket_path)
            self._write_own("stop")
            self.writer.close()
            self.exits.close()
            self.write_status("stopped")
