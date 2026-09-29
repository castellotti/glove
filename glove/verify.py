"""Core verify kinds: checks run after the sidecars are up and before the
harness starts (§4.4). A failing check aborts the launch (fail closed).

An extension lists checks in its manifest::

    verify:
      - { name: tunnel-up, kind: container-healthy, service: gluetun, timeout: 120 }
      - { name: exit-not-host, kind: exit-ip-differs }

Kinds:
  container-healthy  the sidecar's healthcheck reports healthy (`service`, `timeout`)
  tcp-open           `host:port` accepts a connection from `network`
  http-ok            `url` answers < 400 from `network`, optionally via `proxy`
  exit-ip-differs    the IP an echo service sees through the egress proxy differs
                     from this machine's public IP (both must be known)

Network probes run in a throwaway, hardened container on the named session
network (never on the host), so the host never resolves or contacts a
destination for a check; only `exit-ip-differs` fetches the host's own IP.
"""

from __future__ import annotations

import os
import subprocess
import time
import urllib.request
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from .config import ConfigError

if TYPE_CHECKING:
    from .plan import SessionPlan

PROBE_IMAGE = ("docker.io/curlimages/curl:8.22.0"
               "@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777")
ECHO_URL = "https://am.i.mullvad.net/ip"
KINDS = frozenset({"container-healthy", "tcp-open", "http-ok", "exit-ip-differs"})


class VerifyError(ConfigError):
    """A verify check failed; the session must not start."""

    def __init__(self, msg: str, *, service: str | None = None) -> None:
        super().__init__(msg)
        self.service = service  # short name of the sidecar whose logs explain it


def _net(plan: SessionPlan, logical: str) -> str:
    return f"glove-{plan.session}-{logical}"


def probe(provider: str, plan: SessionPlan, network: str, script: str, env: dict[str, str],
          *, timeout: int = 60) -> tuple[int, str]:
    """Run `sh -c script` in a hardened throwaway curl container on `network`.
    Values travel as env vars, never interpolated into the script."""
    cmd = [provider, "run", "--rm", "--network", _net(plan, network),
           "--user", f"{plan.uid}:{plan.gid}", "--cap-drop", "ALL",
           "--security-opt", "no-new-privileges:true", "--read-only", "--pids-limit", "64",
           "--memory", "128m", *[a for k in env for a in ("-e", k)],
           "--entrypoint", "sh", PROBE_IMAGE, "-c", script]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False,
                           env={**os.environ, **env})
    except subprocess.TimeoutExpired:
        return 124, "timed out"
    return r.returncode, (r.stdout.strip() or r.stderr.strip())[-400:]


def host_public_ip(url: str) -> str:
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            return r.read(64).decode().strip()
    except OSError:
        return ""


def _retry(n: int, interval: float, fn: Callable[[], tuple[bool, str]], say: Callable[[str], None],
           what: str) -> tuple[bool, str]:
    last = ""
    for i in range(1, n + 1):
        ok, last = fn()
        if ok:
            return True, last
        if i < n:
            say(f"    {what}: not yet ({last or 'no answer'}) — retry {i}/{n - 1}")
            time.sleep(interval)
    return False, last


def _health(provider: str, container: str) -> str:
    r = subprocess.run([provider, "inspect", "--format",
                        "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}", container],
                       capture_output=True, text=True, check=False)
    return r.stdout.strip() or "missing"


def run_check(provider: str, plan: SessionPlan, ext: str, item: dict[str, Any],
              say: Callable[[str], None], *, sleep_scale: float = 1.0) -> str:
    """Run one check; returns a one-line result, raises VerifyError."""
    kind = item.get("kind")
    name = f"{ext}/{item.get('name', kind)}"
    if kind not in KINDS:
        raise VerifyError(f"verify {name}: unknown kind {kind!r} (known: {sorted(KINDS)})")
    retries = int(item.get("retries", 15))
    interval = float(item.get("interval", 4)) * sleep_scale
    network = str(item.get("network", "egress"))

    if kind == "container-healthy":
        svc = str(item["service"])
        container = f"glove-{plan.session}-{svc}"
        n = max(1, int(item.get("timeout", 120)) // 5)

        def healthy() -> tuple[bool, str]:
            st = _health(provider, container)
            if st == "none":
                raise VerifyError(f"verify {name}: {container} has no healthcheck", service=svc)
            return st == "healthy", st

        ok, st = _retry(n, 5 * sleep_scale, healthy, say, container)
        if not ok:
            raise VerifyError(f"verify {name}: {container} is {st!r}, not healthy", service=svc)
        return f"{container} healthy"

    if kind == "tcp-open":
        host, port = str(item["host"]), str(item["port"])
        ok, out = _retry(retries, interval, lambda: (
            probe(provider, plan, network, 'nc -z -w 3 "$H" "$P"', {"H": host, "P": port})[0] == 0, ""),
            say, f"{host}:{port}")
        if not ok:
            raise VerifyError(f"verify {name}: {host}:{port} is not accepting connections on {network}",
                              service=item.get("service"))
        return f"{host}:{port} open"

    if kind == "http-ok":
        url, proxy = str(item["url"]), str(item.get("proxy") or "")
        script = 'curl -sS -o /dev/null -m 20 -w "%{http_code}" ${X:+-x "$X"} "$U"'

        def get() -> tuple[bool, str]:
            rc, out = probe(provider, plan, network, script, {"U": url, "X": proxy})
            return rc == 0 and out.isdigit() and int(out) < 400, out

        ok, out = _retry(retries, interval, get, say, url)
        if not ok:
            raise VerifyError(f"verify {name}: {url} did not answer from {network}"
                              + (f" via {proxy}" if proxy else "") + f" ({out or 'no answer'})",
                              service=item.get("service"))
        return f"{url} → HTTP {out}" + (f" via {proxy}" if proxy else "")

    # exit-ip-differs
    comp = plan.composition
    egress = comp.slot_exports("egress") if comp else {}
    proxy = str(item.get("proxy") or egress.get("proxy_url") or "")
    if not proxy:
        raise VerifyError(f"verify {name}: no egress proxy to check")
    echo = str(item.get("echo_url") or ECHO_URL)
    real = host_public_ip(echo)

    def through() -> tuple[bool, str]:
        rc, out = probe(provider, plan, network, 'curl -fsS -m 20 -x "$X" "$U"', {"U": echo, "X": proxy})
        out = out.strip() if rc == 0 else ""
        return bool(out) and len(out) <= 45, out if rc == 0 else ""

    ok, exit_ip = _retry(retries, interval, through, say, "egress")
    if not ok:
        raise VerifyError(f"verify {name}: the egress proxy is not passing traffic ({proxy}); the tunnel is down "
                          "or blocked", service=item.get("service"))
    if not real:
        raise VerifyError(f"verify {name}: could not determine this machine's public IP from {echo}, so a leak "
                          "cannot be ruled out")
    if exit_ip == real:
        raise VerifyError(f"verify {name}: the egress exit IP ({exit_ip}) equals this machine's public IP — "
                          "traffic is NOT going through the tunnel", service=item.get("service"))
    return f"host {real} ≠ exit {exit_ip}"


def run_verify(provider: str, plan: SessionPlan, say: Callable[[str], None]) -> None:
    """Every active extension's checks, in extension order. On failure the
    extension's `diagnose` hook (if any) adds an explanation."""
    comp = plan.composition
    if comp is None or not comp.verify:
        return
    from .extensions import _hook_ctx

    for ext, item in comp.verify:
        say(f"  verify {ext}/{item.get('name', item.get('kind'))} ({item.get('kind')})…")
        try:
            say(f"    ✓ {run_check(provider, plan, ext, item, say)}")
        except VerifyError as e:
            a = comp.by_name(ext)
            if a is not None and a.hooks is not None and hasattr(a.hooks, "diagnose"):
                def run(service: str, argv: list[str]) -> tuple[int, str]:
                    r = subprocess.run([provider, "exec", f"glove-{plan.session}-{service}", *argv],
                                       capture_output=True, text=True, check=False)
                    return r.returncode, r.stdout.strip()

                hint = a.hooks.diagnose(_hook_ctx(comp, a), item, run)
                if hint:
                    raise VerifyError(f"{e}\n{hint}", service=e.service) from e
            raise
