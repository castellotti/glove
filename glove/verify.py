"""Core verify kinds: checks run after the sidecars are up and before the
harness starts (§4.4). A failing check aborts the launch (fail closed).

An extension lists checks in its manifest::

    verify:
      - { name: tunnel-up, kind: container-healthy, service: gluetun, timeout: 120 }
      - { name: exit-confirmed, kind: exit-confirmed, source: exec, service: gluetun, argv: [cat, /tmp/ip] }

Kinds:
  container-healthy  the sidecar's healthcheck reports healthy (`service`, `timeout`)
  tcp-open           `host:port` accepts a connection from `network`
  http-ok            `url` answers < 400 from `network`, optionally via `proxy`
  http-refused       `proxy` answers a request for `url` with a refusal (403) —
                     a negative check: the proxy is up and does NOT pass it
  exit-confirmed     the egress's own software reports one valid IP address for it
                     (its exit; for vpn, the server it tunnels to). `source: exec`:
                     `argv` prints it inside the sidecar `service` (within `timeout`).
                     `source: url`: `url` answers it through the egress proxy as JSON,
                     `ip_field` holding the IP and every `expect` field its value
                     (e.g. `{IsTor: true}`). With the operator's `host_check_url` (no
                     default) that service, asked from the host and through the
                     egress, must see two different IPs.
  exec-ok            `argv` exits 0 inside the sidecar `service` (its output is
                     withheld: it may carry identifiers), within `timeout`

`warn: true` makes a failed check a warning: the session starts anyway (e.g. a
credential that has expired, which the operator can refresh while it runs).

Network probes run in a throwaway, hardened container on the named session
network (never on the host), so the host never resolves or contacts a
destination for a check. Only `exit-confirmed` with an operator's
`host_check_url` fetches the host's own IP: glove picks no lookup service.
"""

from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import time
import urllib.request
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from .config import ConfigError
from .naming import scoped
from .runtimes import get_runtime

if TYPE_CHECKING:
    from .plan import SessionPlan

PROBE_IMAGE = ("docker.io/curlimages/curl:8.22.0"
               "@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777")
KINDS = frozenset({"container-healthy", "tcp-open", "http-ok", "http-refused", "exit-confirmed", "exec-ok"})
EXIT_SOURCES = frozenset({"exec", "url"})
FETCH = 'curl -fsS -m 20 -x "$X" "$U"'  # a probe's body for `$U`, through the proxy `$X`


class VerifyError(ConfigError):
    """A verify check failed; the session must not start."""

    def __init__(self, msg: str, *, service: str | None = None) -> None:
        super().__init__(msg)
        self.service = service  # short name of the sidecar whose logs explain it


def probe(provider: str, plan: SessionPlan, network: str, script: str, env: dict[str, str],
          *, timeout: int = 60) -> tuple[int, str]:
    """Run `sh -c script` in a hardened throwaway curl container on `network`.
    Values travel as env vars, never interpolated into the script."""
    cmd = get_runtime(provider).throwaway_argv(PROBE_IMAGE, ["-c", script], plan=plan,
                                               network=scoped(plan.session, network), env=env, entrypoint="sh")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False,
                           env={**os.environ, **env})
    except subprocess.TimeoutExpired:
        return 124, "timed out"
    return r.returncode, (r.stdout.strip() or r.stderr.strip())[-400:]


def ip_or_none(text: str) -> str | None:
    """`text` as one IP address, or None (an HTML page, an empty body, two lines)."""
    try:
        return str(ipaddress.ip_address(text.strip()))
    except ValueError:
        return None


def host_public_ip(url: str) -> str | None:
    """The host's own IP from the operator's `host_check_url`."""
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            return ip_or_none(r.read(64).decode(errors="replace"))
    except OSError:
        return None


def item_error(item: dict[str, Any]) -> str | None:
    """What is wrong with a check's fields for its kind (None: nothing), at
    compose time. Which sidecar an `argv` may run in is the composition's rule."""
    if item.get("kind") != "exit-confirmed":
        return None
    if item.get("source") not in EXIT_SOURCES:
        return f"exit-confirmed needs `source`, one of {sorted(EXIT_SOURCES)}"
    if item["source"] == "url" and (not item.get("url") or not item.get("ip_field")
                                    or not isinstance(item.get("expect", {}), dict)):
        return ("exit-confirmed from a url needs `url`, `ip_field` (the JSON field holding the IP) and optionally "
                "`expect`, a mapping")
    return None


def sidecar_exec(provider: str, session: str, service: str, argv: list[str], timeout: float) -> tuple[int, str]:
    """`argv` in the session's sidecar `service`: exit code (124: timed out) and
    stdout, decoded leniently (a caller withholds it unless it is what it asked for)."""
    try:
        r = subprocess.run([provider, "exec", scoped(session, service), *argv], capture_output=True,
                           timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return 124, ""
    return r.returncode, r.stdout.decode(errors="replace").strip()


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
        container = scoped(plan.session, svc)
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

    if kind == "exec-ok":
        svc, argv = str(item["service"]), [str(x) for x in item["argv"]]
        rc, _ = sidecar_exec(provider, plan.session, svc, argv, int(item.get("timeout", 120)))
        if rc != 0:
            raise VerifyError(f"verify {name}: `{' '.join(argv)}` exited {rc} in {svc} (output withheld)")
        return f"{svc}: exit 0"

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

    if kind == "http-refused":
        url, proxy = str(item["url"]), str(item["proxy"])
        # the CONNECT (https) or request (http) status the proxy itself answered
        script = 'curl -sS -o /dev/null -m 20 -w "%{http_connect} %{http_code}" -x "$X" "$U"; true'

        def answered() -> tuple[bool, str]:
            _, out = probe(provider, plan, network, script, {"U": url, "X": proxy})
            codes = [c for c in out.split() if c.isdigit() and c != "000"]
            # no status at all: the proxy is not up (yet)
            return bool(codes), codes[0] if codes else out

        ok, out = _retry(retries, interval, answered, say, proxy)
        if not ok:
            raise VerifyError(f"verify {name}: {proxy} did not answer from {network} ({out or 'no answer'})",
                              service=item.get("service"))
        if out != "403":
            raise VerifyError(f"verify {name}: {proxy} let {url} through (HTTP {out}) — it must refuse it",
                              service=item.get("service"))
        return f"{url} refused by {proxy}"

    # exit-confirmed
    comp = plan.composition
    proxy = str(item.get("proxy") or (comp.slot_exports("egress") if comp else {}).get("proxy_url") or "")

    def fetch(url: str) -> tuple[int, str]:
        return probe(provider, plan, network, FETCH, {"U": url, "X": proxy})

    if item.get("source") == "exec":
        svc, argv = str(item["service"]), [str(x) for x in item["argv"]]

        def named() -> tuple[bool, str]:
            rc, out = sidecar_exec(provider, plan.session, svc, argv, int(item.get("timeout", 30)))
            ip = ip_or_none(out) if rc == 0 else None
            # what it printed is withheld unless it is the IP
            return (True, ip) if ip else (False, f"exit {rc}, no IP address")

        ok, ip = _retry(retries, interval, named, say, svc)
        if not ok:
            raise VerifyError(f"verify {name}: `{' '.join(argv)}` in {svc} did not print one IP address ({ip})",
                              service=item.get("service"))
        via = f"from {svc}"
    else:
        if not proxy:
            raise VerifyError(f"verify {name}: no egress proxy to check")
        url, field = str(item["url"]), str(item["ip_field"])
        expect = dict(item.get("expect") or {})

        def answered() -> tuple[bool, str]:
            """No answer or no JSON (a fresh circuit's interstitial page) is
            retried; a JSON answer is final."""
            rc, body = fetch(url)
            if rc != 0:
                return False, f"the egress proxy is not passing traffic ({proxy}); the tunnel is down or blocked"
            try:
                doc = json.loads(body)
            except ValueError:
                doc = None
            return (True, body) if isinstance(doc, dict) else (False, f"{url} did not answer JSON through {proxy}")

        ok, body = _retry(retries, interval, answered, say, "egress")
        if not ok:
            raise VerifyError(f"verify {name}: {body}", service=item.get("service"))
        doc = json.loads(body)
        wrong = {k: got for k, v in expect.items() if type(got := doc.get(k)) is not type(v) or got != v}
        if wrong:
            raise VerifyError(f"verify {name}: {url} answered {wrong}, not {expect} — traffic is NOT leaving "
                              "through the egress", service=item.get("service"))
        ip = ip_or_none(str(doc.get(field, "")))
        if not ip:
            raise VerifyError(f"verify {name}: {url} answered no IP address in {field!r}", service=item.get("service"))
        via = f"via {proxy}"

    host_url = str(item.get("host_check_url") or "")
    if not host_url:
        return f"{ip} ({via})"
    # The operator's leak check: their service, asked from the host and through
    # the egress, must see two different addresses (an endpoint is not an exit).
    if not proxy:
        raise VerifyError(f"verify {name}: host_check_url needs an egress proxy to ask through")
    real = host_public_ip(host_url)
    if not real:
        raise VerifyError(f"verify {name}: could not determine this machine's public IP from {host_url}, so a leak "
                          "cannot be ruled out")
    rc, out = fetch(host_url)
    seen = ip_or_none(out) if rc == 0 else None
    if not seen:
        raise VerifyError(f"verify {name}: {host_url} named no IP address through the egress proxy ({proxy}), so a "
                          "leak cannot be ruled out", service=item.get("service"))
    if seen == real:
        raise VerifyError(f"verify {name}: {host_url} sees this machine's public IP ({real}) through the egress — "
                          "traffic is NOT going through the tunnel", service=item.get("service"))
    return f"{ip} ({via}); {host_url}: host {real} ≠ egress {seen}"


def run_verify(provider: str, plan: SessionPlan, say: Callable[[str], None]) -> None:
    """Every active extension's checks, in extension order. On failure the
    extension's `diagnose` hook (if any) adds an explanation."""
    comp = plan.composition
    if not comp.verify:
        return
    from .extensions import call_hook

    def run(service: str, argv: list[str]) -> tuple[int, str]:  # for a diagnose hook
        return sidecar_exec(provider, plan.session, service, argv, 60)

    for ext, item in comp.verify:
        say(f"  verify {ext}/{item.get('name', item.get('kind'))} ({item.get('kind')})…")
        try:
            say(f"    ✓ {run_check(provider, plan, ext, item, say)}")
        except VerifyError as e:
            a = comp.by_name(ext)
            if a is not None and (hint := call_hook(comp, a, "diagnose", item, run)):
                e = VerifyError(f"{e}\n{hint}", service=e.service)
            if item.get("warn") is True:
                say(f"    ⚠ {e} (a warning: the session starts anyway)")
                continue
            raise e from None
