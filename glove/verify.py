"""Core verify kinds: checks run after the sidecars are up and before the
harness starts (§4.4). A failing check aborts the launch (fail closed).

An extension lists checks in its manifest::

    verify:
      - { name: tunnel-up, kind: container-healthy, service: gluetun, timeout: 120 }
      - { name: exit-confirmed, kind: hook, source: exec, service: gluetun, argv: [cat, /tmp/ip] }

Kinds:
  container-healthy  the sidecar's healthcheck reports healthy (`service`, `timeout`)
  tcp-open           `host:port` accepts a connection from `network`
  http-ok            `url` answers < 400 from `network`, optionally via `proxy`
  http-refused       `proxy` answers a request for `url` with a refusal (403) —
                     a negative check: the proxy is up and does NOT pass it
  hook               the extension's `verify` hook runs the check with `VerifyTools`
                     and returns a one-line result; a raise (a bug included), no
                     hook or an empty result fails it; its message is shown only
                     for a `ConfigError` (vpn's and tor's exit check,
                     in the `exitcheck` library)
  exec-ok            `argv` exits 0 inside the sidecar `service` (its output is
                     withheld: it may carry identifiers), within `timeout`

`warn: true` makes a failed check a warning: the session starts anyway (e.g. a
credential that has expired, which the operator can refresh while it runs).

An extension's consecutive `exec-ok` checks run at once (at most `EXEC_POOL`, each within its
own `timeout`), so K hung checks cost one timeout, not K; their results report
in list order and a failure stops the launch as before.

Network probes run in a throwaway, hardened container on the named session
network (never on the host), so the host never resolves or contacts a
destination for a check (a `hook` check's own code runs on the host, like every hook).
"""

from __future__ import annotations

import os
import subprocess
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from itertools import groupby
from typing import TYPE_CHECKING, Any

from .config import ConfigError
from .naming import scoped
from .runtimes import get_runtime

if TYPE_CHECKING:
    from .plan import SessionPlan

PROBE_IMAGE = ("docker.io/curlimages/curl:8.22.0"
               "@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777")
KINDS = frozenset({"container-healthy", "tcp-open", "http-ok", "http-refused", "hook", "exec-ok"})
EXEC_POOL = 4  # `exec-ok` checks run at once
FETCH = 'curl -fsS -m 20 -x "$X" "$U"'  # a probe's body for `$U`, through the proxy `$X`


@dataclass(frozen=True)
class VerifyTools:
    """What a `verify` hook gets for its check (`kind: hook`): no more than core's own kinds use."""

    proxy: str  # the check's `proxy`, else the egress slot's `proxy_url` ("" without one)
    fetch: Callable[[str], tuple[int, str]]  # (curl's exit, body) for a url, via `proxy`, from a probe on `network`
    run: Callable[[], tuple[int, str]]  # (exit, stdout) of the check's own `argv` in its own `service`
    retry: Callable[[Callable[[], tuple[bool, str]], str], tuple[bool, str]]  # fn until ok: `retries`, `interval`


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

    # hook: the extension's own check, given only what it needs (fail closed)
    from .extensions import call_hook
    from .manifest import ExtensionError

    comp = plan.composition
    if (a := comp.by_name(ext)) is None:
        raise VerifyError(f"verify {name}: extension {ext!r} is not selected")
    proxy = str(item.get("proxy") or comp.slot_exports("egress").get("proxy_url") or "")
    # bound now: the hook gets a copy of the check, and runs only its own command (`_check_verify`)
    svc, argv = str(item.get("service") or ""), [str(x) for x in item.get("argv") or []]

    def run() -> tuple[int, str]:
        if not argv:
            raise ConfigError("this check has no `argv`")
        return sidecar_exec(provider, plan.session, svc, argv, int(item.get("timeout", 30)))

    tools = VerifyTools(proxy=proxy, fetch=lambda url: probe(provider, plan, network, FETCH, {"U": url, "X": proxy}),
                        run=run, retry=lambda fn, what: _retry(retries, interval, fn, say, what))
    try:
        out = call_hook(comp, a, "verify", dict(item), tools)
    except Exception as e:  # a check that crashed confirmed nothing
        why = e.__cause__ if isinstance(e, ExtensionError) and e.__cause__ else e
        # its own words for a ConfigError; anything else (a parse bug) may quote what a sidecar printed
        raise VerifyError(f"verify {name}: {why if isinstance(why, ConfigError) else type(why).__name__}",
                          service=item.get("service")) from e
    if not out:
        raise VerifyError(f"verify {name}: the verify hook of {ext!r} confirmed nothing", service=item.get("service"))
    return out


def _outcome(provider: str, plan: SessionPlan, ext: str, item: dict[str, Any],
             say: Callable[[str], None]) -> str | VerifyError:
    try:
        return run_check(provider, plan, ext, item, say)
    except VerifyError as e:
        return e


def run_verify(provider: str, plan: SessionPlan, say: Callable[[str], None]) -> None:
    """Every active extension's checks, in extension order (a run of an
    extension's `exec-ok` ones at once). On failure the extension's
    `diagnose` hook (if any) adds an explanation."""
    comp = plan.composition
    if not comp.verify:
        return
    from .extensions import call_hook

    def run(service: str, argv: list[str]) -> tuple[int, str]:  # for a diagnose hook
        return sidecar_exec(provider, plan.session, service, argv, 60)

    pool = ThreadPoolExecutor(EXEC_POOL)
    try:
        for (ext, at_once), group in groupby(comp.verify, lambda v: (v[0], v[1].get("kind") == "exec-ok")):
            batch = [item for _, item in group]
            started = [pool.submit(_outcome, provider, plan, ext, item, say) for item in batch] if at_once else []
            for i, item in enumerate(batch):
                say(f"  verify {ext}/{item.get('name', item.get('kind'))} ({item.get('kind')})…")
                result = started[i].result() if at_once else _outcome(provider, plan, ext, item, say)
                if isinstance(result, str):
                    say(f"    ✓ {result}")
                    continue
                e = result
                try:  # a failing diagnose must not turn the VerifyError (which stops the sidecars) into another
                    hint = call_hook(comp, a, "diagnose", item, run) if (a := comp.by_name(ext)) else None
                except Exception as d:
                    hint = f"(its diagnose hook failed: {d!r})"
                if hint:
                    e = VerifyError(f"{e}\n{hint}", service=e.service)
                if item.get("warn") is True:
                    say(f"    ⚠ {e} (a warning: the session starts anyway)")
                    continue
                raise e from None
    finally:
        # a failure stops the launch: checks not yet started never start
        pool.shutdown(wait=False, cancel_futures=True)
