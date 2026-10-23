"""The egresses' exit check, run from an egress's `verify` hook (core's `hook`
verify kind, which fails the launch closed on a raise or an empty result).

The egress's own software must report one valid IP address for its exit (for
vpn, the server it tunnels to):

  source: exec   the check's `argv` prints it inside its sidecar `service`
  source: url    `url` answers it through the egress proxy as JSON, `ip_field`
                 holding the IP and every `expect` field its value (e.g.
                 `{IsTor: true}`)

With the operator's `host_check_url` (no default) that service, asked from the
host and through the egress, must see two different IPs. It is the only lookup
of the host's own IP: glove picks no lookup service.
"""

from __future__ import annotations

import ipaddress
import json
import urllib.request
from typing import Any

from glove.api import ConfigError, HookContext, VerifyTools, hook

SOURCES = ("exec", "url")


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


def check_item(item: dict[str, Any]) -> None:
    """Raise ConfigError when the check lacks its source's fields."""
    source = item.get("source")
    if source not in SOURCES:
        raise ConfigError(f"exit-confirmed needs `source`, one of {list(SOURCES)}")
    if source == "exec" and not (item.get("service") and item.get("argv")):
        raise ConfigError("source exec needs `service` and `argv` (it prints the IP)")
    if source == "url" and (not item.get("url") or not item.get("ip_field")
                            or not isinstance(item.get("expect") or {}, dict)):
        raise ConfigError("source url needs `url`, `ip_field` (the JSON field holding the IP) and optionally "
                        "`expect`, a mapping")


def _from_exec(item: dict[str, Any], tools: VerifyTools) -> tuple[str, str]:
    svc, argv = str(item["service"]), " ".join(str(x) for x in item["argv"])

    def named() -> tuple[bool, str]:
        rc, out = tools.run()
        ip = ip_or_none(out) if rc == 0 else None
        # what it printed is withheld unless it is the IP
        return (True, ip) if ip else (False, f"exit {rc}, no IP address")

    ok, ip = tools.retry(named, svc)
    if not ok:
        raise ConfigError(f"`{argv}` in {svc} did not print one IP address ({ip})")
    return ip, f"from {svc}"


def _from_url(item: dict[str, Any], tools: VerifyTools) -> tuple[str, str]:
    url, field, expect = str(item["url"]), str(item["ip_field"]), item.get("expect") or {}
    if not tools.proxy:
        raise ConfigError("no egress proxy to check")

    doc: dict[str, Any] = {}

    def answered() -> tuple[bool, str]:
        """No answer or no JSON (a fresh circuit's interstitial page) is
        retried; a JSON answer is final."""
        rc, body = tools.fetch(url)
        if rc != 0:
            return False, f"the egress proxy is not passing traffic ({tools.proxy}); the tunnel is down or blocked"
        try:
            got = json.loads(body)
        except ValueError:
            got = None
        if not isinstance(got, dict):
            return False, f"{url} did not answer JSON through {tools.proxy}"
        doc.update(got)
        return True, ""

    ok, why = tools.retry(answered, "egress")
    if not ok:
        raise ConfigError(why)
    wrong = {k: got for k, v in expect.items() if type(got := doc.get(k)) is not type(v) or got != v}
    if wrong:
        raise ConfigError(f"{url} answered {wrong}, not {expect} — traffic is NOT leaving through the egress")
    ip = ip_or_none(str(doc.get(field, "")))
    if not ip:
        raise ConfigError(f"{url} answered no IP address in {field!r}")
    return ip, f"via {tools.proxy}"


def confirm_exit(item: dict[str, Any], tools: VerifyTools) -> str:
    """The exit's IP (and the leak check's verdict) as one line; raises ConfigError."""
    check_item(item)
    ip, via = (_from_exec if item["source"] == "exec" else _from_url)(item, tools)
    host_url = str(item.get("host_check_url") or "")
    if not host_url:
        return f"{ip} ({via})"
    # The operator's leak check: their service, asked from the host and through
    # the egress, must see two different addresses (an endpoint is not an exit).
    if not tools.proxy:
        raise ConfigError("host_check_url needs an egress proxy to ask through")
    real = host_public_ip(host_url)
    if not real:
        raise ConfigError(f"could not determine this machine's public IP from {host_url}, so a leak cannot be "
                          "ruled out")
    rc, out = tools.fetch(host_url)
    seen = ip_or_none(out) if rc == 0 else None
    if not seen:
        raise ConfigError(f"{host_url} named no IP address through the egress proxy ({tools.proxy}), so a leak "
                        "cannot be ruled out")
    if seen == real:
        raise ConfigError(f"{host_url} sees this machine's public IP ({real}) through the egress — traffic is NOT "
                        "going through the tunnel")
    return f"{ip} ({via}); {host_url}: host {real} ≠ egress {seen}"


@hook
def verify(ctx: HookContext, item: dict[str, Any], tools: VerifyTools) -> str:
    """An egress's `verify` hook: its module imports this one (vpn, tor)."""
    return confirm_exit(item, tools)
