"""`glove playwright login`: what it exports from the login browser, and how.

Leaf module, pure (no I/O): `hooks.py` checks the session's `login` settings
with it at plan time, `cli.py` filters what the login browser holds with it.

- `spec()` validates `playwright.login` (and `storage_state`, which must be a
  `keychain:` reference: login writes it).
- `export_state()` builds a Playwright storage state (cookies + localStorage)
  holding only the hosts `login.domains` names; what it drops is reported by
  domain, never by value.
- `captures()` picks each `login.capture` value (a cookie, or a localStorage
  key optionally narrowed by a regex) for its Keychain service.
- `expiry()` summarises a stored state's cookie lifetimes (for `status`).
"""

from __future__ import annotations

import fnmatch
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from glove.config import keychain_service
from glove.naming import HOST_GLOB as _DOMAIN

_SERVICE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_ORIGIN = re.compile(r"https?://[a-z0-9.-]+(:[0-9]{1,5})?")
LOGIN_KEYS = frozenset({"start_url", "domains", "capture"})


class LoginError(ValueError):
    """Something the session's `login` settings, or the signed-in browser, lacks."""


@dataclass(frozen=True)
class Capture:
    service: str
    cookie: tuple[str, str] | None = None             # (domain, name)
    storage: tuple[str, str, str | None] | None = None  # (origin, key, match)

    def describe(self) -> str:
        if self.cookie:
            return f"cookie {self.cookie[1]} of {self.cookie[0]}"
        origin, key, match = self.storage
        return f"localStorage {key} of {origin}" + (f" (matching {match})" if match else "")


@dataclass(frozen=True)
class Spec:
    start_url: str
    domains: tuple[str, ...]
    captures: tuple[Capture, ...]
    state_service: str | None    # storage_state's Keychain service, when set

    def wants_storage(self, origin: str) -> bool:
        """An origin whose localStorage is kept (state) or captured."""
        return (self.state_service is not None and matches(urlsplit(origin).hostname or "", self.domains)) or \
            any(c.storage and c.storage[0] == origin for c in self.captures)

    @property
    def needs_storage(self) -> bool:
        return self.state_service is not None or any(c.storage for c in self.captures)


def spec(login: Any, storage_state: str | None) -> Spec | None:
    """`playwright.login` checked, or None when it is unset."""
    if login is None:
        return None
    if not isinstance(login, dict) or not login.keys() <= LOGIN_KEYS:
        raise LoginError(f"playwright.login: keys are {sorted(LOGIN_KEYS)}")
    url = login.get("start_url")
    if not isinstance(url, str) or not re.fullmatch(r"https?://\S+", url):
        raise LoginError("playwright.login.start_url: an http(s) URL is required")
    domains = login.get("domains") or []
    if not isinstance(domains, list) or not all(isinstance(d, str) and _DOMAIN.fullmatch(d) for d in domains):
        raise LoginError("playwright.login.domains: a list of lower-case host names, each optionally `*.`-prefixed")
    service = None
    if storage_state is not None:
        service = keychain_service(storage_state)
        if service is None:
            raise LoginError("playwright.storage_state: `glove playwright login` writes it, so it must be "
                             "keychain:<service>")
        if not domains:
            raise LoginError("playwright.login.domains: required with storage_state (only those hosts' cookies "
                             "and localStorage are exported)")
    caps = _captures(login.get("capture") or {})
    if service is None and not caps:
        raise LoginError("playwright.login: nothing to store (set storage_state, login.capture or both)")
    if service is not None and any(c.service == service for c in caps):
        raise LoginError(f"playwright.login.capture: {service} is storage_state's own service")
    return Spec(url, tuple(domains), caps, service)


def _captures(raw: Any) -> tuple[Capture, ...]:
    where = "playwright.login.capture"
    if not isinstance(raw, dict):
        raise LoginError(f"{where}: a mapping of Keychain service → {{cookie: …}} or {{storage: …}}")
    out = []
    for service, item in raw.items():
        if not isinstance(service, str) or not _SERVICE.fullmatch(service):
            raise LoginError(f"{where}: {service!r} is not a Keychain service name")
        if not isinstance(item, dict) or len(item) != 1 or not item.keys() <= {"cookie", "storage"}:
            raise LoginError(f"{where}.{service}: exactly one of cookie: {{domain, name}} or "
                             "storage: {origin, key, match?}")
        kind, body = next(iter(item.items()))
        if kind == "cookie":
            if not isinstance(body, dict) or set(body) != {"domain", "name"} or \
                    not all(isinstance(v, str) and v for v in body.values()) or \
                    not _DOMAIN.fullmatch(body["domain"]) or body["domain"].startswith("*"):
                raise LoginError(f"{where}.{service}.cookie: {{domain: <host>, name: <cookie>}}")
            out.append(Capture(service, cookie=(body["domain"], body["name"])))
            continue
        if not isinstance(body, dict) or not {"origin", "key"} <= set(body) <= {"origin", "key", "match"} or \
                not all(isinstance(v, str) and v for v in body.values()) or not _ORIGIN.fullmatch(body["origin"]):
            raise LoginError(f"{where}.{service}.storage: {{origin: https://<host>[:port], key: <key>, "
                             "match: <regex>?}")
        if body.get("match") is not None:
            try:
                re.compile(body["match"])
            except re.error as e:
                raise LoginError(f"{where}.{service}.storage.match: {e}") from e
        out.append(Capture(service, storage=(body["origin"], body["key"], body.get("match"))))
    return tuple(out)


def matches(host: str, domains: tuple[str, ...]) -> bool:
    """`host` (a cookie's domain, an origin's host) is one `domains` names:
    `x` itself, or `*.x` for x's subdomains (not x: list both for both)."""
    host = host.lower().lstrip(".")
    return any(fnmatch.fnmatchcase(host, d) for d in domains)


@dataclass
class Export:
    state: dict[str, Any]
    dropped: Counter = field(default_factory=Counter)   # domain/origin → how many items left out

    @property
    def summary(self) -> str:
        cookies, origins = self.state["cookies"], self.state["origins"]
        hosts = sorted({c["domain"].lstrip(".") for c in cookies})
        return f"{len(cookies)} cookie(s) for {', '.join(hosts) or 'no host'}; localStorage of {len(origins)} origin(s)"


def export_state(cookies: list[dict[str, Any]], storage: dict[str, dict[str, str]], domains: tuple[str, ...]) \
        -> Export:
    """A Playwright storage state of the cookies (CDP `Storage.getCookies`)
    and localStorage (origin → items) whose host `domains` names."""
    out = Export({"cookies": [], "origins": []})
    for c in cookies:
        domain = str(c.get("domain", ""))
        if not matches(domain, domains) or c.get("partitionKey"):
            key = domain.lstrip(".") + (" (partitioned)" if c.get("partitionKey") else "")
            out.dropped[key] += 1
            continue
        out.state["cookies"].append({
            "name": c["name"], "value": c["value"], "domain": domain, "path": c.get("path", "/"),
            "expires": -1 if c.get("session") else c.get("expires", -1),
            "httpOnly": bool(c.get("httpOnly")), "secure": bool(c.get("secure")),
            "sameSite": s if (s := c.get("sameSite")) in ("Strict", "Lax", "None") else "Lax",
        })
    for origin, items in sorted(storage.items()):
        if not matches(urlsplit(origin).hostname or "", domains):
            out.dropped[origin] += len(items)
            continue
        if items:
            out.state["origins"].append({"origin": origin,
                                         "localStorage": [{"name": k, "value": v} for k, v in items.items()]})
    return out


def captures(caps: tuple[Capture, ...], cookies: list[dict[str, Any]], storage: dict[str, dict[str, str]]) \
        -> dict[str, str]:
    """service → its captured value. Raises LoginError naming what is
    missing (never a value)."""
    out, missing = {}, []
    for cap in caps:
        if cap.cookie:
            domain, name = cap.cookie
            values = {c["value"] for c in cookies
                      if c.get("name") == name and str(c.get("domain", "")).lower().lstrip(".") == domain}
            if len(values) > 1:
                missing.append(f"{cap.service}: {len(values)} different cookies {name} for {domain} (paths?)")
                continue
            value = next(iter(values), "")
        else:
            origin, key, match = cap.storage
            value = (storage.get(origin) or {}).get(key, "")
            if value and match:
                m = re.search(match, value)
                value = m.group(0) if m else ""
        if not value:
            missing.append(f"{cap.service}: no {cap.describe()}"
                           + (" (is that origin open in a tab?)" if cap.storage else ""))
        elif not value.isascii() or any(ch in value for ch in "\n\r\0"):
            missing.append(f"{cap.service}: the {cap.describe()} is not one ASCII line")
        else:
            out[cap.service] = value
    if missing:
        raise LoginError("; ".join(missing))
    return out


def expiry(state: dict[str, Any]) -> tuple[int, int, float | None]:
    """(cookies, session cookies, earliest expiry as epoch seconds or None)."""
    cookies = state.get("cookies") or []
    timed = [float(c["expires"]) for c in cookies if float(c.get("expires", -1)) > 0]
    return len(cookies), len(cookies) - len(timed), min(timed) if timed else None
