"""The rules file: strict validation, first-match evaluation, watch/reload.

``rules.json`` is the single control channel into the gate (handoff brief §3),
written by Layman or ``glove net block`` by atomic rename and mounted read-only
into the gate containers only. Its schema can express **only verdicts over
destinations**: any key outside the schema — at any level — rejects the whole
file, and the gate keeps its last known-good rule set. A bad write therefore
never opens a session up, and a compromised writer cannot reach anything but
"block or allow some traffic".

The same validator runs host-side (the CLI refuses to write what the gate would
reject), so it is stdlib-only and shared.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from .records import iso_utc

MAX_BYTES = 1024 * 1024
MAX_RULES = 10_000
TOP_KEYS = frozenset({"v", "env", "session", "updated_at", "updated_by", "default", "rules"})
RULE_KEYS = frozenset({"id", "action", "match", "terminate", "note"})
MATCH_KEYS = frozenset({"host", "ip", "port", "service", "tool", "scope"})
SCOPES = frozenset({"local", "tunnelled", "direct"})
_ID = re.compile(r"r_[0-9A-Za-z_-]{1,64}")  # always fullmatch'd (`$` would admit a trailing newline)
_GLOB = re.compile(r"[a-z0-9*?._-]{1,253}")
_LABEL = re.compile(r"[A-Za-z0-9_.-]{1,64}")


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class Rule:
    id: str
    action: str  # "allow" | "block"
    host: str | None = None  # lowercase glob
    net: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
    port: tuple[int, int] | None = None
    service: str | None = None
    tool: str | None = None
    scope: str | None = None
    terminate: bool = False

    def matches(self, f: dict) -> bool:
        """All present match keys must hold (AND). A key whose flow value is
        unknown (e.g. ``ip`` before resolution) does not match."""
        if self.host is not None:
            host = f.get("host")
            if not host or not fnmatch.fnmatchcase(host.lower(), self.host):
                return False
        if self.net is not None:
            ip = f.get("ip")
            try:
                if ip is None or ipaddress.ip_address(ip) not in self.net:
                    return False
            except ValueError:
                return False
        if self.port is not None:
            port = f.get("port")
            if port is None or not self.port[0] <= port <= self.port[1]:
                return False
        return all(
            want is None or f.get(key) == want
            for key, want in (("service", self.service), ("tool", self.tool), ("scope", self.scope))
        )


@dataclass(frozen=True)
class RuleSet:
    default: str = "allow"
    rules: tuple[Rule, ...] = ()

    def evaluate(self, f: dict) -> tuple[str, str | None, bool]:
        """(verdict, rule id, terminate). First match wins; else the default."""
        for rule in self.rules:
            if rule.matches(f):
                return rule.action, rule.id, rule.terminate
        return self.default, None, False


def _str(v, what: str, pattern: re.Pattern | None = None) -> str:
    if not isinstance(v, str) or (pattern is not None and not pattern.fullmatch(v)):
        raise PolicyError(f"{what}: invalid value {v!r}")
    return v


def _port(v) -> tuple[int, int]:
    if isinstance(v, bool):
        raise PolicyError(f"match.port: invalid value {v!r}")
    if isinstance(v, int):
        lo = hi = v
    elif isinstance(v, str) and re.fullmatch(r"\d{1,5}-\d{1,5}", v):
        lo, hi = (int(x) for x in v.split("-"))
    else:
        raise PolicyError(f"match.port: must be an integer or 'lo-hi', got {v!r}")
    if not (1 <= lo <= hi <= 65535):
        raise PolicyError(f"match.port: out of range {v!r}")
    return lo, hi


def _rule(i: int, raw) -> Rule:
    where = f"rules[{i}]"
    if not isinstance(raw, dict):
        raise PolicyError(f"{where}: must be an object")
    extra = set(raw) - RULE_KEYS
    if extra:
        raise PolicyError(f"{where}: unknown keys {sorted(extra)} (allowed: {sorted(RULE_KEYS)})")
    rid = _str(raw.get("id"), f"{where}.id", _ID)
    action = raw.get("action")
    if action not in ("allow", "block"):
        raise PolicyError(f"{where}.action: must be allow|block, got {action!r}")
    term = raw.get("terminate", False)
    if not isinstance(term, bool):
        raise PolicyError(f"{where}.terminate: must be a boolean")
    note = raw.get("note")
    if note is not None and (not isinstance(note, str) or len(note) > 500):
        raise PolicyError(f"{where}.note: must be a string of at most 500 characters")
    m = raw.get("match")
    if not isinstance(m, dict) or not m:
        raise PolicyError(f"{where}.match: must be a non-empty object (use `default` to match everything)")
    extra = set(m) - MATCH_KEYS
    if extra:
        raise PolicyError(f"{where}.match: unknown keys {sorted(extra)} (allowed: {sorted(MATCH_KEYS)})")
    kw: dict = {}
    if "host" in m:
        h = m["host"]
        kw["host"] = _str(h.lower() if isinstance(h, str) else h, f"{where}.match.host", _GLOB)
    if "ip" in m:
        try:
            kw["net"] = ipaddress.ip_network(_str(m["ip"], f"{where}.match.ip"), strict=False)
        except ValueError as e:
            raise PolicyError(f"{where}.match.ip: {e}") from e
    if "port" in m:
        kw["port"] = _port(m["port"])
    for key in ("service", "tool"):
        if key in m:
            kw[key] = _str(m[key], f"{where}.match.{key}", _LABEL)
    if "scope" in m:
        if m["scope"] not in SCOPES:
            raise PolicyError(f"{where}.match.scope: must be one of {sorted(SCOPES)}")
        kw["scope"] = m["scope"]
    return Rule(id=rid, action=action, terminate=term, **kw)


def validate(data, *, env: str | None = None, session: str | None = None) -> RuleSet:
    """A RuleSet from parsed JSON, or PolicyError naming the first problem.

    ``env``/``session`` (when given) must equal the file's own, so a rules file
    copied to the wrong session's directory is refused rather than applied."""
    if not isinstance(data, dict):
        raise PolicyError("top level must be an object")
    extra = set(data) - TOP_KEYS
    if extra:
        raise PolicyError(f"unknown top-level keys {sorted(extra)} (allowed: {sorted(TOP_KEYS)})")
    if data.get("v") != 1:
        raise PolicyError(f"v: must be 1, got {data.get('v')!r}")
    for key, want in (("env", env), ("session", session)):
        val = _str(data.get(key), key, _LABEL)
        if want is not None and val != want:
            raise PolicyError(f"{key}: file is for {val!r}, this gate is {want!r}")
    for key in ("updated_at", "updated_by"):
        if key in data and not isinstance(data[key], str):
            raise PolicyError(f"{key}: must be a string")
    default = data.get("default", "allow")
    if default not in ("allow", "block"):
        raise PolicyError(f"default: must be allow|block, got {default!r}")
    rules_raw = data.get("rules", [])
    if not isinstance(rules_raw, list):
        raise PolicyError("rules: must be an array")
    if len(rules_raw) > MAX_RULES:
        raise PolicyError(f"rules: at most {MAX_RULES} rules")
    rules = tuple(_rule(i, r) for i, r in enumerate(rules_raw))
    ids = [r.id for r in rules]
    if len(set(ids)) != len(ids):
        raise PolicyError("rules: duplicate rule id")
    return RuleSet(default=default, rules=rules)


def parse_bytes(raw: bytes, **kw) -> RuleSet:
    if len(raw) > MAX_BYTES:
        raise PolicyError(f"file larger than {MAX_BYTES} bytes")
    try:
        data = json.loads(raw)
    except ValueError as e:
        raise PolicyError(f"not valid JSON: {e}") from e
    return validate(data, **kw)


@dataclass
class PolicyWatcher:
    """Polls ``path`` (a file inside a read-only directory mount) and keeps the
    last known-good RuleSet. No file ⇒ the empty default-allow set.

    Polling, not inotify: change events do not cross Docker Desktop's file
    sharing reliably. Nothing here sleeps, since it runs on the gate's event
    loop. A torn read from a non-atomic writer just fails validation (the
    last-good set stays) and is retried when the file's signature next changes.
    """

    path: Path | None
    env: str | None = None
    session: str | None = None
    rules: RuleSet = field(default_factory=RuleSet)
    loaded_at: str | None = None
    source_mtime: str | None = None
    ok: bool = True
    error: str | None = None
    _sig: tuple | None = None

    def _signature(self) -> tuple | None:
        try:
            st = os.stat(self.path)  # type: ignore[arg-type]
        except (OSError, TypeError):
            return None
        return (st.st_ino, st.st_mtime_ns, st.st_size)

    def poll(self) -> bool:
        """Re-read on change. True when the *active* rule set changed."""
        if self.path is None:
            return False
        sig = self._signature()
        if sig == self._sig:
            return False
        if sig is None:  # file removed ⇒ back to default allow
            self._sig = None
            changed = self.rules != RuleSet()
            self.rules, self.ok, self.error = RuleSet(), True, None
            self.loaded_at, self.source_mtime = iso_utc(), None
            return changed
        self._sig = sig
        try:
            raw = Path(self.path).read_bytes()
            new = parse_bytes(raw, env=self.env, session=self.session)
        except (OSError, PolicyError) as e:
            self.ok, self.error = False, str(e)  # keep the last known-good set
            return False
        self.ok, self.error = True, None
        self.loaded_at = iso_utc()
        self.source_mtime = iso_utc(sig[1] / 1e9) if sig else None
        changed = new != self.rules
        self.rules = new
        return changed

    def status(self) -> dict:
        return {
            "loaded_at": self.loaded_at,
            "source_mtime": self.source_mtime,
            "ok": self.ok,
            "error": self.error,
            "active_count": len(self.rules.rules),
        }
