"""`llm` extension hooks: provider routing and the model descriptor.

`contribute()` runs at plan time. It reads the provider catalog entry
(`providers/<name>.yml`, data only) and routes by `location`:

| location | endpoint `llm` forwards to                         | via network        |
|----------|----------------------------------------------------|--------------------|
| host     | host.docker.internal:<port>                        | glove-<id>-hostgw  |
| lan      | exactly the configured <host>:<port>               | glove-<id>-llm     |
| internet | the provider's HTTPS host:443 (TLS end to end)     | glove-<id>-llm     |

For `internet` the forwarder carries the provider's hostname as an alias on the
harness network, so the harness speaks TLS to the real name (correct SNI and
certificate) while it can still reach nothing else.

`resolve()` runs at launch, after the forwarders are up. It resolves
`model: auto` (the single model `/v1/models` lists) and `capabilities: auto` (the
catalog's probes) through a throwaway container on the harness network — the
host never resolves or contacts the endpoint itself.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

import yaml

PROVIDERS = Path(__file__).parent / "providers"
CATALOG_KEYS = frozenset({
    "name", "api", "host", "base_path", "default_port", "locations", "auth", "headers", "models_endpoint",
    "models_cursor", "dated_aliases", "probes", "defaults",
})
HEADER_NAME = re.compile(r"[A-Za-z0-9-]+")
HEADER_VALUE = re.compile(r"[\x20-\x7e]*")
CAPABILITY_KEYS = ("vision", "context_window", "max_tokens", "reasoning")
LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1")


class LlmError(ValueError):
    pass


def load_provider(name: str) -> dict[str, Any]:
    path = PROVIDERS / f"{name}.yml"
    if not path.is_file():
        known = sorted(p.stem for p in PROVIDERS.glob("*.yml"))
        raise LlmError(f"llm: unknown provider {name!r} (catalog: {known})")
    cat = yaml.safe_load(path.read_text()) or {}
    unknown = set(cat) - CATALOG_KEYS
    if unknown:
        raise LlmError(f"llm: provider {name!r} has unknown catalog keys {sorted(unknown)}")
    for h in (cat.get("headers") or {}, ((cat.get("auth") or {}).get("oauth") or {}).get("headers") or {}):
        for k, v in h.items():
            if not HEADER_NAME.fullmatch(str(k)) or not HEADER_VALUE.fullmatch(str(v)):
                raise LlmError(f"llm: provider {name!r} has a bad header {k!r}")
    return cat


def _auth(s: dict[str, Any], cat: dict[str, Any], harness: str) -> tuple[dict[str, Any], dict[str, str]]:
    """The auth block for `s["auth"]` and the public headers a probe sends."""
    auth = cat.get("auth") or {}
    headers = {str(k): str(v) for k, v in (cat.get("headers") or {}).items()}
    if s.get("auth", "api-key") != "oauth":
        return auth, headers
    oauth = auth.get("oauth")
    if not oauth:
        raise LlmError(f"llm: provider {cat['name']!r} takes no `auth: oauth` (an API key only)")
    if harness not in (oauth.get("harnesses") or []):
        raise LlmError(f"llm: an {cat['name']} subscription token (`auth: oauth`) is for "
                       f"{', '.join(oauth.get('harnesses') or [])} only, not harness {harness!r}; use an API key")
    if not s.get("api_key"):
        raise LlmError("llm: `auth: oauth` needs `api_key: keychain:<service>` holding the token")
    headers.update({str(k): str(v) for k, v in (oauth.get("headers") or {}).items()})
    return {**auth, **oauth}, headers


def _split_endpoint(endpoint: str, default_port: int | None) -> tuple[str, int, str | None, str | None]:
    """(host, port, scheme, path) from `host:port` or a URL."""
    if "://" in endpoint:
        u = urlsplit(endpoint)
        if not u.hostname:
            raise LlmError(f"llm.endpoint {endpoint!r} has no host")
        port = u.port or (443 if u.scheme == "https" else 80)
        return u.hostname, port, u.scheme, (u.path.rstrip("/") or None)
    host, sep, port = endpoint.rpartition(":")
    if not sep:
        host, port = endpoint, str(default_port or "")
    if not host or not port.isdigit():
        raise LlmError(f"llm.endpoint must be host:port, got {endpoint!r}")
    return host.strip("[]"), int(port), None, None


def route(settings: dict[str, Any], cat: dict[str, Any]) -> dict[str, Any]:
    """Where the forwarder dials and what the harness sees."""
    locations = cat.get("locations") or []
    location = settings.get("location") or ("internet" if locations == ["internet"] else None)
    if location is None:
        raise LlmError(f"llm: set `location` (one of {locations}) for provider {cat['name']!r}")
    if location not in locations:
        raise LlmError(f"llm: provider {cat['name']!r} supports location {locations}, not {location!r}")
    if settings.get("route", "direct") != "direct":
        raise LlmError("llm.route: egress is not implemented yet — cloud inference dials direct (untunnelled)")
    endpoint = settings.get("endpoint")
    if location == "internet":
        if endpoint:
            host, port, scheme, path = _split_endpoint(endpoint, 443)
        elif cat.get("host"):
            host, port, scheme, path = cat["host"], 443, "https", None
        else:
            raise LlmError(f"llm: provider {cat['name']!r} needs `endpoint` (a URL) for location internet")
        scheme = scheme or ("https" if port == 443 else "http")
        base_path = path if path is not None else cat.get("base_path", "")
        return {"location": location, "host": host, "port": port, "listen_port": port, "scheme": scheme,
                "base_path": base_path, "alias": host, "scope": "cloud"}
    if not endpoint:
        raise LlmError(f"llm: set `endpoint` (host:port) for location {location!r}")
    host, port, scheme, path = _split_endpoint(endpoint, cat.get("default_port"))
    if scheme == "https":
        raise LlmError("llm: an https endpoint needs location: internet (TLS is passed through by name)")
    if location == "host" and host not in LOCAL_HOSTS:
        raise LlmError(
            f"llm: location host means a server on this Mac — endpoint must be 127.0.0.1:<port>, got {host!r}"
        )
    if location == "lan" and host in LOCAL_HOSTS:
        raise LlmError("llm: a loopback endpoint is location: host, not lan")
    base_path = path if path is not None else cat.get("base_path", "")
    return {"location": location, "host": host, "port": port, "listen_port": port, "scheme": "http",
            "base_path": base_path, "alias": None, "scope": "local" if location == "host" else "lan"}


def _capabilities(settings: dict[str, Any], cat: dict[str, Any]) -> dict[str, Any]:
    caps = dict(cat.get("defaults") or {})
    explicit = settings.get("capabilities")
    if isinstance(explicit, dict):
        unknown = set(explicit) - set(CAPABILITY_KEYS)
        if unknown:
            raise LlmError(f"llm.capabilities: unknown keys {sorted(unknown)} (known: {list(CAPABILITY_KEYS)})")
        caps.update(explicit)
    return {k: caps.get(k) for k in CAPABILITY_KEYS}


def contribute(ctx: dict[str, Any]) -> dict[str, Any]:
    s = ctx["settings"]
    cat = load_provider(s["provider"])
    auth, headers = _auth(s, cat, ctx.get("harness", ""))
    if auth.get("required") and not s.get("api_key"):
        raise LlmError(f"llm: provider {cat['name']!r} needs `api_key: keychain:<service>`")
    r = route(s, cat)
    session = ctx["session"]["id"]
    if r["location"] == "internet":
        target = {"address": f"{r['host']}:{r['port']}", "via": "llm"}
        base = f"{r['scheme']}://{r['alias']}{'' if r['port'] in (80, 443) else ':' + str(r['port'])}"
    elif r["location"] == "lan":
        target = {"address": f"{r['host']}:{r['port']}", "via": "llm"}
        base = f"http://glove-{session}-llm:{r['listen_port']}"
    else:
        target = {"host_port": r["port"]}
        base = f"http://glove-{session}-llm:{r['listen_port']}"
    endpoint = {
        "port": r["listen_port"], "harness": True, "target": target,
        "aliases": [r["alias"]] if r["alias"] else [],
        "observe": {"tool": "llm", "scope": r["scope"]},
    }
    exports = {
        "base_url": base + r["base_path"],
        "api": cat["api"],
        "model": s.get("model") or "auto",
        "api_key_secret": "api_key" if s.get("api_key") else None,
        "auth_header": auth.get("header", "Authorization"),
        "auth_scheme": auth.get("scheme", "Bearer"),
        "api_key_kind": s.get("auth") or "api-key",
        "probe_headers": headers,
        "capabilities": _capabilities(s, cat),
        "capabilities_auto": s.get("capabilities") == "auto",
        "capabilities_explicit": sorted(s["capabilities"]) if isinstance(s.get("capabilities"), dict) else [],
        "extra_models": list(s.get("extra_models") or []),
        "location": r["location"],
        "provider": cat["name"],
    }
    return {"endpoints": {"llm": endpoint}, "exports": exports}


# --- launch-time resolution ---------------------------------------------------


def json_path(doc: Any, path: str) -> Any:
    """`$.a.b[0].c` (dotted keys and integer indexes only)."""
    if not path.startswith("$"):
        raise LlmError(f"probe path must start with $, got {path!r}")
    cur = doc
    for key, idx in re.findall(r"\.([A-Za-z0-9_-]+)|\[(\d+)\]", path[1:]):
        if key:
            cur = cur.get(key) if isinstance(cur, dict) else None
        else:
            cur = cur[int(idx)] if isinstance(cur, list) and int(idx) < len(cur) else None
        if cur is None:
            return None
    return cur


def _extract(doc: Any, spec: Any) -> Any:
    if isinstance(spec, str):
        return json_path(doc, spec)
    value = json_path(doc, spec["path"])
    if "contains" in spec:
        return isinstance(value, list) and spec["contains"] in value
    if "equals" in spec:
        return value == spec["equals"]
    return value


MAX_MODEL_PAGES = 20
CONNECT_RETRIES = (1, 2, 3, 4)  # seconds between attempts while nothing answers


def _model_ids(cat: dict[str, Any], root: str, probe, auth: bool) -> list[str]:
    """Every id the models endpoint lists, following a paginated list
    (`has_more` + `last_id`, the catalog's `models_cursor` names the parameter)."""
    endpoint = cat.get("models_endpoint", "/v1/models")
    url, ids = root + endpoint, []
    for _ in range(MAX_MODEL_PAGES):
        status, text = probe(url, auth=auth)
        for wait in CONNECT_RETRIES if status == 0 else ():
            # no HTTP answer at all: a forwarder that implements more than socat
            # (observe's gate) can still be starting
            time.sleep(wait)
            status, text = probe(url, auth=auth)
            if status != 0:
                break
        if status != 200:
            raise LlmError(f"llm: {cat['name']} did not answer {endpoint} (HTTP {status}): "
                           f"{text[:200]} — is the server running and reachable at the configured endpoint?")
        try:
            doc = json.loads(text)
            ids += [m.get("id") for m in (doc.get("data") or []) if isinstance(m, dict)]
        except (ValueError, AttributeError) as e:
            raise LlmError(f"llm: {endpoint} returned non-JSON: {text[:200]}") from e
        cursor = cat.get("models_cursor")
        if not (cursor and doc.get("has_more") and doc.get("last_id")):
            return ids
        url = f"{root}{endpoint}{'&' if '?' in endpoint else '?'}{cursor}={quote(str(doc['last_id']))}"
    raise LlmError(f"llm: {endpoint} listed more than {MAX_MODEL_PAGES} pages")


def resolve(ctx: dict[str, Any], exports: dict[str, Any], probe) -> tuple[dict[str, Any], list[str]]:
    """Resolve `model: auto` / `capabilities: auto`. Returns (exports, notes).
    `probe(url, method=, body=, auth=)` → (status, text) via a throwaway container."""
    cat = load_provider(ctx["settings"]["provider"])
    root = exports["base_url"].removesuffix(cat.get("base_path", "") or "")
    auth = bool(exports.get("api_key_secret"))
    notes: list[str] = []
    out = dict(exports)
    ids = _model_ids(cat, root, probe, auth)
    if exports["model"] == "auto":
        if len(ids) != 1:
            raise LlmError(f"llm: model: auto needs exactly one model at {cat.get('models_endpoint')}, found "
                           f"{ids or 'none'} — set `model:` to one of them")
        out["model"] = ids[0]
        notes.append(f"model: auto → {ids[0]}")
    elif ids and exports["model"] not in ids and not (
            cat.get("dated_aliases") and any(re.fullmatch(re.escape(exports["model"]) + r"-\d{8}", i or "")
                                             for i in ids)):
        raise LlmError(f"llm: model {exports['model']!r} is not served (available: {ids})")
    caps = dict(exports["capabilities"])
    spec = (cat.get("probes") or {}).get("capabilities")
    if spec:
        path = spec["path"].replace("{model}", out["model"])
        body = None
        if spec.get("body"):
            body = json.loads(json.dumps(spec["body"]).replace("{model}", out["model"]))
        status, text = probe(root + path, method=spec.get("method", "GET"), body=body, auth=auth)
        if status == 200:
            doc = json.loads(text)
            probed = {k: _extract(doc, spec[k]) for k in CAPABILITY_KEYS if k in spec}
            probed = {k: v for k, v in probed.items() if v is not None}
            # Explicit settings win; the probe fills every key you did not set.
            explicit = set(exports.get("capabilities_explicit") or [])
            for k in explicit & set(probed):
                if probed[k] != caps.get(k):
                    notes.append(f"warning: capabilities.{k} is {caps.get(k)!r} but the server reports "
                                 f"{probed[k]!r} — keeping your explicit setting")
            filled = {k: v for k, v in probed.items() if k not in explicit}
            caps.update(filled)
            if filled:
                notes.append("capabilities probed → " + ", ".join(f"{k}={v}" for k, v in sorted(filled.items())))
            for k in sorted(set(CAPABILITY_KEYS) & set(spec) - explicit - set(probed)):
                notes.append(f"warning: the server did not report {k}; using the default {caps.get(k)!r} — "
                             f"set `capabilities: {{{k}: …}}` if that is wrong")
        elif exports.get("capabilities_auto"):
            raise LlmError(f"llm: capability probe {path} failed (HTTP {status}); set `capabilities:` explicitly")
    elif exports.get("capabilities_auto"):
        notes.append(f"capabilities: auto → provider {cat['name']!r} has no probe; using catalog defaults")
    out["capabilities"] = caps
    return out, notes


def doctor(ctx: dict[str, Any]) -> list[tuple[str, str, str]]:
    s = ctx["settings"]
    try:
        r = route(s, load_provider(s["provider"]))
    except LlmError as e:
        return [("llm", "fail", str(e))]
    return [("llm", "ok", f"{s['provider']} at {r['location']} {r['host']}:{r['port']}")]
