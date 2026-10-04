#!/usr/bin/env python3
"""MCP server exposing `fetch_url`: one web page as readable text, through the
session's egress proxy. The twin of Pi's web_fetch extension (pi-extension/).

Runs in the `fetcher` sidecar and serves streamable HTTP on :8000 (stateless,
plain JSON responses), which the harness reaches through the `webfetch-mcp`
forwarder; requests must name that forwarder as their Host (`MCP_ALLOWED_HOST`).
Every fetch goes through GLOVE_FETCH_PROXY (the egress provider's proxy, or with
observe a gate in front of it): the sidecar has no other route.

The destination guard is pi-extension/guard.ts, ported: refuse anything that is
not plainly a public internet host, judged by shape only and never resolved,
before the request is sent and again on every redirect hop. Under the
`corporate` egress the operator's allowlist (GLOVE_FETCH_ALLOW) is let through
even when private; this machine, link-local/metadata and multicast stay refused.
When the egress gate refuses a request (a filter rule, the corporate allowlist,
the SSRF guard), the agent is told it was refused by policy, not that the
network failed. Standard library only, bar the MCP server itself.
"""

from __future__ import annotations

import fnmatch
import http.client
import ipaddress
import os
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser

PROXY = os.environ.get("GLOVE_FETCH_PROXY", "")
ALLOW = [x.strip().lower() for x in os.environ.get("GLOVE_FETCH_ALLOW", "").split(",") if x.strip()]
ALLOWED_HOST = os.environ.get("MCP_ALLOWED_HOST", "")
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
MAX_BODY = 5 * 1024 * 1024
MAX_REDIRECTS = 5
TIMEOUT = 45

# --- the destination guard (guard.ts) -------------------------------------------

LOCAL_SUFFIXES = (".localhost", ".local", ".internal", ".lan", ".home.arpa", ".intranet", ".corp")
HARD_NAMES = ("localhost", "host.docker.internal", "gateway.docker.internal", "host.containers.internal",
              "metadata.google.internal")


def _v4(ip: str) -> list[int]:
    return [int(x) for x in ip.split(".")]


def _ip_kind(host: str) -> int:
    try:
        return ipaddress.ip_address(host).version
    except ValueError:
        return 0


def public_v4(ip: str) -> bool:
    a, b, c, _ = _v4(ip)
    if a in (0, 10, 127) or a >= 224:
        return False
    if a == 100 and 64 <= b <= 127:  # CGNAT
        return False
    if a == 169 and b == 254:  # link-local, cloud metadata
        return False
    if a == 172 and 16 <= b <= 31:
        return False
    if a == 192 and b == 168:
        return False
    if a == 192 and b == 0 and c in (0, 2):
        return False
    if a == 198 and b in (18, 19):
        return False
    if a == 198 and b == 51 and c == 100:
        return False
    return not (a == 203 and b == 0 and c == 113)


def public_v6(ip: str) -> bool:
    h = ip.lower()
    mapped = re.fullmatch(r"::ffff:(\d+\.\d+\.\d+\.\d+)", h)
    if mapped:
        return public_v4(mapped.group(1))
    if h in ("::", "::1"):
        return False
    if re.match(r"^(fc|fd)", h) or re.match(r"^fe[89ab]", h) or h.startswith("ff"):
        return False
    return not h.startswith(("::ffff:", "64:ff9b:", "2001:db8:"))


def _hard_v4(ip: str) -> bool:
    a, b, _, _ = _v4(ip)
    return a in (0, 127) or a >= 224 or (a == 169 and b == 254)


def _in_cidr(ip: str, cidr: str) -> bool:
    try:
        return ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(cidr, strict=False)
    except ValueError:
        return False


def refusal(url: str, allow: list[str] | None = None) -> str | None:
    """Why `url` must not be fetched, or None when it may be."""
    allow = ALLOW if allow is None else allow
    u = urllib.parse.urlsplit(url)
    if u.scheme not in ("http", "https"):
        return "not an http(s) URL"
    if u.username or u.password:
        return "URLs with credentials are not fetched"
    host = (u.hostname or "").lower().rstrip(".")
    kind = _ip_kind(host)
    if allow:
        if host in HARD_NAMES or host.endswith(".localhost"):
            return f"{host} is this machine"
        if kind == 4 and _hard_v4(host):
            return f"{host} is not a reachable address"
        if kind == 4 and any("/" in a and _in_cidr(host, a) for a in allow):
            return None
        if kind == 0 and any("/" not in a and fnmatch.fnmatchcase(host, a) for a in allow):
            return None
    if kind == 4:
        return None if public_v4(host) else f"{host} is not a public address"
    if kind == 6:
        return None if public_v6(host) else f"{host} is not a public address"
    if "." not in host:
        return f"{host} is a local (single-label) name"
    if host == "localhost" or host.endswith(LOCAL_SUFFIXES):
        return f"{host} is a local name"
    return None


# --- HTML to text -----------------------------------------------------------------

SKIP = {"script", "style", "nav", "noscript", "template", "svg", "head"}
BLOCK = {"p", "div", "br", "li", "ul", "ol", "tr", "table", "section", "article", "header", "footer", "main",
         "h1", "h2", "h3", "h4", "h5", "h6", "pre", "blockquote", "hr", "dt", "dd", "figure", "form"}


class _Text(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.out: list[str] = []
        self.skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in SKIP:
            self.skip += 1
        elif tag in BLOCK:
            self.out.append("\n")

    def handle_endtag(self, tag):
        if tag in SKIP:
            self.skip = max(0, self.skip - 1)
        elif tag in BLOCK:
            self.out.append("\n")

    def handle_data(self, data):
        if not self.skip:
            self.out.append(data)


def html_to_text(html: str) -> str:
    p = _Text()
    p.feed(html)
    p.close()
    lines = (re.sub(r"[ \t\r\f\v]+", " ", ln).strip() for ln in "".join(p.out).split("\n"))
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()


# --- fetching through the proxy ---------------------------------------------------


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # every hop is followed by hand, through the guard


def _opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(urllib.request.ProxyHandler({"http": PROXY, "https": PROXY}), _NoRedirect)


def tunnel_refusal(url: str) -> str | None:
    """The egress gate's refusal text if it answers a CONNECT for `url` with 403, else None."""
    if not PROXY:
        return None
    p, u = urllib.parse.urlsplit(PROXY), urllib.parse.urlsplit(url)
    port = u.port or (443 if u.scheme == "https" else 80)
    conn = http.client.HTTPConnection(p.hostname, p.port or 80, timeout=15)
    try:
        conn.request("CONNECT", f"{u.hostname}:{port}", headers={"Host": f"{u.hostname}:{port}"})
        res = conn.getresponse()
        if res.status != 403:
            return None
        return res.read(4096).decode("utf-8", "replace").strip() or "refused (403)"
    except (OSError, http.client.HTTPException):
        return None
    finally:
        conn.close()


def _policy(url: str, why: str) -> str:
    return (f"Refused by this session's network policy for {url}: {why}. Do not retry or look for another "
            "route; tell the user if you need this source.")


def fetch(url: str, max_chars: int = 20000, raw: bool = False) -> str:
    if not PROXY:
        return ("fetch_url is not configured: GLOVE_FETCH_PROXY is unset, so there is no egress path. "
                "Refusing to fetch directly.")
    why = refusal(url)
    if why:
        return f"Refused: {why}. fetch_url reads public web pages only."
    opener = _opener()
    headers = {"User-Agent": UA, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"}
    res = None
    for hop in range(MAX_REDIRECTS + 1):
        try:
            res = opener.open(urllib.request.Request(url, headers=headers), timeout=TIMEOUT)
            break
        except urllib.error.HTTPError as e:
            loc = e.headers.get("Location")
            if 300 <= e.code < 400 and loc:
                if hop >= MAX_REDIRECTS:
                    return f"Too many redirects from {url}"
                nxt = urllib.parse.urljoin(url, loc)
                why = refusal(nxt)
                if why:
                    return f"Refused a redirect to {nxt}: {why}."
                url = nxt
                continue
            if e.code == 429:
                return "Rate-limited (HTTP 429). Back off; do not retry immediately."
            if e.code == 403 and (e.headers.get("Content-Type") or "").startswith("text/plain"):
                text = e.read(4096).decode("utf-8", "replace")
                if text.startswith("glove netgate refused"):
                    return _policy(url, text.strip())
            return f"HTTP {e.code} for {url}"
        except (urllib.error.URLError, OSError, http.client.HTTPException) as e:
            # urllib does not say why a tunnel failed; ask the proxy once. A 403
            # is a policy decision, not a network failure.
            refused = tunnel_refusal(url)
            if refused is not None:
                return _policy(url, refused)
            cause = getattr(e, "reason", None) or e
            if isinstance(cause, socket.timeout):
                cause = "timed out"
            return (f"Fetch failed for this URL ({cause}). This is a per-request failure, not necessarily an "
                    "egress outage. Over Tor many sites block exit-node traffic — retry once or try a different "
                    "source. If web_search is also failing, the egress itself may be down.")
    assert res is not None
    with res:
        body = res.read(MAX_BODY).decode(res.headers.get_content_charset() or "utf-8", "replace")
        ctype = res.headers.get("Content-Type") or ""
    if raw:
        out = body
    elif not re.search(r"html|xml", ctype, re.I):
        out = f"[content-type: {ctype or 'unknown'}]\n\n" + body
    else:
        out = html_to_text(body)
    text = out.strip()
    footer = f"\n\n[fetched: {url} | {ctype.split(';')[0] or '?'} | via egress]"
    if len(text) > max_chars:
        text = text[:max_chars]
        footer = f"\n\n[truncated to {max_chars} chars]" + footer
    return text + footer


def main() -> None:
    from mcp.server.fastmcp import FastMCP
    from mcp.server.transport_security import TransportSecuritySettings

    mcp = FastMCP(
        "webfetch", host="0.0.0.0", port=8000, stateless_http=True, json_response=True,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True, allowed_hosts=[ALLOWED_HOST] if ALLOWED_HOST else [],
            allowed_origins=[]),
    )

    @mcp.tool()
    def fetch_url(url: str, max_chars: int = 20000, raw: bool = False) -> str:
        """Fetch a URL and return its main text content (HTML converted to readable
        text, no JavaScript). Routed through the session's egress proxy; public web
        pages only. Use it to read a page found with web_search. Shares one exit IP:
        on a rate-limit error, back off rather than retrying immediately.
        `max_chars` truncates the output (default 20000); `raw` returns the HTML."""
        return fetch(url, max_chars, raw)

    mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()
