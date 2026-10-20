#!/usr/bin/env python3
"""MCP server exposing `fetch_url` (one web page as readable text, for Pi and
Vibe) and, with webfetch downloads on, `web_download`/`web_download_status`
(files saved to /work, for every harness), all through the session's egress
proxy.

Runs in the `fetcher` sidecar and serves streamable HTTP on :8000 (stateless,
plain JSON responses), which the harness reaches through the `webfetch-mcp`
and `webdownload-mcp` forwarders; requests must name one as their Host (`MCP_ALLOWED_HOST`, a list).
fetch_url goes through GLOVE_FETCH_PROXY and downloads through
GLOVE_DOWNLOAD_PROXY (the egress provider's proxy, or with observe a gate in
front of it, one per tool): the sidecar has no other route. Each tool is served
only when its variable is set.

The destination guard refuses anything that is not plainly a public internet
host, judged by shape only and never resolved, before the request is sent and
again on every redirect hop. Under the
`corporate` egress the operator's allowlist (GLOVE_FETCH_ALLOW) is let through
even when private; this machine, link-local/metadata and multicast stay refused.
When the egress gate refuses a request (a filter rule, the corporate allowlist,
the SSRF guard), the agent is told it was refused by policy, not that the
network failed. Standard library only, bar the MCP server itself.
"""

from __future__ import annotations

import asyncio
import contextlib
import email.utils
import fnmatch
import hashlib
import http.client
import ipaddress
import os
import re
import socket
import stat
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser

PROXY = os.environ.get("GLOVE_FETCH_PROXY", "")
ALLOW = [x.strip().lower() for x in os.environ.get("GLOVE_FETCH_ALLOW", "").split(",") if x.strip()]
ALLOWED_HOSTS = [x.strip() for x in os.environ.get("MCP_ALLOWED_HOST", "").split(",") if x.strip()]
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
MAX_BODY = 5 * 1024 * 1024
MAX_REDIRECTS = 5
TIMEOUT = 45
SNIFF = 4096  # bytes of the body read to look for NUL before deciding text or binary

# --- the destination guard (guard.ts) -------------------------------------------

LOCAL_SUFFIXES = (".localhost", ".local", ".internal", ".lan", ".home.arpa", ".intranet", ".corp")
HARD_NAMES = ("localhost", "host.docker.internal", "gateway.docker.internal", "host.containers.internal",
              "metadata.google.internal")


def _v4(ip: str) -> list[int]:
    return [int(x) for x in ip.split(".")]


def _canonical(host: str) -> str | None:
    """`host` in the one spelling the guard judges, or None for an IPv4 address
    written any other way (`0xa.0.0.1`, `012.0.0.1`, `127.1`, `10.1`). Node's URL
    rewrites those to dotted quads before guard.ts sees them; urlsplit does not,
    and the resolver behind the proxy (inet_aton) reads them as addresses."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        try:
            socket.inet_aton(host)
        except (OSError, ValueError):
            return host
        return None
    if ip.version == 6:
        return f"::ffff:{ip.ipv4_mapped}" if ip.ipv4_mapped else ip.compressed
    return host


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
    host = _canonical((u.hostname or "").lower().rstrip("."))
    if host is None:
        return f"{u.hostname} is an IP address in a non-standard form"
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


def _opener(proxy: str) -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy, "https": proxy}), _NoRedirect)


def tunnel_refusal(url: str, proxy: str) -> str | None:
    """The egress gate's refusal text if it answers a CONNECT for `url` with 403, else None."""
    p, u = urllib.parse.urlsplit(proxy), urllib.parse.urlsplit(url)
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


# --- what a fetch makes of a response it won't read as text ---------------------

TEXT = re.compile(r"(text/.+|[^/]+/([^/]+\+)?(json|xml|yaml)|"
                  r"application/(x-)?(javascript|ecmascript|yaml|toml|ndjson|sql|graphql|sh|shellscript))")
UNKNOWN = ("", "application/octet-stream", "binary/octet-stream")


def is_binary(ctype: str, head: bytes) -> bool:
    """Whether a response is binary: by its content type, or for a text or
    unlabelled one by a NUL in the first SNIFF bytes of `head`."""
    mime = ctype.split(";")[0].strip().lower()
    if mime not in UNKNOWN and not TEXT.fullmatch(mime):
        return True
    return b"\0" in head[:SNIFF]


def binary_notice(tool: str, url: str, ctype: str, length: str | None, read: int, can_download: bool) -> str:
    """The agent's text for a binary response (`length`: Content-Length, else
    the bytes read, as a lower bound)."""
    size = (f"{length} bytes" if re.fullmatch(r"[0-9]+", length or "")
            else f"≥{read} bytes" if read else "size unknown")
    return (f"[binary: {ctype.split(';')[0].strip() or 'unknown type'}, {size}] {url}\n"
            f"{tool} returns text only. "
            + ("Use web_download to save the file, then open it with a shell tool the session has "
               "(e.g. pdftotext, 7z)." if can_download
               else "This session has no web_download: ask the operator to provide this file."))


def rate_limited(retry_after: str | None, now: float | None = None) -> str:
    """The agent's text for a 429, with the server's Retry-After (seconds or an
    HTTP date) when it sent one."""
    v = (retry_after or "").strip()
    s = None
    if re.fullmatch(r"[0-9]+", v):
        s = int(v)
    elif v:
        # a date counts only in RFC 9110's one form (IMF-fixdate), as it reads back
        with contextlib.suppress(TypeError, ValueError):
            date = email.utils.parsedate_to_datetime(v)
            if email.utils.format_datetime(date, usegmt=True) == v:
                s = round(date.timestamp() - (time.time() if now is None else now))
    return "Rate-limited (HTTP 429). Back off; " + (
        f"the server asks to wait {s} s before retrying." if s and s > 0 else "do not retry immediately.")


class Refusal(Exception):
    """A fetch that ends in a message for the agent instead of a response
    (`status`: the HTTP status that caused it, if any)."""

    def __init__(self, message: str, status: int = 0) -> None:
        super().__init__(message)
        self.status = status


def open_url(url: str, headers: dict[str, str], proxy: str, timeout: float):
    """GET `url` through `proxy`, following redirects by hand so every hop passes
    the guard: (response, final url). Raises Refusal with the agent's message."""
    opener = _opener(proxy)
    for hop in range(MAX_REDIRECTS + 1):
        try:
            return opener.open(urllib.request.Request(url, headers=headers), timeout=timeout), url
        except urllib.error.HTTPError as e:
            loc = e.headers.get("Location")
            if 300 <= e.code < 400 and loc:
                if hop >= MAX_REDIRECTS:
                    break
                nxt = urllib.parse.urljoin(url, loc)
                why = refusal(nxt)
                if why:
                    raise Refusal(f"Refused a redirect to {nxt}: {why}.") from None
                url = nxt
                continue
            if e.code == 429:
                raise Refusal(rate_limited(e.headers.get("Retry-After")), e.code) from None
            if e.code == 403 and (e.headers.get("Content-Type") or "").startswith("text/plain"):
                text = e.read(4096).decode("utf-8", "replace")
                if text.startswith("glove netgate refused"):
                    raise Refusal(_policy(url, text.strip())) from None
            raise Refusal(f"HTTP {e.code} for {url}", e.code) from None
        except (urllib.error.URLError, OSError, http.client.HTTPException) as e:
            cause = getattr(e, "reason", None) or e
            # urllib drops the body of a refused tunnel; only a 403 is a policy
            # decision worth asking the proxy about (once).
            if str(cause).startswith("Tunnel connection failed: 403"):
                refused = tunnel_refusal(url, proxy)
                if refused is not None:
                    raise Refusal(_policy(url, refused)) from None
            if isinstance(cause, socket.timeout):
                cause = "timed out"
            raise Refusal(
                f"Fetch failed for this URL ({cause}). This is a per-request failure, not necessarily an "
                "egress outage. Over Tor many sites block exit-node traffic — retry once or try a different "
                "source. If web_search is also failing, the egress itself may be down.") from None
    raise Refusal(f"Too many redirects from {url}")


def fetch(url: str, max_chars: int = 20000, raw: bool = False) -> str:
    if not PROXY:
        return ("fetch_url is not configured: GLOVE_FETCH_PROXY is unset, so there is no egress path. "
                "Refusing to fetch directly.")
    why = refusal(url)
    if why:
        return f"Refused: {why}. fetch_url reads public web pages only."
    headers = {"User-Agent": UA, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"}
    try:
        res, url = open_url(url, headers, PROXY, TIMEOUT)
    except Refusal as e:
        return str(e)
    with res:
        # read SNIFF bytes, decide text or binary, and only then the rest: a
        # binary body is never read further, nor returned
        ctype = res.headers.get("Content-Type") or ""
        data = b""
        binary = is_binary(ctype, data)
        if not binary:
            data = res.read(SNIFF)
            binary = is_binary(ctype, data)
        if binary:
            return binary_notice("fetch_url", url, ctype, res.headers.get("Content-Length"), len(data),
                                 bool(DOWNLOADS))
        data += res.read(MAX_BODY - len(data))
        try:
            body = data.decode(res.headers.get_content_charset() or "utf-8", "replace")
        except LookupError:  # a charset Python does not know
            body = data.decode("utf-8", "replace")
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


# --- web_download: files saved to the downloads dir, as background jobs ------------
#
# Only this sidecar writes the files: its one writable bind is the session's
# downloads dir (DOWNLOADS here; the agent reads it at /work/downloads, and
# cannot write it). A link planted there would resolve inside this container,
# never into the harness's home. A file
# streams to <name>.part (created O_EXCL|O_NOFOLLOW), is hashed on the way and
# is linked to <name> only when complete, never over an existing file. No size
# cap: the reserve (GLOVE_MIN_FREE) is the free space a download must leave on
# the host volume, checked before it starts and as it grows.

DOWNLOADS = os.environ.get("GLOVE_DOWNLOADS", "")
DOWNLOAD_PROXY = os.environ.get("GLOVE_DOWNLOAD_PROXY", "")
SHOWN_AS = os.environ.get("GLOVE_DOWNLOADS_SHOWN_AS", "/work/downloads")  # DOWNLOADS as the agent sees it
MAX_JOBS = 3  # running at once, per session: one exit IP is shared
MAX_WAIT = 45  # seconds a call waits for its job (under every client's 60 s tool timeout)
IDLE_TIMEOUT = 120  # per read, never for the whole download
MAX_NAME = 200
CHUNK = 1 << 20
CHECK_EVERY = 64 << 20  # bytes between free-space checks
STATUS_RECENT = 5  # finished jobs web_download_status lists (besides running and resumable ones)


def parse_size(text: str) -> int:
    m = re.fullmatch(r"([0-9]+)([kmgKMG]?)", text.strip())
    if not m:
        raise ValueError(f"not a size: {text!r}")
    return int(m.group(1)) << {"": 0, "k": 10, "m": 20, "g": 30}[m.group(2).lower()]


MIN_FREE_TEXT = os.environ.get("GLOVE_MIN_FREE") or "2g"
MIN_FREE = parse_size(MIN_FREE_TEXT)


def human(n: float | None) -> str:
    if n is None:
        return "?"
    if n < 1024:
        return f"{int(n)} B"
    for unit in ("KiB", "MiB", "GiB"):
        n /= 1024
        if n < 1024 or unit == "GiB":
            return f"{n:.1f} {unit}"
    raise AssertionError  # the loop returns at GiB


def safe_name(name: str) -> str:
    """A plain file name: the last path segment, no leading dot, only
    [A-Za-z0-9._+-], at most MAX_NAME characters (keeping the extension)."""
    base = re.sub(r"[^A-Za-z0-9._+-]", "_", re.split(r"[/\\]", name)[-1]).lstrip(".")
    if len(base) > MAX_NAME:
        stem, ext = os.path.splitext(base)
        ext = ext[:20]
        base = stem[:MAX_NAME - len(ext)] + ext
    return base or "download"


def url_name(url: str) -> str:
    return urllib.parse.unquote(urllib.parse.urlsplit(url).path.rsplit("/", 1)[-1])


class Job:
    def __init__(self, id: str, url: str) -> None:
        self.id, self.url = id, url
        self.name = ""  # the final file name in DOWNLOADS (its .part while running)
        self.final_url = ""
        self.state = "starting"  # starting | running | done | failed
        self.bytes = 0
        self.total: int | None = None
        self.content_type = ""
        self.sha256 = ""
        self.error = ""
        self.resumable = False  # failed with its .part kept: the server takes ranges
        self.validator = ""  # ETag or Last-Modified: If-Range on a resume
        self.inode = 0
        self.digest = hashlib.sha256()  # of the .part's first `bytes`, kept for a resume
        self.since = self.since_bytes = 0  # when (and at which byte) this attempt began writing
        self.done = threading.Event()

    @property
    def running(self) -> bool:
        return self.state in ("starting", "running")


_jobs: list[Job] = []
_lock = threading.Lock()


def _path(name: str) -> str:
    return os.path.join(DOWNLOADS, name)


def _free() -> int:
    st = os.statvfs(DOWNLOADS)
    return st.f_bavail * st.f_frsize


def _check_free(need: int | None) -> None:
    """Refuse when `need` more bytes would leave less than the reserve free."""
    if _free() - (need or 0) < MIN_FREE:
        what = f"saving {human(need)} more" if need else "continuing"
        raise Refusal(f"Refused: {what} would leave less than the {MIN_FREE_TEXT} free-space reserve on the "
                      "host volume. Tell the user; do not retry.")


def _candidates(name: str):
    """`name`, then `stem-1.ext`, `stem-2.ext`, …"""
    stem, ext = os.path.splitext(name)
    yield name
    yield from (f"{stem}-{n}{ext}" for n in range(1, 1000))


def _no_name(name: str) -> Refusal:
    return Refusal(f"Refused: no free file name for {name} in {SHOWN_AS}")


def _claim(name: str) -> tuple[str, int]:
    """A name free in DOWNLOADS with its .part created exclusively, never
    through a link: (name, fd)."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    with _lock:  # a running or resumable job's name is held by its .part
        for cand in _candidates(name):
            if os.path.lexists(_path(cand)):
                continue
            try:
                return cand, os.open(_path(cand + ".part"), flags, 0o644)
            except FileExistsError:
                continue
    raise _no_name(name)


def _reopen(job: Job) -> int:
    """The failed job's .part, cut to the bytes its digest covers, to append
    to; -1 when it is gone or is no longer the file this job wrote."""
    try:
        fd = os.open(_path(job.name + ".part"), os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return -1
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_ino != job.inode or st.st_size < job.bytes:
        os.close(fd)
        return -1
    os.ftruncate(fd, job.bytes)  # a write cut short may have left a few more
    os.lseek(fd, 0, os.SEEK_END)
    return fd


def _publish(job: Job, fd: int) -> None:
    """Link the finished .part to a free final name (never replacing a file),
    then drop the .part. Refuses if the .part was swapped while writing."""
    part = _path(job.name + ".part")
    try:
        same = os.lstat(part).st_ino == os.fstat(fd).st_ino
    except OSError:
        same = False
    if not same:
        raise Refusal(f"{SHOWN_AS}/{job.name}.part was moved or replaced during the download")
    for cand in _candidates(job.name):
        try:
            os.link(part, _path(cand), follow_symlinks=False)
        except FileExistsError:
            continue
        except OSError:  # a filesystem without hard links
            if os.path.lexists(_path(cand)):
                continue
            os.rename(part, _path(cand))
        else:
            os.unlink(part)
        job.name = cand
        return
    raise _no_name(job.name)


def _write(fd: int, data: memoryview) -> None:
    while data:
        data = data[os.write(fd, data):]


def _rewind(job: Job, fd: int) -> None:
    """Empty the job's .part to download it again from the start."""
    os.ftruncate(fd, 0)
    os.lseek(fd, 0, os.SEEK_SET)
    job.bytes, job.digest = 0, hashlib.sha256()


def _run(job: Job, name: str | None) -> None:
    """One download (or the resume of a failed one), on its own thread. A
    failure keeps the .part, to resume, when the server takes byte ranges."""
    fd, ranges = -1, False
    try:
        headers = {"User-Agent": UA, "Accept": "*/*", "Accept-Encoding": "identity"}
        if job.resumable:
            fd = _reopen(job)
            if fd >= 0:
                ranges = True
                headers["Range"] = f"bytes={job.bytes}-"
                if job.validator:
                    headers["If-Range"] = job.validator
        if fd < 0:  # a fresh download (or the .part is gone or replaced): under a fresh name
            job.name, job.bytes, job.digest = "", 0, hashlib.sha256()
        job.resumable = False
        try:
            res, job.final_url = open_url(job.url, headers, DOWNLOAD_PROXY, IDLE_TIMEOUT)
        except Refusal as e:
            if fd < 0 or e.status != 416:
                raise
            # the .part is no longer a prefix of the file: start over
            headers.pop("Range"), headers.pop("If-Range", None)
            _rewind(job, fd)
            res, job.final_url = open_url(job.url, headers, DOWNLOAD_PROXY, IDLE_TIMEOUT)
        with res:
            if job.bytes and res.status != 206:  # the file changed, or ranges are off: start over
                _rewind(job, fd)
            offset = job.bytes
            length = res.headers.get("Content-Length", "")
            job.total = offset + int(length) if length.isdigit() else None
            job.content_type = (res.headers.get("Content-Type") or "").split(";")[0].strip()
            etag = res.headers.get("ETag", "")
            job.validator = etag if etag and not etag.startswith("W/") else res.headers.get("Last-Modified", "")
            ranges = res.status == 206 or res.headers.get("Accept-Ranges", "").lower() == "bytes"
            _check_free(job.total - offset if job.total is not None else None)
            if fd < 0:
                job.name, fd = _claim(safe_name(name or res.headers.get_filename() or url_name(job.final_url)))
                job.inode = os.fstat(fd).st_ino
            job.since, job.since_bytes, job.state = time.monotonic(), offset, "running"
            buf, checked = bytearray(CHUNK), offset
            while n := res.readinto(buf):
                chunk = memoryview(buf)[:n]
                _write(fd, chunk)
                job.digest.update(chunk)
                job.bytes += n
                if job.bytes - checked >= CHECK_EVERY:
                    checked = job.bytes
                    _check_free(None)
        if job.total is not None and job.bytes < job.total:
            raise Refusal(f"the connection closed after {human(job.bytes)} of {human(job.total)}")
        _publish(job, fd)
        job.sha256, job.state = job.digest.hexdigest(), "done"
    except Refusal as e:
        job.error = str(e)
    except (OSError, http.client.HTTPException, ValueError) as e:
        job.error = f"no data for {IDLE_TIMEOUT} s (idle timeout)" if isinstance(e, socket.timeout) else str(e)
    finally:
        if fd >= 0:
            os.close(fd)
        if job.state != "done":
            job.state = "failed"
            job.resumable = ranges and job.bytes > 0 and bool(job.name)
            if job.name and not job.resumable:
                with contextlib.suppress(OSError):
                    os.unlink(_path(job.name + ".part"))
        job.done.set()


def describe(job: Job) -> str:
    if job.state == "done":
        return (f"saved: {SHOWN_AS}/{job.name}\nbytes: {job.bytes}\nsha256: {job.sha256}\n"
                f"content_type: {job.content_type or 'unknown'}\nfinal_url: {job.final_url}")
    if job.state == "failed":
        keep = (f" {human(job.bytes)} are kept in {SHOWN_AS}/{job.name}.part: call web_download with the same "
                "URL to resume." if job.resumable else "")
        return f"Download {job.id} of {job.url} failed: {job.error.rstrip('.')}.{keep}"
    if job.state == "starting":
        return f"started: {job.id} (connecting). Check web_download_status('{job.id}')."
    rate = (job.bytes - job.since_bytes) / max(time.monotonic() - job.since, 1e-3)
    return (f"started: {job.id} → {SHOWN_AS}/{job.name} (writing {job.name}.part), {human(job.bytes)} of "
            f"{human(job.total)} at {human(rate)}/s. Check web_download_status('{job.id}') or "
            f"`ls -la {SHOWN_AS}`.")


def download(url: str, name: str | None = None, wait_s: float = 30) -> str:
    if not DOWNLOADS or not DOWNLOAD_PROXY:
        return "web_download is not configured for this session (webfetch downloads are off)."
    why = refusal(url)
    if why:
        return f"Refused: {why}. web_download fetches from public hosts only."
    with _lock:
        if sum(j.running for j in _jobs) >= MAX_JOBS:
            return (f"{MAX_JOBS} downloads are already running (they share one exit IP). Wait for one to finish: "
                    "web_download_status.")
        job = next((j for j in reversed(_jobs) if j.url == url and j.state == "failed" and j.resumable), None)
        if job is None:
            job = Job(id=f"d{len(_jobs) + 1}", url=url)
            _jobs.append(job)
        else:  # resume it
            job.state, job.error, job.done = "starting", "", threading.Event()
    threading.Thread(target=_run, args=(job, name), daemon=True).start()
    job.done.wait(max(0.0, min(float(wait_s), MAX_WAIT)))
    return describe(job)


def status(job_id: str | None = None) -> str:
    """One job, or the ones still running or resumable and the last few others."""
    if job_id:
        jobs = [j for j in _jobs if j.id == job_id]
    else:
        recent = set([j for j in _jobs if not (j.running or j.resumable)][-STATUS_RECENT:])
        jobs = [j for j in _jobs if j.running or j.resumable or j in recent]
    if not jobs:
        return f"No download {job_id}." if job_id else "No downloads yet."
    return "\n\n".join(describe(j) for j in jobs)


SYSTEM_ROOTS = "/etc/ssl/certs/ca-certificates.crt"


def trust_corporate_ca(extra: str, dest: str = "/tmp/ca-bundle.pem", roots: str = SYSTEM_ROOTS) -> None:
    """glove's `corporate_ca` (bound read-only at `extra`): every TLS context
    from here on trusts the image's roots and it (ssl reads SSL_CERT_FILE)."""
    with open(dest, "wb") as out:
        for path in (roots, extra):
            with open(path, "rb") as f:
                out.write(f.read().rstrip(b"\n") + b"\n")
    os.environ["SSL_CERT_FILE"] = dest


def main() -> None:
    from mcp.server.fastmcp import FastMCP

    if os.environ.get("GLOVE_CORPORATE_CA"):
        trust_corporate_ca(os.environ["GLOVE_CORPORATE_CA"])
    from mcp.server.transport_security import TransportSecuritySettings

    mcp = FastMCP(
        "webfetch", host="0.0.0.0", port=8000, stateless_http=True, json_response=True,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True, allowed_hosts=ALLOWED_HOSTS,
            allowed_origins=[]),
    )

    if PROXY:  # fetch_url: Pi, Vibe
        @mcp.tool()
        async def fetch_url(url: str, max_chars: int = 20000, raw: bool = False) -> str:
            """Fetch a URL and return its main text content (HTML converted to readable
            text, no JavaScript). Routed through the session's egress proxy; public web
            pages only. Use it to read a page found with web_search. Shares one exit IP:
            on a rate-limit error, back off rather than retrying immediately.
            `max_chars` truncates the output (default 20000); `raw` returns the HTML."""
            return await asyncio.to_thread(fetch, url, max_chars, raw)

    if DOWNLOADS:  # webfetch downloads: work
        @mcp.tool()
        async def web_download(url: str, name: str | None = None, wait_s: float = 30) -> str:
            """Download a file (PDF, archive, image, audio, ISO: any size) to /work/downloads/,
            through the session's egress proxy; public hosts only. Waits up to `wait_s`
            seconds (max 45): returns the saved path, size and sha256, or a job id
            while it is still running (check web_download_status, or `ls -la
            /work/downloads`: the .part file grows). `name` sets the file name (default:
            the server's, else the URL's). Calling it again with the URL of a failed
            download resumes it. Treat downloaded files as untrusted."""
            return await asyncio.to_thread(download, url, name, wait_s)

        @mcp.tool()
        def web_download_status(id: str | None = None) -> str:
            """The state of web_download jobs (all, or the one with this id): bytes
            so far, total, rate, and when finished the path and sha256, or the error."""
            return status(id)

    mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()
