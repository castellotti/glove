"""Live web_download (round 10) for a session directory, through glove's own launch path.

    uv run python tests/integration/downloads_live.py <session-dir>

The session has an egress provider, `webfetch: {downloads: work}`, observe +
filter, and its llm pointed at the tool-driving stub. It checks, against real
containers and the harness's real tool path (Pi's web_download, the
webdownload MCP for Vibe and Claude Code):
  1. the fetcher binds <session>/downloads (never a path under work/), the
     harness reads it at /work/downloads read-only: a tool command can neither
     write there nor plant a link; the harness-only vars (GLOVE_FETCH_PROXY, …)
     are not in a tool command's env;
  2. a small PDF downloads to /work/downloads/, its sha256 matches the host
     file's and the shell's; the fetch tool (Pi, Vibe) describes the PDF
     instead of returning it; with OCR set, `glove-ocr --pages 1-2` reads it;
  3. a plain http:// page (the Wayback CDX API) through the fetch tool, and
     with observe the flow says proto http (Pi, Vibe);
  4. a filter block on a host: web_download is refused by the policy, nothing saved;
  5. a large file (BIG: Debian netinst, or `dvd`) runs as a job: the call
     returns a job id, the .part grows, the harness answers meanwhile, the
     fetcher's memory stays flat, the final sha256 matches Debian's SHA256SUMS;
  6. a fetcher restart: it still binds <session>/downloads and downloads again;
  7. `glove downloads mark` (macOS) stamps com.apple.quarantine on the saved
     files and leaves an already stamped one alone; at the end `glove down`
     stamps one saved after that;
  8. a reserve above the free space (min_free, relaunch): web_download refuses;
  then tears down. Prints PASS/FAIL per check; exit 0 only if all pass.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

from live_common import check, glove, inspect, live_session, summary, tool_result, wait_for

PDF = "https://www.worldradiohistory.com/Archive-Hands-On-Electronics/Hands-On-1987-01.pdf"
CDX = "http://web.archive.org/cdx/search/cdx?url=theoldrobots.com&matchType=domain&limit=5"
BLOCKED = "https://httpbin.org/bytes/4096"
DEBIAN = "https://cdimage.debian.org/debian-cd/current/amd64/{}/"
HIDDEN = ("GLOVE_FETCH_PROXY", "GLOVE_DOWNLOAD_MCP_URL", "GLOVE_FETCH_ALLOW")


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        while b := f.read(1 << 20):
            h.update(b)
    return h.hexdigest()


def big_file() -> tuple[str, str]:
    """(url, sha256) of the current Debian netinst ISO (BIG=dvd: the first DVD)."""
    kind = "iso-dvd" if os.environ.get("BIG") == "dvd" else "iso-cd"
    base = DEBIAN.format(kind)
    sums = urllib.request.urlopen(base + "SHA256SUMS", timeout=30).read().decode()
    want = "DVD-1.iso" if kind == "iso-dvd" else "netinst.iso"
    digest, name = next(ln.split() for ln in sums.splitlines() if ln.endswith(want) and "-edu-" not in ln)
    return base + name, digest


def mem_mib(rt: str, container: str) -> float:
    out = subprocess.run([rt, "stats", "--no-stream", "--format", "{{.MemUsage}}", container],
                         capture_output=True, text=True).stdout.split("/")[0].strip()
    m = re.fullmatch(r"([\d.]+)\s*([KMG]i?B|B)", out)
    if not m:
        return -1
    return float(m[1]) * {"B": 1 / 2**20, "KiB": 1 / 1024, "KB": 1 / 1024, "MiB": 1, "MB": 1,
                          "GiB": 1024, "GB": 1024}[m[2]]


def main(directory: str) -> int:
    with live_session(directory, logs="fetcher") as live:
        rt, s, comp = live.rt, live.prefix, live.plan.composition
        out_dir = live.sd.root / "downloads"
        dl, status, fetch = live.tools["download"], live.tools["download_status"], live.tools["fetch"]
        cc = live.cfg.harness == "claude-code"

        def download(url: str, wait_s: int = 45) -> str:
            return tool_result(live.call(dl, {"url": url, "wait_s": wait_s}, timeout=300), 1500)

        def bind_source() -> str:
            mounts = inspect(rt, f"{s}-fetcher").get("Mounts") or []
            return next((m.get("Source", "") for m in mounts if m.get("Destination") == "/run/glove-output/downloads"),
                        "")

        print("== binds and the shell's view")
        src = bind_source()
        check("the fetcher binds <session>/downloads", os.path.realpath(src) == os.path.realpath(out_dir), src)
        out = live.sh("touch /work/downloads/x; echo rc=$?; ln -s /home/agent /work/downloads/evil.part; echo rc=$?; "
                      "ls -A /work/downloads | wc -l")
        check("a tool command can't write /work/downloads or plant a link there",
              out.count("rc=1") == 2 and not (out_dir / "evil.part").is_symlink(), out[-240:])
        out = live.sh("env | grep -o '^GLOVE_[A-Z_]*' | sort | tr '\\n' ' '; echo END")
        check("no harness-only var in a tool command's env", "END" in out and not any(n in out for n in HIDDEN),
              out[-200:])

        print(f"== {dl}: a small PDF")
        res = download(PDF)
        print(f"    {res[-500:]}")
        m = re.search(r"saved: /work/downloads/([^\s\\\"]+)", res)
        digest = (re.search(r"sha256: ([0-9a-f]{64})", res) or [None, ""])[1]
        saved = out_dir / m[1] if m else None
        check("web_download saves the PDF and says its sha256", bool(saved and saved.is_file() and digest), res[-200:])
        if saved and saved.is_file():
            check("its sha256 matches the host file's", sha256(saved) == digest, digest)
            out = live.sh(f"sha256sum /work/downloads/{m[1]}")
            check("…and the shell's", digest in out, out[-120:])
            if comp.by_name("ocr"):
                out = live.sh(f"glove-ocr --pages 1-2 /work/downloads/{m[1]} > /tmp/ocr.txt 2>&1; "
                              "echo rc=$? words=$(wc -w < /tmp/ocr.txt); head -c 300 /tmp/ocr.txt")
                words = re.search(r"rc=0 words=(\d+)", out)
                check("glove-ocr --pages 1-2 reads it from the shell", bool(words) and int(words[1]) > 20,
                      out[-200:])
        if not cc:  # Claude Code's WebFetch is its own
            out = tool_result(live.call(fetch, {"url": PDF}, timeout=240), 600)
            check(f"{fetch} describes the PDF, never returns it", "[binary: application/pdf" in out, out[-200:])
            out = tool_result(live.call(fetch, {"url": CDX}, timeout=240), 600)
            check(f"{fetch} reads a plain http:// page (Wayback CDX)", "theoldrobots.com" in out, out[-200:])
            if comp.by_name("observe"):
                svc = "webfetch-egress" if live.cfg.harness == "vibe" else "proxy"
                protos = [r.get("proto") for r in live.flows() if r.get("service") == svc
                          and (r.get("dest") or {}).get("host") == "web.archive.org"
                          and r["dest"].get("port") == 80]
                check("flow: → http://web.archive.org/ unwrapped (proto http)",
                      bool(protos) and set(protos) == {"http"}, f"protos {protos}")

        if comp.by_name("filter"):
            print("== filter")
            r = glove("filter", "block", "httpbin.org", "--dir", str(live.sd.root))
            check("glove filter block httpbin.org", r.returncode == 0, (r.stdout + r.stderr)[-200:])
            time.sleep(2)  # the gates reload within ~1 s
            res = download(BLOCKED)
            print(f"    {res[-300:]}")
            check("web_download is refused by the policy", "network policy" in res
                  and not any(p.name.startswith("4096") for p in out_dir.iterdir()), res[-200:])
            glove("filter", "unblock", "httpbin.org", "--dir", str(live.sd.root))

        print("== a large file as a job")
        url, want = big_file()
        name = url.rsplit("/", 1)[1]
        part = out_dir / f"{name}.part"
        res = download(url, wait_s=5)
        print(f"    {res[-300:]}")
        job = (re.search(r"started: (d\d+)", res) or [None, ""])[1]
        check("the call returns a job id", bool(job), res[-200:])
        grew = wait_for(lambda: part.exists() and part.stat().st_size > 50 << 20, timeout=300, step=2)
        check(".part grows on the host", bool(grew), f"{part.stat().st_size if part.exists() else 0} B")
        out = live.sh("echo PARTS=$(ls -la /work/downloads/ | grep -c '\\.part$')")
        check("…and the shell sees it", "PARTS=1" in out, out[-80:])
        out = tool_result(live.call(status, {"id": job}, timeout=240), 600)
        check(f"{status} reports it running", "running" in out or "writing" in out or "saved:" in out, out[-200:])
        out = live.sh("echo still-here")
        check("the harness answers meanwhile", "still-here" in out, out[-80:])
        mems, done = [], threading.Event()

        def sample() -> None:
            while not done.is_set():
                mems.append(mem_mib(rt, f"{s}-fetcher"))
                time.sleep(5)

        threading.Thread(target=sample, daemon=True).start()
        t = time.time()
        finished = wait_for(lambda: (out_dir / name).is_file() and not part.exists(), timeout=3600, step=5)
        done.set()
        size = (out_dir / name).stat().st_size if finished else 0
        print(f"    {size / 2**20:.0f} MiB in {time.time() - t:.0f}s; "
              f"fetcher memory MiB {min(mems or [0]):.0f}..{max(mems or [0]):.0f}")
        check("the job finishes", bool(finished))
        check("the fetcher's memory stays flat (< 256 MiB)", bool(mems) and 0 < max(mems) < 256,
              f"max {max(mems or [0]):.0f} MiB over {len(mems)} samples")
        if finished:
            check("sha256 matches Debian's SHA256SUMS", sha256(out_dir / name) == want, want)
            out = tool_result(live.call(status, {"id": job}, timeout=240), 600)
            check(f"{status} says saved with that sha256", want in out, out[-200:])

        print("== a fetcher restart")
        subprocess.run([rt, "restart", f"{s}-fetcher"], capture_output=True, check=True)
        wait_for(lambda: inspect(rt, f"{s}-fetcher").get("State", {}).get("Health", {}).get("Status") == "healthy",
                 timeout=60)
        check("after a restart the fetcher still binds <session>/downloads", bind_source() == src, bind_source())
        res = download("https://www.worldradiohistory.com/robots.txt")
        check("…and downloads there", "saved: /work/downloads/robots" in res, res[-200:])

        if sys.platform == "darwin":
            print("== quarantine")
            xattr = subprocess.run(["xattr", "-w", "com.apple.quarantine", "00c1;0;Finder;", str(saved)])
            r = glove("downloads", "mark", str(live.sd.root))
            print(f"    {(r.stdout + r.stderr).strip()[-300:]}")
            attr = {p.name: subprocess.run(["xattr", "-p", "com.apple.quarantine", str(p)], capture_output=True,
                                           text=True).stdout.strip() for p in out_dir.iterdir()}
            print(f"    {attr}")
            check("glove downloads mark stamps every saved file", r.returncode == 0 and all(
                v.startswith(("0081;", "00c1;")) for v in attr.values()), str(attr)[:300])
            check("…and keeps an existing attribute (an approval)",
                  xattr.returncode == 0 and attr.get(saved.name) == "00c1;0;Finder;", attr.get(saved.name, ""))

            # one more, left unstamped for `glove down` (below)
            fresh = re.search(r"saved: /work/downloads/([^\s\\\"]+)",
                              download("https://www.worldradiohistory.com/robots.txt"))

        print("== min_free above the free space")
        session = live.sd.root / "glove-session.yml"
        session.write_text(session.read_text().replace("downloads: work", "downloads: work, min_free: 900000g"))
        live.relaunch()
        res = download("https://www.worldradiohistory.com/robots.txt")
        print(f"    {res[-300:]}")
        check("web_download refuses below the reserve", "free-space reserve" in res, res[-200:])

        if sys.platform == "darwin":
            print("== glove down")
            r = glove("down", str(live.sd.root))
            print(f"    {(r.stdout + r.stderr).strip()[-200:]}")
            attr = subprocess.run(["xattr", "-p", "com.apple.quarantine", str(out_dir / fresh[1])],
                                  capture_output=True, text=True).stdout.strip() if fresh else ""
            check("glove down stamps a file saved after the last mark", r.returncode == 0
                  and attr.startswith("0081;") and "quarantined 1 " in r.stdout, f"{fresh and fresh[1]}: {attr}")
    return summary()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
