"""Live ocr + rag (v3 M6) for a session directory, through glove's own launch path.

    STUB_LOG=<stub log> uv run python tests/integration/rag_live.py <session-dir>

The session must have `ocr` and `rag` (models_dir holding the fastembed model,
optionally obsidian_dir), its llm pointed at the tool-driving stub
(tests/integration/stubs/llm_stub.py), and work/data/input/ holding the OCR
fixtures plus a small note. Every command runs as the agent's own: a
stub-driven Pi `bash` tool call, inside the nono tool sandbox. It checks:
  1. the session is offline (no egress provider, only the llm forwarder); the
     model (and claude-obsidian) dirs are read-only mounts;
  2. `glove-ocr` reads a PNG, a scanned PDF page (OCR) and a text-layer PDF;
  3. `kstore sync` parses the tiny corpus (OCR'ing the scan and the image),
     builds the vector index with the mounted model, offline, and writes vault
     pages; `kstore ask` cites the scanned page for a question only it answers;
  4. the model dir is read-only to the agent; the shell has no network;
  5. Pi lists the rag skills (and claude-obsidian's, when mounted) in its
     system prompt;
  then tears down. Prints PASS/FAIL per check; exit 0 only if all pass.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import yaml

from glove.cli import _materialize_plan, _open, _resolve_extensions
from glove.harnessconfig import render_home
from glove.plan import secret_env
from glove.session import _compose_base, ensure_images, start_sidecars

results: list[tuple[str, bool]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok))
    print(f"  {'PASS' if ok else 'FAIL'} {name}" + (f"  ({detail})" if detail else ""), flush=True)


def main(directory: str) -> int:
    sd, _, sid, cfg = _open(Path(directory))
    rt = cfg.provider
    base = None
    env = dict(os.environ)
    try:
        plan, _, _ = _materialize_plan(sd, sid, cfg)
        env = {**os.environ, **secret_env(plan)}
        base = _compose_base(rt, plan.project, sd.compose)
        t = time.time()
        ensure_images(cfg, plan, rt)
        print(f"  (images ready in {time.time() - t:.0f}s: {plan.image})", flush=True)
        start_sidecars(plan, sd.compose, provider=rt, env=env)
        comp = plan.composition
        _resolve_extensions(plan, rt, {k: v for k, v in env.items() if k.startswith("GLOVE_")})
        render_home(cfg, plan.profile, sd.home, plan.model, mount_plan=plan.mount_plan, comp=comp)

        print("== offline, read-only mounts")
        check("no egress provider; the only endpoint is the llm",
              "egress" not in comp.slots and [e.name for e in comp.endpoints] == ["llm"])
        hv = yaml.safe_load(sd.compose.read_text())["services"][plan.harness_service]["volumes"]
        binds = {v["target"]: v for v in hv if v.get("type") == "bind"}
        want = ["/mnt/rag-models"] + (["/mnt/rag-obsidian"] if "obsidian" in comp.by_name("rag").mounts else [])
        check("model (and claude-obsidian) dirs are read-only binds",
              all(binds.get(t, {}).get("read_only") is True for t in want), ", ".join(want))

        def bash(command: str, timeout: int = 900) -> str:
            cmd = [*plan.harness_command, "-p", f"CALL bash {json.dumps({'command': command})}"]
            r = subprocess.run([*base, "run", "--rm", "-T", plan.harness_service, *cmd], env=env,
                               stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout)
            out = (r.stdout.strip() or r.stderr.strip())[-320:]
            print(f"    $ {command[:90]}\n      {out}", flush=True)
            return out

        print("== glove-ocr (Pi bash tool, nono tool sandbox)")
        out = bash("glove-ocr /work/data/input/sample.png")
        check("a PNG", "quick brown fox" in out.lower(), out[-80:])
        out = bash("glove-ocr /work/data/input/scanned.pdf --pages 2")
        check("a scanned PDF page is OCR'd", "=== page 2 (ocr) ===" in out and "PAGE TWO" in out)
        out = bash("glove-ocr /work/data/input/text-layer.pdf")
        check("a text-layer PDF is read directly", "=== page 1 (text) ===" in out and "real PDF text" in out)

        print("== kstore")
        out = bash("kstore sync 2>&1 | tail -4")
        check("kstore sync parses the corpus (scan and image OCR'd)", "+4 new" in out and "OCR'd 1" in out, out[-160:])
        out = bash("kstore ask 'When is invoice 4711 due?' --k 3 --json | python3 -c "
                   "\"import json,sys; c=json.load(sys.stdin)['citations'][0]; "
                   "print('TOP', c['source_path'], 'page', c.get('page_label'), '+'.join(c['found_by']))\"")
        check("kstore ask cites the scanned page, found by both stores",
              "TOP data/input/scanned.pdf page 1" in out and "llama+obsidian" in out, out[-100:])
        store = sd.work / "data" / "store"
        man = json.loads((store / "llama" / "raw" / "manifest.json").read_text())
        check("vector index built with the mounted model", man.get("embed_model") == "BAAI/bge-small-en-v1.5"
              and man.get("chunk_count", 0) >= 4, f"{man.get('embed_model')} {man.get('chunk_count')} chunks")
        pages = list((store / "vault").rglob("*.md"))
        check("vault source pages written", len(pages) >= 4, f"{len(pages)} pages")

        print("== confinement")
        out = bash("touch /mnt/rag-models/x 2>&1; echo rc=$?")
        check("the model dir is read-only to the agent", "rc=0" not in out, out[-80:])
        out = bash("python3 -c \"import socket; socket.create_connection(('1.1.1.1', 443), 3)\" 2>&1 | tail -1; "
                   "echo rc=$?")
        check("the shell has no network", "Error" in out or "error" in out, out[-90:])

        print("== skills in Pi's system prompt")
        log = Path(os.environ["STUB_LOG"]).read_text() if os.environ.get("STUB_LOG") else ""
        seen = {s for line in log.splitlines() if line.startswith("stub: skills=")
                for s in line.split("=", 1)[1].split(",")}
        check("rag-parse and rag-query", {"/opt/glove/skills/rag/rag-parse", "/opt/glove/skills/rag/rag-query"} <= seen,
              ", ".join(sorted(seen))[:200])
        if "obsidian" in comp.by_name("rag").mounts:
            check("claude-obsidian's wiki-ingest (mounted)", "/mnt/rag-obsidian/skills/wiki-ingest" in seen)
    except Exception as e:  # report, then tear down
        check(f"live run ({type(e).__name__})", False, str(e)[-600:])
    finally:
        if base is not None and not os.environ.get("KEEP"):
            subprocess.run([*base, "down", "--volumes"], env=env, capture_output=True)
    failed = [n for n, ok in results if not ok]
    print(f"== RESULT: {len(results) - len(failed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
