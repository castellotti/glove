"""Live checks of `enforcer: nono+srt` in a real session (driven by test_nono_srt.sh).

    uv run python tests/integration/nono_srt_live.py <session-dir>

Renders and starts the session the way `glove up` does, then, in the harness
service (its mounts, user, hardening and the relaxed seccomp profile):
  1. the harness position — the rendered harness command with a probe in place
     of the TUI: no namespaces or mounts, the llm endpoint reachable and nothing
     else (ring 0), protected /work paths, .env hidden;
  2. the tool position — the rendered tool wrapper inside that: the same
     seccomp denials, no network, no secret-shaped env, protected paths;
  3. the agent end to end — `<harness> -p "CALL bash {...}"` against the stub:
     the model's tool call runs through the harness hook and the wrapper;
  4. the TUI on a pty — resize redraws to the new width, `!` shell works, and a
     `!` command cannot open the harness's terminal (TIOCSTI).
Prints PASS/FAIL per check; exits non-zero on any failure.
"""

from __future__ import annotations

import fcntl
import json
import os
import pty
import re
import select
import shlex
import struct
import subprocess
import sys
import termios
import time
from pathlib import Path

from glove.cli import _materialize_plan, _open, _resolve_extensions
from glove.harnessconfig import render_home
from glove.plan import secret_env
from glove.session import _compose_base, ensure_images, start_sidecars

RESULTS: list[bool] = []
# What differs per harness: the model id the host stub lists (llm_stub for
# OpenAI-API harnesses, anthropic_stub for Claude Code) and the shell tool's name.
LLM_MATCH = {"claude-code": "claude-stub"}
BASH_TOOL = {"claude-code": "Bash"}


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append(ok)
    print(f"  {'PASS' if ok else 'FAIL'}: {name}" + (f"  [{detail}]" if detail and not ok else ""), flush=True)


def lines(out: str) -> dict[str, str]:
    """`KEY=value` lines a probe printed."""
    return dict(ln.split("=", 1) for ln in out.splitlines() if re.match(r"^[A-Z_0-9]+=", ln))


HARNESS_PROBE = r"""
unshare -Ur true 2>/dev/null; echo "UNSHARE_USER=$?"
unshare -m true 2>/dev/null; echo "UNSHARE_MOUNT=$?"
echo "KEY_IN_HARNESS=$(env | grep -c '^FAKE_API_KEY=')"
echo "LLM=$(curl -sS -m 10 "http://$LLM_HOST:$LLM_PORT/v1/models" 2>&1 | grep -c "$LLM_MATCH")"
curl -sS -m 10 -o /dev/null https://example.com 2>/dev/null; echo "EXAMPLE=$?"
getent hosts example.com >/dev/null 2>&1; echo "DNS_EXTERNAL=$?"
( echo pwn > /work/.git/hooks/pre-commit ) 2>/dev/null; echo "HOOK_WRITE=$?"
( echo x > /work/.envrc ) 2>/dev/null; echo "ENVRC_WRITE=$?"
( echo '{}' > /work/.vscode/settings.json ) 2>/dev/null; echo "VSCODE_WRITE=$?"
( echo '[core]' >> /work/.git/config ) 2>/dev/null; echo "GITCONFIG_WRITE=$?"
( echo ok > /work/harness-wrote.txt ) 2>/dev/null; echo "WORK_WRITE=$?"
echo "DOTENV=$(cat /work/.env 2>/dev/null | grep -c PROBE-DOTENV)"
echo "CLEAN_ENV=$(cat /work/sub/.env.local 2>/dev/null | grep -c PROBE-DOTENV)"
"""

TOOL_PROBE = r"""
unshare -Ur true 2>/dev/null; echo "T_UNSHARE_USER=$?"
echo "T_KEY=$(env | grep -c '^FAKE_API_KEY=')"
curl -sS -m 5 "http://$LLM_HOST:$LLM_PORT/v1/models" >/dev/null 2>&1; echo "T_NET=$?"
( echo pwn > /work/.git/hooks/post-checkout ) 2>/dev/null; echo "T_HOOK_WRITE=$?"
( echo ok > /work/tool-wrote.txt ) 2>/dev/null; echo "T_WORK_WRITE=$?"
( exec 3<>/dev/tty ) 2>/dev/null; echo "T_DEVTTY=$?"
"""


def drive_tui(argv: list[str], env: dict) -> dict:
    """Run the harness TUI on a pty: 30x100, then resize to 40x160, `!` a command
    that tries to open the terminal, then quit. Returns what was observed."""
    pid, fd = pty.fork()
    if pid == 0:
        os.execvpe(argv[0], argv, env)

    def setsize(r: int, c: int) -> None:
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("hhhh", r, c, 0, 0))

    buf = bytearray()

    def pump(t: float) -> None:
        end = time.time() + t
        while time.time() < end:
            r, _, _ = select.select([fd], [], [], 0.1)
            if r:
                try:
                    buf.extend(os.read(fd, 65536))
                except OSError:
                    return

    def widest(b: bytes) -> int:
        return max((len(m) for m in re.findall("[─━]+", b.decode(errors="replace"))), default=0)

    setsize(30, 100)
    pump(20)
    before = widest(bytes(buf))
    mark = len(buf)
    setsize(40, 160)
    pump(4)
    after = widest(bytes(buf[mark:]))
    mark = len(buf)
    # markers built at run time: Pi echoes the command text itself
    os.write(fd, b"!perl -e 'open(T, \"+<\", \"/dev/tty\") or die \"TTY\".\"-REFUSED: $!\\n\"; "
                 b"print \"TTY\".\"-OPENED\\n\"'")
    pump(1)
    os.write(fd, b"\r")  # on its own: Claude Code takes one burst as a paste, Enter included
    pump(10)
    ansi = r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(\x07|\x1b\\)"
    shell = re.sub(ansi, "", bytes(buf[mark:]).decode(errors="replace"))
    if os.environ.get("TUI_DUMP"):
        Path(os.environ["TUI_DUMP"]).write_text(re.sub(ansi, "", bytes(buf).decode(errors="replace")))
    os.write(fd, b"\x03\x03")
    pump(2)
    try:
        os.kill(pid, 9)
        os.waitpid(pid, 0)
    except OSError:
        pass
    return {"before": before, "after": after, "shell": shell}


def main(directory: str) -> int:
    sd, _, sid, cfg = _open(Path(directory))
    rt = cfg.provider
    base = None
    env = dict(os.environ)
    try:
        plan, _, _ = _materialize_plan(sd, sid, cfg)
        env = {**os.environ, **secret_env(plan)}
        base = _compose_base(rt, plan.project, sd.compose)
        print(f"== session {sid} ({cfg.harness}, enforcer {plan.enforcer}, runtime {rt})")
        settings = json.loads(plan.policies["srt-harness.json"])
        check("harness command: glove-pty relay → glove-srt (srt's library) → glove-pty ctty → harness",
              plan.harness_command[1] == "relay" and plan.harness_command[4].endswith("glove-srt.mjs")
              and plan.harness_command[8] == "ctty", " ".join(plan.harness_command[:10]))
        check("srt makes no network namespace for the harness (no `network` block)", "network" not in settings)
        t = time.time()
        ensure_images(cfg, plan, rt)
        print(f"  (images ready in {time.time() - t:.0f}s: {plan.image})", flush=True)
        start_sidecars(plan, sd.compose, provider=rt, env=env)
        check("sidecars up + verify passed", True)
        _resolve_extensions(plan, rt, secret_env(plan))
        render_home(cfg, plan.profile, sd.home, plan.model, mount_plan=plan.mount_plan, comp=plan.composition)
        if cfg.harness == "claude-code":
            # Claude Code asks once whether to use an ANTHROPIC_API_KEY and keeps
            # the answer (its last 20 chars); glove never writes key material, so
            # the test pre-approves its fake key the way the operator's "Yes" would.
            state = sd.home / ".claude" / ".claude.json"
            doc = json.loads(state.read_text())
            doc["customApiKeyResponses"] = {"approved": [env["GLOVE_TEST_ANTHROPIC_KEY"][-20:]], "rejected": []}
            state.write_text(json.dumps(doc))
        port = plan.model.base_url.split(":")[2].split("/")[0]
        probe_env = {"LLM_HOST": f"glove-{sid}-llm", "LLM_PORT": port,
                     "LLM_MATCH": LLM_MATCH.get(cfg.harness, "stub-qwen")}
        env_args = [a for k, v in probe_env.items() for a in ("-e", f"{k}={v}")]
        prefix = plan.harness_command[:plan.harness_command.index("ctty") + 2]  # relay … ctty --
        wrapper = json.loads(plan.policies["tool-wrapper.json"])["argv"]

        def in_harness(script: str) -> str:
            r = subprocess.run([*base, "run", "--rm", "-T", *env_args, plan.harness_service, *prefix,
                                "bash", "-c", script], env=env, stdin=subprocess.DEVNULL,
                               capture_output=True, text=True, timeout=300)
            return r.stdout + r.stderr

        print("== the harness position (srt, glove's apply-seccomp)")
        h = lines(in_harness(HARNESS_PROBE))
        check("no user namespace (unshare -Ur)", h.get("UNSHARE_USER") not in (None, "0"), str(h))
        check("no mount namespace (unshare -m)", h.get("UNSHARE_MOUNT") not in (None, "0"))
        check("the harness keeps its env (a secret-shaped var)", h.get("KEY_IN_HARNESS") == "1")
        check("the llm endpoint is reachable (its forwarder)", h.get("LLM") == "1", h.get("LLM", ""))
        check("no internet (ring 0: internal network)", h.get("EXAMPLE") not in (None, "0"))
        check("no external DNS", h.get("DNS_EXTERNAL") not in (None, "0"))
        check("/work/.git/hooks not writable", h.get("HOOK_WRITE") not in (None, "0"))
        check("/work/.envrc not writable", h.get("ENVRC_WRITE") not in (None, "0"))
        check("/work/.vscode/settings.json not creatable", h.get("VSCODE_WRITE") not in (None, "0"))
        check("/work/.git/config not writable", h.get("GITCONFIG_WRITE") not in (None, "0"))
        check("/work itself writable", h.get("WORK_WRITE") == "0")
        check("/work/.env and /work/sub/.env.local hidden",
              h.get("DOTENV") == "0" and h.get("CLEAN_ENV") == "0", f"{h.get('DOTENV')} {h.get('CLEAN_ENV')}")

        print("== the tool position (the rendered tool wrapper, inside the harness position)")
        t_ = lines(in_harness(shlex.join([*wrapper, "bash", "-c", TOOL_PROBE])))
        check("wrapper: glove-pty notty → nono wrap", wrapper[1] == "notty" and wrapper[3:5] == ["nono", "wrap"])
        check("no user namespace", t_.get("T_UNSHARE_USER") not in (None, "0"), str(t_))
        check("secret-shaped env stripped (nono deny_vars)", t_.get("T_KEY") == "0")
        check("no network (nono)", t_.get("T_NET") not in (None, "0"))
        check("/work/.git/hooks not writable", t_.get("T_HOOK_WRITE") not in (None, "0"))
        check("/work writable", t_.get("T_WORK_WRITE") == "0")
        check("no controlling terminal (/dev/tty)", t_.get("T_DEVTTY") not in (None, "0"))
        leaked = [p for p in ("work/.git/hooks/pre-commit", "work/.git/hooks/post-checkout",
                              "work/.vscode/settings.json") if (sd.root / p).exists()]
        check("nothing protected appeared on the host", not leaked, str(leaked))

        print("== the host's work/ while the harness runs (no bwrap placeholders)")
        work = sd.root / "work"

        def listing() -> set[str]:
            return {str(p.relative_to(work)) for p in work.rglob("*")}

        before = listing()
        running = subprocess.Popen([*base, "run", "--rm", "-T", plan.harness_service, *prefix, "sleep", "6"],
                                   env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
        time.sleep(4)
        during = listing()
        running.wait(timeout=60)
        check("no new files in work/ during the session", during == before, str(sorted(during - before)))

        print(f"== the agent end to end ({cfg.harness} -p, a model tool call through the hook)")
        cmd = 'echo tool-ran-$((6*7)); unshare -Ur true 2>/dev/null; echo userns=$?'
        t0 = time.time()
        r = subprocess.run([*base, "run", "--rm", "-T", plan.harness_service, *plan.harness_command, "-p",
                            f"CALL {BASH_TOOL.get(cfg.harness, 'bash')} {json.dumps({'command': cmd})}"], env=env, stdin=subprocess.DEVNULL,
                           capture_output=True, text=True, timeout=300)
        ans = (r.stdout + r.stderr)[-800:]
        check("the tool call ran (TOOL RESULT: tool-ran-42)", "tool-ran-42" in ans, ans.replace("\n", " "))
        check("and could not make a user namespace", "userns=1" in ans, ans.replace("\n", " ")[-200:])
        print(f"  ({cfg.harness} -p with one tool call: {time.time() - t0:.1f}s wall, incl. compose run)")

        if True:
            print("== the TUI on a pty (resize, `!` shell, no terminal for tools)")
            argv = [*base, "run", "--rm", plan.harness_service, *plan.harness_command]
            o = drive_tui(argv, env)
            check("draws at 100 columns", o["before"] == 100, str(o["before"]))
            check("re-lays out to 160 columns on resize (SIGWINCH through the relay)", o["after"] == 160,
                  str(o["after"]))
            check("`!` ran and could not open /dev/tty (TIOCSTI into the harness)",
                  "TTY-REFUSED: No such device" in o["shell"] and "TTY-OPENED" not in o["shell"],
                  o["shell"][-200:].replace("\n", " "))
    finally:
        if base:
            subprocess.run([*base, "down", "--volumes"], env=env, capture_output=True)
    print(f"== RESULT: {sum(RESULTS)} passed, {len(RESULTS) - sum(RESULTS)} failed")
    return 0 if all(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
