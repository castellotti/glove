"""Live checks of the agent's own tools under the harness's hook (Pi's enforcer
extension, Vibe's pre_tool hook), by the tool names each harness uses today
(driven by test_tool_confine.sh). A rename upstream (Vibe 2.26's
`file_system.bash`) fails a check here instead of silently unwrapping a tool.

    uv run python tests/integration/tool_confine_live.py <session-dir>

  1. the image runs the version harness.yml pins;
  2. every shell path runs wrapped (Pi: bash, codemode's `tools.bash`; Vibe:
     bash, run_typescript's `tools.file_system.bash` and `tools.process.start`):
     a probe only the tool profile refuses (the harness's own config, which the
     container and the harness process can read) and no secret-shaped env;
  3. the file-write tool writes /work and /tmp and refuses the home, `~`, a
     symlink and `..` out of /work (Pi: `@path` too), nested (codemode,
     run_typescript) as well;
  4. Pi: built-in MCP is off: a stdio server in the home's mcp.json (written by
     the host, as if it were not read-only) or in the project's .pi/mcp.json
     never starts (control: it does with glove's `-builtin:mcp` removed), and
     the harness cannot write mcp.json;
  5. the tool inventory (tools.json) fails closed: every tool the harness offers
     is in it (Vibe: also run_typescript's functions); a tool not in it is
     refused (Pi: an operator extension's tool; Vibe: vibe.todo taken out of
     the file), and every tool is when the file is missing; Pi: the session's
     `harness_config.tools.allow` lets the extension's tool run.
Prints PASS/FAIL per check; exits non-zero on any failure.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from contextlib import contextmanager
from pathlib import Path

from live_common import check, check_version, live_session, offered_tools, summary, tool_result
from nono_srt_live import lines

CONFIG = {"pi": "/home/agent/.pi/agent/settings.json", "vibe": "/home/agent/.vibe/config.toml"}
# A home file the harness process may write (ring 0 allows it): only the hook refuses the agent.
TARGET = {"pi": "/home/agent/.pi/agent/auth.json", "vibe": "/home/agent/.vibe/logs/session/plugins/planted"}
DENIED = "glove enforcer"
# Vibe's tools that never reach its hook, only the calls they make (measured, Vibe 2.26)
VIBE_UNHOOKED = {"run_typescript", "search_tool_functions", "skill"}
PROBE_EXT = """export default function (pi: any) {
  pi.registerTool({
    name: "glove_probe", label: "glove probe", description: "Returns a marker.",
    parameters: { type: "object", properties: {} },
    async execute() { return { content: [{ type: "text", text: "PROBE-" + "RAN" }], details: {} }; },
  });
}
"""


def probe(config: str, out: str) -> str:
    """A command that records, in /work/<out>, whether it ran under the tool profile."""
    return (f"{{ cat {config} >/dev/null 2>&1 && echo CONFIG=readable || echo CONFIG=denied; "
            f"echo KEYS=$(env | grep -c '^FAKE_API_KEY='); }} > /work/{out} 2>&1")


@contextmanager
def host_edit(path: Path, text: str | None):
    """`path` holds `text` (None: is gone) for the block (the host's copy: a
    ring-0 read-only file the harness could never write), then its old contents
    and mode again."""
    old, mode = (path.read_text(), path.stat().st_mode) if path.exists() else (None, None)
    try:
        if old is not None:
            path.chmod(mode | 0o200)
        if text is None:
            path.unlink(missing_ok=True)
        else:
            path.write_text(text)
        yield
    finally:
        if old is None:
            path.unlink(missing_ok=True)
        else:
            path.write_text(old)
            path.chmod(mode)


def main(directory: str) -> int:
    with live_session(directory) as s:
        h, home, work = s.cfg.harness, s.sd.home, s.sd.root / "work"
        stub_log = Path(f"{directory}.stub.log")
        offered_end = None  # where the stub log reaches Pi's runs with its built-in MCP on: not glove's tools
        check_version(s)
        settings = home / ".pi" / "agent" / "settings.json"

        def code(body: str) -> str:
            """Model-written code calling the harness's tools (Pi's codemode, on for the
            call; Vibe's run_typescript): `body` is a function body, `return`s its result."""
            if h == "vibe":
                return s.call("run_typescript", {"code": f"async function main() {{ {body} }}"})
            with host_edit(settings, json.dumps({**json.loads(settings.read_text()), "defaultTools": ["+codemode"]})):
                return s.call("codemode", {"code": body})

        def nested_bash(fn: str, after: str = "") -> Callable[[str], str]:
            return lambda p: code(f"const r = await tools.{fn}({{command: {json.dumps(p)}}}); {after}return r;")

        print("== every shell path runs wrapped (a probe only the tool profile refuses)")
        # one run in the container, unwrapped: the control, and (Pi) a write to the rendered mcp.json
        mcp = next((p for p in s.plan.protect if p.container_path.endswith("/.pi/agent/mcp.json")), None)
        ctl = s.run("-c", probe(CONFIG[h], "base.out") + (
            f"; : >> {mcp.container_path} 2>/dev/null; echo MCP_W=$?" if mcp else ""), entry="bash")
        check(f"control: {CONFIG[h]} is readable in the container",
              lines((work / "base.out").read_text()).get("CONFIG") == "readable")
        paths = {"bash": lambda p: s.call(s.bash_tool, {"command": p})}
        if h == "pi":
            paths["codemode tools.bash"] = nested_bash("bash")
        else:
            paths["run_typescript tools.file_system.bash"] = nested_bash("file_system.bash")
            paths["run_typescript tools.process.start"] = nested_bash(
                "process.start", "await tools.self.sleep({seconds: 2}).catch(() => 0); ")
        for i, (label, run) in enumerate(paths.items()):
            out = run(probe(CONFIG[h], f"p{i}.out"))
            got = (work / f"p{i}.out").read_text() if (work / f"p{i}.out").exists() else "(never ran)"
            check(f"{label}: wrapped (config denied, no secret-shaped env)",
                  lines(got) == {"CONFIG": "denied", "KEYS": "0"}, f"{' '.join(got.split())} | {tool_result(out, 300)}")

        print("== the file-write tool is held to the write roots")
        tool, key, content = s.tools["write"]
        (work / "link").symlink_to("/home/agent")
        target = home / TARGET[h].removeprefix("/home/agent/")
        before = target.read_bytes() if target.exists() else None
        refused = {"the home": TARGET[h], "~": "~/planted", "a symlink out of /work": "/work/link/planted",
                   "..": "/work/../home/agent/planted", **({"@path": "@" + TARGET[h]} if h == "pi" else {})}
        for p in ("/work/ok.txt", "/tmp/ok.txt"):
            r = tool_result(s.call(tool, {key: p, content: "x"}), 300)
            check(f"{tool} {p}: written", DENIED not in r and "rror" not in r, r)
        check(f"{tool} /work/ok.txt is on the host", (work / "ok.txt").is_file())
        for label, p in refused.items():
            r = tool_result(s.call(tool, {key: p, content: "x"}), 300)
            check(f"{tool} {label} ({p}): refused by the hook", DENIED in r, r)
        nested, fn = ("codemode", "write") if h == "pi" else ("run_typescript", "file_system.write_file")

        def nested_write(p: str) -> str:
            return tool_result(code(f"try {{ return await tools.{fn}({{path: {p!r}, content: 'x'}}); }} "
                               "catch (e) { return 'ERR ' + String(e) + ' ' + JSON.stringify(e); }"), 300)
        r = nested_write("/work/nested.txt")
        check(f"control: {nested} tools.{fn} /work/nested.txt: written", (work / "nested.txt").is_file(), r)
        r = nested_write(TARGET[h])
        # Vibe's TypeScript sees a hook denial as `tool_skipped`, without the reason
        check(f"{nested} tools.{fn} into the home: refused by the hook", DENIED in r or "tool_skipped" in r, r)
        planted = sorted(str(f.relative_to(home)) for f in home.rglob("*planted*"))
        check("nothing written into the home", not planted and
              (target.read_bytes() if target.exists() else None) == before, str(planted))

        if h == "pi":
            print("== Pi's built-in MCP is off")
            w = lines(ctl.stdout).get("MCP_W")
            check("the harness cannot write mcp.json", w not in (None, "0"), str(w))

            def server(marker: str) -> str:
                return json.dumps({"mcpServers": {"glove-probe": {"command": "/bin/sh", "args": [
                    "-c", f"touch /work/{marker}; sleep 5"]}}})
            (work / ".pi").mkdir(exist_ok=True)
            (work / ".pi" / "mcp.json").write_text(server("mcp-project"))
            with host_edit(Path(mcp.host_path), server("mcp-home")):
                s.ask("hello")
                check("a stdio server in the home's mcp.json never starts", not (work / "mcp-home").exists())
                check("nor the project's .pi/mcp.json", not (work / "mcp-project").exists())
                on = json.loads(settings.read_text())
                on["extensions"] = [e for e in on.get("extensions", []) if e != "-builtin:mcp"]
                offered_end = len(stub_log.read_text())
                with host_edit(settings, json.dumps(on)):
                    s.ask("hello")
                check("control: with -builtin:mcp removed it does", (work / "mcp-home").exists())
                check("… the project's still not (defaultProjectTrust: never)", not (work / "mcp-project").exists())
        print("== the tool inventory fails closed")
        inventory, inv = s.sd.state / "enforcer" / "tools.json", s.inventory
        listed = {n for c in ("shell", "file_write", "allow") for n in inv[c]}
        offered = offered_tools(stub_log.read_text()[:offered_end])
        if h == "vibe":  # the hook sees a top-level tool by its group's name (read_file: file_system.read_file)
            offered = {n for n in offered - VIBE_UNHOOKED if not any(x.endswith(f".{n}") for x in listed)}
            nested = s.vibe_functions("file_system", "process", "vibe", "self")
            check("every run_typescript function is in the inventory", bool(nested) and set(nested) <= listed,
                  str(sorted(set(nested) - listed) or nested))
        # (Vibe: what's left once mapped may be nothing)
        check(f"every tool {h} offers is in the inventory", offered <= listed and (bool(offered) or h == "vibe"),
              str(sorted(offered - listed)) or "nothing offered")
        if h == "pi":
            ext = home / ".pi" / "agent" / "extensions"
            ext.mkdir(parents=True, exist_ok=True)
            (ext / "glove-probe.ts").write_text(PROBE_EXT)
            r = tool_result(s.call("glove_probe", {}), 300)
            check("an operator extension's tool, not listed: refused", "inventory" in r and "PROBE-RAN" not in r, r)
        else:
            with host_edit(inventory, json.dumps({**inv, "allow": [n for n in inv["allow"] if n != "vibe.todo"]})):
                r = tool_result(s.call("todo", {"action": "read"}), 300)
            check("a tool taken out of the inventory (vibe.todo): refused", DENIED in r and "inventory" in r, r)
        with host_edit(inventory, None):
            r = tool_result(s.call(s.bash_tool, {"command": "echo SHELL-RAN"}), 300)
        check("no tools.json: every tool refused (the shell too)", "SHELL-RAN" not in r and "inventory" in r, r)
        if h == "pi":
            session = s.sd.root / "glove-session.yml"
            session.write_text(session.read_text() + "harness_config: {tools: {allow: [glove_probe]}}\n")
            s.relaunch()
            check("… listed in harness_config.tools.allow, it runs",
                  "glove_probe" in json.loads(inventory.read_text())["allow"]
                  and "PROBE-RAN" in tool_result(s.call("glove_probe", {}), 300))
    return summary()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
