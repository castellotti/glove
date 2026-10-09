/**
 * glove-pi-enforcer — routes every shell command through the ring-1 enforcer.
 *
 * The model's `bash` tool and the operator's `!`/`!!` commands are both rewritten
 * to run under the enforcer's per-command wrapper (e.g.
 *   nono wrap -s --allow-cwd --profile /etc/glove/enforcer/tool.json -- bash -c <cmd>
 * ), so a prompt-injected command can only touch /work + rw mounts + /tmp, has no
 * network, and cannot read the harness home (extensions, skills, session
 * transcripts). The LLM key is not in the harness at all (glove's llm-auth holds it).
 *
 * Pi's own `write` and `edit` tools run in this process, outside that sandbox, so
 * they are held to the same write roots (/etc/glove/enforcer/write-roots.json):
 * the path is resolved the way Pi and the kernel would (`@`, `~`, `file://`,
 * symlinks), checked, and the call is rewritten to that checked absolute path.
 * Nested calls (codemode) pass through `tool_call` too.
 *
 * Every tool call is classified by the session's inventory
 * (/etc/glove/enforcer/tools.json, rendered by glove from harness.yml, the
 * session's extensions and its `harness_config.tools.allow`): `shell` is
 * wrapped, `file_write` held to the write roots, `allow` passed through, and any
 * other tool blocked, so a tool a new Pi release or an operator extension adds
 * fails closed. Without a readable inventory every tool is blocked.
 *
 * The wrapper argv is read from /etc/glove/enforcer/tool-wrapper.json, rendered by
 * glove's enforcer — so this extension is enforcer-agnostic (nono today, srt
 * later). If the wrapper file is missing or unreadable, the extension FAILS CLOSED
 * and blocks all shell execution rather than running commands unsandboxed.
 *
 * This is a pure-JS extension (node builtins only) so it needs no npm install and
 * does not depend on pi internals at runtime.
 */
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { spawn } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const WRAPPER_FILE = "/etc/glove/enforcer/tool-wrapper.json";
const ROOTS_FILE = "/etc/glove/enforcer/write-roots.json";
const TOOLS_FILE = "/etc/glove/enforcer/tools.json";
const TOOL_CLASSES = ["shell", "file_write", "allow"] as const;
type Tools = Record<(typeof TOOL_CLASSES)[number], Set<string>>;
// What Pi's path normalization turns into a plain space: refused, so the path
// checked is the path written.
const ODD_SPACE = /[\u00A0\u2000-\u200B\u202F\u205F\u3000\uFEFF]/;

function loadWrapper(): string[] | null {
  try {
    const data = JSON.parse(fs.readFileSync(WRAPPER_FILE, "utf-8"));
    if (Array.isArray(data.argv) && data.argv.length > 0 && data.argv.every((a: unknown) => typeof a === "string")) {
      return data.argv as string[];
    }
  } catch {
    // fall through — treated as "no wrapper", fail closed below
  }
  return null;
}

function loadRoots(): string[] | null {
  try {
    const roots = JSON.parse(fs.readFileSync(ROOTS_FILE, "utf-8")).roots;
    if (Array.isArray(roots) && roots.length > 0 && roots.every((r: unknown) => typeof r === "string" && r.startsWith("/"))) {
      const real = roots.map((r: string) => realpathLoose(r));
      return real.every((r) => r !== null) ? (real as string[]) : null;
    }
  } catch {
    // fall through — no roots, file writes fail closed below
  }
  return null;
}

/** The inventory, class → tool names; null when missing or malformed. */
export function loadTools(file: string = TOOLS_FILE): Tools | null {
  try {
    const data = JSON.parse(fs.readFileSync(file, "utf-8"));
    const ok = TOOL_CLASSES.every((c) => Array.isArray(data[c]) && data[c].every((n: unknown) => typeof n === "string"));
    if (ok) return Object.fromEntries(TOOL_CLASSES.map((c) => [c, new Set<string>(data[c])])) as Tools;
  } catch {
    // fall through — no inventory, every tool blocked below
  }
  return null;
}

/** `p` resolved component by component as the kernel would: each symlink
 * followed (a dangling one too: a write creates its target), `..` after it;
 * missing components kept as given. null on a symlink loop. */
export function realpathLoose(p: string): string | null {
  const todo = p.split("/").filter((s) => s !== "" && s !== ".").reverse();
  let cur = "/";
  for (let links = 0; todo.length > 0; ) {
    const part = todo.pop() as string;
    if (part === "..") {
      cur = path.dirname(cur);
      continue;
    }
    const next = path.join(cur, part);
    let target: string | null = null;
    try {
      if (fs.lstatSync(next).isSymbolicLink()) target = fs.readlinkSync(next);
    } catch {
      // missing: kept as given
    }
    if (target === null) {
      cur = next;
      continue;
    }
    if (++links > 40) return null;
    todo.push(...target.split("/").filter((s) => s !== "" && s !== ".").reverse());
    if (target.startsWith("/")) cur = "/";
  }
  return cur;
}

/** The absolute path Pi would write for a tool's `path` (its normalization:
 * `@` prefix, `~`, `file://`), resolved; null when it can't be checked. */
export function resolveWritePath(raw: string, cwd: string): string | null {
  if (ODD_SPACE.test(raw) || raw !== raw.trim()) return null;
  let p = raw.startsWith("@") ? raw.slice(1) : raw;
  if (p === "~") p = os.homedir();
  else if (p.startsWith("~/")) p = path.join(os.homedir(), p.slice(2));
  else if (p.startsWith("file://")) p = fileURLToPath(p);
  const real = realpathLoose(path.isAbsolute(p) ? p : `${cwd}/${p}`);
  return real === null || ODD_SPACE.test(real) ? null : real;
}

export function insideRoots(real: string, roots: string[]): boolean {
  return roots.some((r) => real === r || real.startsWith(r.endsWith("/") ? r : `${r}/`));
}

/** POSIX single-quote a string so it survives as one argument to `bash -c`. */
function shq(s: string): string {
  return "'" + s.replace(/'/g, "'\\''") + "'";
}

function wrapCommand(argv: string[], command: string): string {
  // argv already ends with "--"; append the shell that runs the agent's command.
  // Use a NON-login shell (`-c`, not `-lc`): a login shell sources /etc/profile,
  // which nono's default profile denies (deny_shell_configs), printing a harmless
  // but noisy "bash: /etc/profile: Permission denied" on every command. PATH is
  // already set by the image env, so login-shell setup is unnecessary here.
  return `${argv.join(" ")} bash -c ${shq(command)}`;
}

// Reject attempts to neuter the enforcer by overriding its env in the command.
const NONO_OVERRIDE = /(^|[;&|(\s])NONO_[A-Z0-9_]*=/;

type ToolEvent = { toolName: string; input: unknown };
type Verdict = { block: true; reason: string } | undefined;

/** The `tool_call` handler: each call classified by the inventory (`tools`). */
export function toolCallHandler(argv: string[] | null, roots: string[] | null, tools: Tools | null) {
  // Pi's own file tools: only under the write roots, at the path checked.
  const holdWrite = (event: ToolEvent, cwd: string): Verdict => {
    const input = event.input as { path?: unknown };
    const real = roots && typeof input.path === "string" ? resolveWritePath(input.path, cwd) : null;
    if (!roots || !real) {
      return { block: true, reason: `glove enforcer: ${event.toolName} needs a plain path and the write roots (fail closed)` };
    }
    if (!insideRoots(real, roots)) {
      return { block: true, reason: `glove enforcer: ${event.toolName} may write only under ${roots.join(", ")}, not ${real}` };
    }
    input.path = real;
    return;
  };

  // A shell tool: mutate the command in place (PLAN §5.2).
  const wrapShell = (event: ToolEvent): Verdict => {
    const input = event.input as { command?: string };
    if (typeof input.command !== "string") {
      return { block: true, reason: `glove enforcer: ${event.toolName} without a command string (fail closed)` };
    }
    if (!argv) {
      return { block: true, reason: "glove enforcer: tool wrapper missing — shell blocked (fail closed)" };
    }
    if (NONO_OVERRIDE.test(input.command)) {
      return { block: true, reason: "glove enforcer: NONO_* env overrides are not allowed" };
    }
    input.command = wrapCommand(argv, input.command);
    return;
  };

  return (event: ToolEvent, ctx?: { cwd?: string }): Verdict => {
    if (!tools) return { block: true, reason: "glove enforcer: the tool inventory is missing — every tool blocked (fail closed)" };
    if (tools.file_write.has(event.toolName)) return holdWrite(event, ctx?.cwd ?? process.cwd());
    if (tools.shell.has(event.toolName)) return wrapShell(event);
    if (tools.allow.has(event.toolName)) return;
    return {
      block: true,
      reason: `glove enforcer: tool ${event.toolName} is not in this session's tool inventory (harness_config.tools.allow can add one)`,
    };
  };
}

export default async function (pi: ExtensionAPI) {
  const argv = loadWrapper();
  pi.on("tool_call", toolCallHandler(argv, loadRoots(), loadTools()));

  // Operator `!`/`!!` commands: run through the same wrapper via custom operations.
  pi.on("user_bash", (event) => {
    if (!argv) {
      return {
        result: {
          content: [{ type: "text", text: "glove enforcer: tool wrapper missing — shell blocked (fail closed)" }],
          isError: true,
        },
      };
    }
    const wrapped = wrapCommand(argv, event.command);
    return {
      operations: {
        exec: (_command: string, cwd: string, opts: { onData: (d: Buffer) => void; signal?: AbortSignal; env?: NodeJS.ProcessEnv }) =>
          new Promise<{ exitCode: number | null }>((resolve, reject) => {
            const child = spawn("bash", ["-c", wrapped], { cwd, env: opts.env ?? process.env });
            child.stdout.on("data", (d: Buffer) => opts.onData(d));
            child.stderr.on("data", (d: Buffer) => opts.onData(d));
            child.on("error", reject);
            child.on("close", (code) => resolve({ exitCode: code }));
            opts.signal?.addEventListener("abort", () => child.kill("SIGTERM"));
          }),
      },
    };
  });
}
