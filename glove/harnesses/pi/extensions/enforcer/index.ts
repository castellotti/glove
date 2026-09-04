/**
 * glove-pi-enforcer — routes every shell command through the ring-1 enforcer.
 *
 * The model's `bash` tool and the operator's `!`/`!!` commands are both rewritten
 * to run under the enforcer's per-command wrapper (e.g.
 *   nono wrap -s --allow-cwd --profile /etc/glove/enforcer/tool.json -- bash -lc <cmd>
 * ), so a prompt-injected command can only touch /work + rw mounts + /tmp, has no
 * network, and cannot read the harness home (extensions, skills, session
 * transcripts) or the LLM key.
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

const WRAPPER_FILE = "/etc/glove/enforcer/tool-wrapper.json";

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

/** POSIX single-quote a string so it survives as one argument to `bash -lc`. */
function shq(s: string): string {
  return "'" + s.replace(/'/g, "'\\''") + "'";
}

function wrapCommand(argv: string[], command: string): string {
  // argv already ends with "--"; append the shell that runs the agent's command.
  return `${argv.join(" ")} bash -lc ${shq(command)}`;
}

// Reject attempts to neuter the enforcer by overriding its env in the command.
const NONO_OVERRIDE = /(^|[;&|(\s])NONO_[A-Z0-9_]*=/;

export default async function (pi: ExtensionAPI) {
  const argv = loadWrapper();

  // Model-issued `bash` tool: mutate the command in place (PLAN §5.2).
  pi.on("tool_call", (event) => {
    if (event.toolName !== "bash") return;
    const input = event.input as { command?: string };
    if (typeof input.command !== "string") return;
    if (!argv) {
      return { block: true, reason: "glove enforcer: tool wrapper missing — shell blocked (fail closed)" };
    }
    if (NONO_OVERRIDE.test(input.command)) {
      return { block: true, reason: "glove enforcer: NONO_* env overrides are not allowed" };
    }
    input.command = wrapCommand(argv, input.command);
    return;
  });

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
