// glove-srt <settings.json> -- <cmd...>
//
// srt's own library, wrapping the harness for `enforcer: nono+srt` with
// everything srt does EXCEPT a network namespace. srt's CLI cannot express
// that (its settings schema requires network.allowedDomains, and any value
// confines), but the library leaves the network alone when allowedDomains is
// absent. glove needs exactly that: ring 0 already confines the harness to the
// session's forwarders on an internal network, and an srt netns broke every
// client that speaks its own proxy protocol (web_fetch) or raw TCP.
//
// The settings are validated with srt's schema (a stand-in network block
// satisfies it and is then dropped), so a typo still refuses to start.
//
// srt starts from /tmp and the command `cd`s back: srt protects its built-in
// dangerous files (.bashrc, .gitconfig, .vscode, …) relative to its cwd, and
// for a path that does not exist bwrap creates an empty placeholder where the
// bind lands — in /work that is the user's project on the host. glove names
// the /work paths to protect itself, only those present at launch.
// Mirrors srt's CLI otherwise: wrap, run through a shell, clean up bwrap's
// deny-path placeholders, exit with the command's status.
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { SandboxManager, SandboxRuntimeConfigSchema } from "/opt/glove/srt/npm/lib/node_modules/@anthropic-ai/sandbox-runtime/dist/index.js";

const die = (msg) => {
  process.stderr.write(`glove-srt: ${msg}\n`);
  process.exit(90);
};

const [settingsPath, sep, ...argv] = process.argv.slice(2);
if (!settingsPath || sep !== "--" || argv.length === 0) die("usage: glove-srt <settings.json> -- <cmd...>");

let settings;
try {
  settings = JSON.parse(readFileSync(settingsPath, "utf-8"));
} catch (e) {
  die(`cannot read ${settingsPath}: ${e.message}`);
}
if ("network" in settings) die(`${settingsPath} has a network block; glove-srt never confines the network`);
const checked = SandboxRuntimeConfigSchema.safeParse({ ...settings, network: { allowedDomains: [], deniedDomains: [] } });
if (!checked.success) die(`${settingsPath} is not a valid srt config: ${checked.error.message}`);
if (!settings.seccomp?.applyPath) die(`${settingsPath} names no seccomp.applyPath (glove's apply-seccomp)`);

const shq = (s) => `'${s.replaceAll("'", "'\\''")}'`;

const cwd = process.cwd();
process.chdir("/tmp");
await SandboxManager.initialize({ ...checked.data, network: {} });
const wrapped = await SandboxManager.wrapWithSandbox(`cd ${shq(cwd)} && exec ${argv.map(shq).join(" ")}`);
const child = spawn(wrapped, { shell: true, stdio: "inherit" });
for (const sig of ["SIGTERM", "SIGHUP", "SIGINT", "SIGQUIT"]) {
  process.on(sig, () => child.kill(sig));
}
child.on("error", (e) => die(`cannot run the command: ${e.message}`));
child.on("exit", (code, signal) => {
  SandboxManager.cleanupAfterCommand();
  process.exit(signal ? 128 + (({ SIGINT: 2, SIGTERM: 15, SIGHUP: 1, SIGKILL: 9 })[signal] ?? 1) : (code ?? 0));
});
