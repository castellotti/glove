# glove

`glove` is a Python CLI that launches an agentic coding harness (Pi or Mistral
Vibe first; Claude Code later) inside a **sandbox**, presents the harness's
normal TUI in your terminal, and guarantees that the harness - and every shell
command, extension, skill, or MCP server it spawns - can only touch the host
directories you explicitly exposed, can only reach the network endpoints you
explicitly allowed, and cannot escalate privilege.

The sandbox is *distributed as a container image* (Docker first) but the
security does not rest on the container alone: a kernel-level capability
sandbox (nono/Landlock by default) runs *inside* the container and wraps every
command the agent executes.

## How it works - three rings (defense in depth)

The agent and everything it spawns are treated as **untrusted** (the real threat
is prompt injection making the model run a bad command). Three independent rings
must each be defeated:

- **Ring 0 - Runtime** (container/VM): namespace, a bind-mount **allow-list**,
  an **internal-only network** (only single-purpose forwarder sidecars are
  routable), and a non-negotiable hardening set - non-root, `cap_drop ALL`,
  `no-new-privileges`, read-only rootfs, seccomp, pids/mem/ipc limits. Never
  `docker.sock`, never `--privileged`, never host-gateway on the harness.
- **Ring 1 - Enforcer** (kernel policy on every process): **nono** (Landlock,
  default) or **srt** (bubblewrap, opt-in) wraps the harness *and* every shell
  command. A prompt-injected command can only write `/work` + exposed rw dirs,
  cannot read the harness home / secrets, and has **no network**.
- **Ring 2 - Harness integration**: a Pi extension / Vibe `pre_tool` hook routes
  every `bash`/`!` command through ring 1 and blocks egress tools; a generated
  context file tells the agent the rules.

See **[docs/SECURITY.md](docs/SECURITY.md)** for the full threat model and the
Docker Desktop macOS blast-radius explanation.

### Runtime / enforcer / browser support

| Component | Option | Status |
|---|---|---|
| Runtime | docker | hardened + doctor probes |
| Runtime | podman | ships, **untested** (no podman on host) |
| Runtime | apple-container / gondolin / utm | stub (registered, `NotImplementedError`) |
| Enforcer | nono (Landlock) - default | Pi wired + verified (16-check integration) |
| Enforcer | srt (bubblewrap) - opt-in | Pi wired + verified (7-check integration); tool commands only |
| Enforcer | none (ring 0 only) | debug |
| Browser | host-mcp - v2 default | implemented + live nav verified - see [docs/pi-remote-llm.md](docs/pi-remote-llm.md) |
| Browser | host-server | implemented (ws-path + version-pin; needs playwright in image) |
| Browser | sidecar-desktop / vm-desktop | spec only (not implemented) |

Giving a harness web access needs Node/npx and a Chromium-family browser on the
host; the friction-free option is Playwright's own Chrome for Testing
(`npx playwright install chromium`). For a complete, reproducible setup - Pi
against a remote OpenAI-compatible LLM over an SSH tunnel plus a dedicated headed
Playwright browser, including the `@playwright/mcp` `--browser` channel gotcha and
the `--executable-path` fix - see **[docs/pi-remote-llm.md](docs/pi-remote-llm.md)**
and copy **[docs/examples/pi-remote-llm.glove.yaml](docs/examples/pi-remote-llm.glove.yaml)**.

Runnable presets live in **[docs/examples/](docs/examples/)**.

## Quick start

Identity is the pair `(directory you run from, harness)`, bound to a stable
`env-id`; all state lives under `~/.glove/envs/<env-id>/` - nothing is written
into your working dir.

```sh
cd ~/src/service-a
uv run glove doctor                 # probe host + runtime + enforcer
uv run glove init pi                # scaffold the env config
uv run glove pi --name TICKET-1234 \
    --add-dir ~/src/shared-lib:ro \ # extra dir, read-only
    --net service --browser host-mcp
#  → doctor (first run) → build image (first run) → host services → sidecars → TUI
```

Inspect what will run before launching:

```sh
uv run glove pi --dry-run           # print the rendered compose project
uv run glove policy show            # ring-1 policies + ring-0 hardening + gaps
```

## Configuration (`~/.glove/envs/<env-id>/glove.yaml`)

```yaml
harness: pi                 # pi | vibe | claude-code (experimental)
runtime: docker             # docker | podman(untested) | apple-container|gondolin|utm (stub)
enforcer: nono              # nono (Landlock, default) | srt (bubblewrap) | none
workdir: .
add_dirs:
  - { path: ../shared-lib, mode: ro }
net: [service]              # none | service | internet | lan | docker:<name>
services:                   # forwarder allow-list (the only routable hosts)
  - { name: llm, to: host.docker.internal:8899, port: 8080 }
browser: { provider: host-mcp, port: 8931 }   # host-mcp | host-server | none
model: your-model-id       # must match the endpoint's /v1/models
llm_api_key: sk-...         # stripped from shell tools' env by ring 1
tools: { net: block, allow_commands: [cp, mv, rm] }
limits: { pids: 512, memory: 4g, cpus: 2 }
enforcer_options: { srt: { nested: weak } }
```

Precedence: defaults < env `glove.yaml` < `--config` overlay < flags.

## CLI

```
glove init [HARNESS] [--name ENV] [--from FILE]
glove run  HARNESS  [--name SESSION] [--add-dir P[:ro|:rw]]… [--net …] [--browser …]
                    [--runtime …] [--enforcer …] [--dry-run] [--rebuild]
glove <harness> …                    # alias of run
glove doctor  [--env ID] [--runtime R] [--enforcer E] [--browser B] [--json]
glove policy show [--env ID]         # rendered ring-1 policies + ring-0 hardening
glove config  [--env ID] [--edit|--path]
glove ls | ps | down [ID] [--name SESSION] [--wipe] | build [HARNESS] [--enforcer srt]
```

## Toolchain

Python ≥ 3.11 managed with [uv](https://docs.astral.sh/uv/):

```sh
uv sync
uv run ruff check glove tests        # lint
uv run pytest -q                     # unit suite
# integration (need Docker; build the images first):
bash tests/integration/test_pi_nono.sh    # nono / Pi  (16 checks)
bash tests/integration/test_vibe_nono.sh  # nono / Vibe (10 checks)
bash tests/integration/test_pi_srt.sh     # srt  / Pi  (7 checks)
```
