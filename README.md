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

> **Minimal core + opt-in plugins.** The base image is *harness + enforcer only*;
> every optional capability is an off-by-default plugin enabled per session (like
> `net:`) — **`media`** (analysis toolchain), **`search`** (private SearXNG), and
> **`browser`** (host Chromium via Playwright). Enable them with
> `plugins: [media, search, browser]` (+ `plugin_options:`) or `--with a,b`; each
> composes as a derived image layer + its wiring only when enabled. See
> `docs/planning/minimal-core-plugins-designnote.md`. Legacy top-level `browser:`
> / bare `search` service configs still work with a deprecation warning.

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
| Runtime | podman | hardened + doctor probes; validated rootless (podman 6, libkrun, Vibe/nono, Landlock ABI 9) |
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
runtime: docker             # docker | podman | apple-container|gondolin|utm (stub)
enforcer: nono              # nono (Landlock, default) | srt (bubblewrap) | none
workdir: .
add_dirs:
  - { path: ../shared-lib, mode: ro }
net: [service]              # none | service | internet | lan | docker:<name>
plugins: [media, browser]   # opt-in capabilities (off by default); also `--with a,b`
plugin_options:             # per-plugin config
  browser: { provider: host-mcp, port: 8931 }   # host-mcp | host-server | none
services:                   # forwarder allow-list (the only routable hosts)
  - { name: llm, to: host.docker.internal:8899, port: 8080 }
model: your-model-id       # must match the endpoint's /v1/models
llm_api_key: sk-...         # stripped from shell tools' env by ring 1
tools: { net: block, allow_commands: [cp, mv, rm] }
limits: { pids: 512, memory: 4g, cpus: 2 }
enforcer_options: { srt: { nested: weak } }
observe: { enabled: true }  # network observability (off by default) — see below
```

Precedence: defaults < env `glove.yaml` < `--config` overlay < flags.

## CLI

```
glove init [HARNESS] [--name ENV] [--from FILE]
glove run  HARNESS  [--name SESSION] [--add-dir P[:ro|:rw]]… [--net …] [--with a,b] [--browser …]
                    [--runtime …] [--enforcer …] [--resume|-r] [--session ID] [--dry-run] [--rebuild]
glove <harness> …                    # alias of run
glove doctor  [--env ID] [--runtime R] [--enforcer E] [--browser B] [--json]
glove policy show [--env ID]         # rendered ring-1 policies + ring-0 hardening
glove config  [--env ID] [--edit|--path]
glove ls | ps | down [ID] [--name SESSION] [--wipe] | build [HARNESS] [--enforcer srt]
glove net status [--env ID] [--session NAME] [--json]          # gate health + per-service totals
glove net flows  [--env ID] [--session NAME] [--follow] [--json] [--tail N]
glove net block  <host-glob|ip|cidr> [--port N] [--terminate] [--allow] [--note TEXT]
glove net unblock <rule-id|target>
glove net rules  [--json]                                       # rules + the gate's load result
glove net validate <file|-> [--env ID] [--session TOKEN] [--json] # the gate's validator; pure
```

### Network observability

With `observe: {enabled: true}`, every service forwarder becomes an instrumented
**netgate**: a drop-in for the socat forwarder (same container name, networks
and port, so the harness config is unchanged) that records every connection:
open, ~1 Hz updates while bytes move, and close, with cumulative byte counts,
timing, tool label and scope. Records go to the session's `net/` directory
(`~/.glove/envs/<env>/sessions/<session>/net/`, a sibling of `home/`) through a
single collector container that has **no network at all**
(`network_mode: none`):

```
net/session.json    static facts: services, tools, upstreams, record mode (0600)
net/flows.ndjson    append-only flow stream + gate start/stop records, size-rotated
                    to flows-<stamp>[-<n>].ndjson (order by (stamp, n), not by name)
net/exit.ndjson     apparent-origin changes (only with exit identity on)
net/status.json     gate heartbeat, upstream health, dropped-record counters,
                    the rules load result (with the enforced file's SHA-256)
```

```yaml
observe:
  enabled: true
  resolve: in-tunnel        # in-tunnel | none — there is deliberately no `host`
  rotate_mb: 64             # rotate flows.ndjson at this size…
  keep: 8                   # …keeping this many rotated files
services:
  - { name: llm, to: host.docker.internal:8080, port: 8080,
      observe: { tool: llm, scope: local } }      # optional per-service labels
  - { name: other, to: x:1, observe: false }      # opt out: stays plain socat
                                                  # (enabled: false turns all of it off)
  - { name: proxy, to: egress-proxy:8888, join_network: pi-search-egress,
      observe: { mode: http-proxy, route: vpn } } # see below
```

**Proxy mode.** A service the harness uses as an HTTP proxy (glove-pi-search's
`proxy`/`web_fetch`) can run with `mode: http-proxy`. The gate then reads the
destination from each `CONNECT host:port` or `GET http://host/…` and records the
real hostname and port, not just `egress-proxy`. It chains to the upstream
(`chain:http://<to>` by default) **by hostname**, so the tunnel, not the gate or
your host, resolves it. `route: vpn|tor|direct` is required and declares what
that upstream really is. glove can't verify a tunnel, so it won't assume one, and
`direct` marks every flow as untunnelled. Before anything goes upstream, a built-in
**SSRF guard** refuses non-public destinations: private and metadata IPs in any
notation, container names like `gluetun`, and `.internal`/`localhost` names.
Refusals are recorded as blocked flows. In `tcp` mode the gate also peeks
(never terminates) a TLS ClientHello, so an HTTPS flow shows its SNI hostname.

Guarantees, each covered by a test (`tests/test_netgate_invariants.py`) and by
live runs (`tests/integration/test_netgate_m1.sh`, `…_m2.sh`,
`test_netgate_shutdown.sh`, `netgate_control_perms.sh`):
- the gate exposes no API on any network;
- it never gains `NET_ADMIN`, joins the harness's network or PID namespace, or
  mounts the harness home;
- `net/` has no harness mount, and a render that would expose it is refused;
- nothing resolves a destination hostname on the host;
- telemetry failures drop records, never traffic.

**Blocking.** `glove net block '*.doubleclick.net'` writes a rule to
`~/.glove/control/<env>/<session>/rules.json`, the same file Layman writes. The
gate reloads it within about a second, refuses new matching connections with a
recorded `verdict: block`, and with `--terminate` also cuts established ones.
A malformed file is rejected as a whole: the gate keeps the previous rules and
reports the error in `glove net rules` and `status.json`. So is a file the gate
cannot read (e.g. left `root:root 0600` by another writer): it is never taken
for "no rules". `status.json` names the enforced file and the last rejected one
by SHA-256, and `glove net rules` says whether the file on disk is `enforced`,
`rejected` or `pending`. `glove net validate FILE` runs the gate's validator
without a gate. The gate runs as your uid, so a second writer (Layman) must
leave `rules.json` owned by you: the contract is in the handoff's §3,
"Ownership". The built-in SSRF guard always runs first.

**Gate lifecycle.** Every flow record carries its forwarder's `run` id, and
`flows.ndjson` records each forwarder's and the collector's `start`/`stop`. A
clean `glove down` stops the forwarders before the collector, so every open
flow gets its `gate_shutdown` close. A forwarder that dies without one (e.g.
`docker kill`, which `restart: unless-stopped` does not undo) gets an inferred
`stop` from the collector after 30 s of silence. `glove net status` then counts
its unclosed flows as cut, not active.

**Where things are (M4).** With `observe.resolver: dns://gluetun:53` (or
`tor-socks://tor:9150`), a proxy gate resolves each destination through the
*tunnel's* resolver, never your host's. Flows then carry `dest.ip` with
`resolution: in-tunnel`, `ip` rules apply to hostnames, and a name that resolves
to a private address is refused. If the resolver is down, flows say
`unavailable` and traffic is unaffected. With `observe.exit_identity: via-proxy`,
the session's apparent origin (exit IP and location) is fetched *through* the
tunnel and written to `net/exit.ndjson`. It's opt-in, because the echo service
(`am.i.mullvad.net` by default) is a third party, though it only sees the exit.

**The whole chain (M5).** A `harness: false` service is a gate listener for
*egress-stack* components, and the sandbox can't reach it. glove-pi-search points
SearXNG's outgoing proxy at one (`fanout`), so a single `web_search` shows every
engine SearXNG contacted (`client: searxng`, `tool: search-engine-fanout`).
`observe.record: full` (with an explicit warning) adds the method and URL of
*cleartext* HTTP requests, and `record_headers` adds headers with credentials
redacted. HTTPS stays opaque. `observe.retain: 12h` expires old records, and
`glove down --wipe` deletes them.

Design and as-built decisions:
[docs/planning/network-observability.md](docs/planning/network-observability.md).
Layman consumes `net/` read-only; the contract is
[the handoff brief](docs/planning/network-observability-layman-handoff.md).
Sample data: `tests/fixtures/netobs/` (the original fixture, frozen) and one
directory per UI state in `tests/fixtures/netobs-scenarios/`.
Podman, and native Linux Docker's file ownership: **untested** live (the
ownership probe, `tests/integration/netgate_control_perms.sh`, has run only on
Docker Desktop for macOS).

### Resuming a session

A harness session's state — its conversation transcript — lives in the
persistent per-session home glove bind-mounts, **not** in the (ephemeral)
container. So you can reopen a prior session:

- `glove <harness> … --resume` (`-r`) — reopen the **most recent** session for
  this env/workdir. Re-run your exact previous command with `--resume` appended.
  glove checks a transcript exists, then defers to the harness's own
  continue-last (which picks the last session for its current project), so use
  `--session <id>` when you need to be sure exactly which one reopens.
- `glove <harness> … --session <id>` — reopen a **specific** session (full or
  partial UUID, or a transcript path). glove resolves it to that transcript's
  canonical id before handing it to the harness.

Because glove re-renders the whole sandbox from the *current* config on every
run, **editing the config (or passing flags) before resuming changes the grants
for the resumed conversation** — e.g. widen `net`/add a `service:` for a LAN host
you now need, then resume, and pick up where you left off with the new grant
live. When a resume run grants **broader** access than the session originally ran
under (net, mounts, plugins, `allow_root`, `allow_sensitive`, services), glove
prints a prominent warning: the prior conversation context (which may include
prompt-injected instructions) will run with the wider reach.

> Transcripts and `models.json` (which holds the LLM API key in cleartext) live
> under `~/.glove/envs/<env-id>/home`. This is durable on-disk state — don't sync
> that tree to anywhere untrusted.

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
