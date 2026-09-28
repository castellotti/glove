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

> **Minimal core + extensions (v3, in progress).** The base image is *harness +
> enforcer only*. Every capability is an **extension** in `extensions/<name>/`
> (a declarative `extension.yml`), selected per session in `extensions:`. An
> extension you don't select contributes nothing: no containers, no mounts, no
> image layers. Today: **`llm`** (the inference engine; required), **`media`**
> (analysis toolchain), **`search`** (SearXNG) and **`playwright`** (host
> Chromium). See [Extensions](#extensions).

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
| Enforcer | nono (Landlock) - default | nono 0.78.0; Pi wired + verified (16-check integration) |
| Enforcer | srt (bubblewrap) - opt-in | srt 0.0.77; Pi wired + verified (11-check integration, incl. env/`/proc` key leaks); tool commands only |
| Enforcer | none (ring 0 only) | debug |
| Inference | `llm` extension: openai-compatible (default; vLLM, NInfer, …), llama.cpp, ollama, lmstudio, openai, anthropic, mistral, openrouter | `host` verified live (stub llama-server); `lan` verified live (`openai-compatible` → NInfer over the user's VPN, `model: auto`, key by Keychain reference, Pi answered); cloud providers **untested** |
| Browser | `playwright` extension, `mode: host` | implemented; MCP pinned (`playwright-core@1.63.0 mcp`); per-session Chrome profile; refused with Vibe unless `i_accept_host_rce: true`; host-side start **untested** |
| Browser | `playwright` headless / novnc sidecars | planned (v3 M7) |

Giving a harness web access needs Node/npx and a Chromium-family browser on the
host; the friction-free option is Playwright's own Chrome for Testing
(`npx playwright install chromium`). For a complete, reproducible setup - Pi
against a remote OpenAI-compatible LLM over an SSH tunnel plus a dedicated headed
Playwright browser, including the `@playwright/mcp` `--browser` channel gotcha and
the `--executable-path` fix - see **[docs/pi-remote-llm.md](docs/pi-remote-llm.md)**
and start from **[docs/examples/pi-remote-llm.glove-session.yml](docs/examples/pi-remote-llm.glove-session.yml)**
(`glove new docs/examples/pi-remote-llm.glove-session.yml <dir>`).

Runnable presets live in **[docs/examples/](docs/examples/)**.

## Quick start

**A session is a directory.** `glove new` materializes one; you edit one file and
run `glove up`. Its state lives in `<dir>/.glove/`, so deleting the directory
deletes the session (only a registry row, and what an extension explicitly
exports, stays under `~/.glove`; `glove gc` removes those).

```sh
glove new minimal ~/work/research-1     # glove-session.yml, work/, .glove/ (0700)
cd ~/work/research-1
$EDITOR glove-session.yml               # the ONE file you edit (set the llm <set-me>s)
glove check                             # schema, secrets exist (never read), doctor
glove plan                              # what it grants; renders .glove/, launches nothing
glove up                                # build → sidecars → resolve model → TUI
glove down                              # stop (glove rm: also delete .glove/)
```

`glove new` takes a bundled template (`templates/`: `minimal`), a path to a
directory or file, or a git URL. Templates are *materialized*, not inherited:
the file is a full copy, so upgrading glove never silently widens a session.
`glove check` warns when the template changed since, and `glove new --diff`
shows how.

```
<session-dir>/
  glove-session.yml   the file you edit (no secrets: references only)
  work/               → /work (rw)
  local/              optional private host assets (e.g. hooks); never mounted
  .glove/             0700; only home/ and enforcer/ are mounted
    id                stable session id: <dirname>-<6 hex>
    compose.yml  effective.yml  baseline.yml  template.yml
    home/             → /home/agent (config, transcripts)
    enforcer/         → /etc/glove/enforcer (ro, ring-1 policies)
    ext/<name>/       per-extension state
```

## Session file (`glove-session.yml`, schema v3)

```yaml
glove: 3
template: minimal           # provenance only
harness: pi                 # pi | vibe | claude-code (experimental)
runtime: docker             # docker | podman | apple-container|gondolin|utm (stub)
enforcer: nono              # nono (Landlock, default) | srt (bubblewrap) | none
mounts:                     # explicit extra host dirs; work/ is always /work
  - { path: ~/src/shared-lib, mode: ro }
extensions:                 # name → settings; unlisted = nothing in the session
  llm:                      # required: fills the `inference` slot
    provider: llama.cpp     # openai-compatible (any OpenAI-API server) | llama.cpp | ollama | lmstudio | openai | anthropic | mistral | openrouter
    location: host          # host (this Mac) | lan | internet
    endpoint: 127.0.0.1:8080
    model: auto             # or an id; auto = the single model /v1/models lists
    capabilities: auto      # or explicit keys, e.g. {vision: true}; probes fill the rest
    # api_key: keychain:my-llm   # a reference only (keychain:<service> | env:<VAR>)
  media: {}
  # search: { host_port: 8888 }  # a SearXNG on this Mac (interim until v3 M4)
  # playwright: { mode: host }   # headed Chrome on this Mac
tools: { net: block, allow_commands: [cp, mv, rm] }
limits: { pids: 512, memory: 4g, cpus: 2 }
enforcer_options: { srt: { nested: weak } }
observe: { enabled: true }  # network observability (off by default) — see below
protect_ide_files: false    # also ro-bind .vscode/.envrc/.mcp.json (creates empty ones if missing)
```

Relative mount paths resolve against the session directory. A mount that would
expose `.glove/`, `local/`, `glove-session.yml`, glove's home (`~/.glove`) or
another session's state is refused. The v2 keys (`workdir`, `add_dirs`, `net`,
`services`, `name`, …) are refused with a pointer to their replacement.

Each session gets a /24 from `subnet_pool` in `~/.glove/config.yml` (default
`172.31.0.0/16`), recorded in the registry, and each of its networks a /27 of
it. Allocation avoids other sessions and the runtime's existing networks; if a
foreign network takes the range later, `glove up` re-allocates.

`.git/hooks` and `.git/config` in every rw mount are always bound read-only (and
`.git` is pinned so it can't be renamed away): an agent must not plant a hook your
Mac runs the next time you use git. See "Planted host-trusted files" in
[docs/SECURITY.md](docs/SECURITY.md).

## CLI

Session commands take an optional directory; without one they use the nearest
`glove-session.yml` at or above the current directory.

```
glove new <template|path|git-url> [DIR]      # materialize a session (DIR default: .)
glove new --diff <any> [DIR]                 # how the template changed since `glove new`
glove check [DIR] [--no-container]           # schema, placeholders, secrets exist, doctor
glove plan  [DIR] [--compose] [--resume|--session ID]   # render .glove/, print the grants
glove up    [DIR] [--resume|-r] [--session ID] [--rebuild]
glove down  [DIR] [--wipe]                   # --wipe: also volumes + the flow record
glove rm    [DIR] [--all] [--yes]            # down --wipe, delete .glove/ + exports + row
glove policy [DIR]                           # ring-1 policies + ring-0 hardening + gaps
glove ls | ps | gc [--yes]                   # registry rows (ok|missing|stale), running, prune
glove keychain set <service>                 # store a secret, prompting (never in argv)
glove doctor [--runtime R] [--enforcer E] [--json] | build [HARNESS] [--enforcer srt] | version
glove net status [--dir D] [--json]          # gate health + per-service totals
glove net flows  [--dir D] [--follow] [--json] [--tail N]
glove net block  <host-glob|ip|cidr> [--port N] [--terminate] [--allow] [--note TEXT]
glove net unblock <rule-id|target>
glove net rules  [--json]                    # rules + the gate's load result
glove net validate <file|-> [--env ID] [--session ID] [--json]   # the gate's validator; pure
```

`~/.glove/registry.json` (v2, `{"v": 2, "sessions": [{id, dir, harness,
template, created, grants, subnet}]}`) indexes sessions; a v2-era registry
(a JSON list) is refused rather than overwritten; move it aside.

### Network observability

With `observe: {enabled: true}`, every service forwarder becomes an instrumented
**netgate**: a drop-in for the socat forwarder (same container name, networks
and port, so the harness config is unchanged) that records every connection:
open, ~1 Hz updates while bytes move, and close, with cumulative byte counts,
timing, tool label and scope. Records go to the session's export directory
(`~/.glove/observe/<id>/net/`, outside the session dir's mounts) through a
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
leave `rules.json` readable by you (mode `0644`); see "Layman" below. The
built-in SSRF guard always runs first.

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
Sample data: `tests/fixtures/netobs/` (the original fixture, frozen) and one
directory per UI state in `tests/fixtures/netobs-scenarios/`.
Verified live on Docker Desktop (macOS) and on rootless and rootful Podman,
including an SELinux-enforcing Fedora host. On Podman the gate's `net/` and
`control/` binds are labelled `selinux: z`, and its socket tmpfs gets a
container SELinux context when SELinux is on. Rootful Docker on Linux:
**untested**. On a native SELinux host, the *harness's* own binds are not
labelled: **unsupported** (see "Layman" below).

### Layman

[Layman](docs/planning/network-observability-layman-handoff.md) shows glove's
sessions and traffic, and edits their rules. The two projects are independent:
Layman touches glove's folders only if they already exist, and glove owns
every folder, owner and mode under `~/.glove`.

- **What Layman mounts.** `~/.glove` read-only, and `~/.glove/control`
  read-write over it, each only if it exists when Layman starts. Layman follows `~/.glove` only, not
  `$GLOVE_HOME`. A `control/` that appears later is picked up when Layman
  restarts.
- **What glove guarantees.** Whenever glove creates its home (`glove new`, any
  registry write), it also creates `control/`, and adds it to an older home
  that lacks it. Both are yours, mode `0777 & ~umask` (`0755` usually).
  `control/<id>/` (`0700`) is created when a session with a gate is rendered,
  and `observe/<id>/net/` is `0700` with files `0600`; `rules.json`'s `env` and
  `session` are both the session id. glove warns, with the `sudo chown` that
  fixes it, when `control/` belongs to someone else. (The v3 read/write grant
  split, and Layman's side of the new paths, land in v3 M5.)
- **What Layman writes.** Only `control/<id>/rules.json`, only if
  that directory exists, and by atomic rename: a temp file unique to Layman
  in the same directory, `fsync`, `chmod 0644` (explicitly, not through the
  umask), rename. No `chown`, no new directories. The directory is `0700` and
  yours, so the file is readable by the gate (which runs as you) and by nobody
  else. The contract is the handoff's §3, "Ownership".
- **SELinux hosts (Fedora, RHEL) are not supported yet**, for glove sessions
  or for Layman. On an enforcing host a container is denied files under your
  home unless they carry a container label, and glove sets none on its home or
  on `/work`. Supporting it is a separate piece of work that must decide how
  harness homes are isolated from each other and what Layman may read
  (`docs/planning/layman-independence-results.md`).

Verified by `netgate_control_perms.sh` on Docker Desktop and on rootless and
rootful Podman.

### Resuming a session

A conversation's transcript lives in the session's `.glove/home` (bind-mounted
at `/home/agent`), **not** in the (ephemeral) container. So you can reopen one:

- `glove up --resume` (`-r`) — reopen the **most recent** conversation. glove
  checks a transcript exists, then defers to the harness's own continue-last,
  so use `--session <id>` when you need to be sure exactly which one reopens.
- `glove up --session <id>` — reopen a **specific** conversation (full or
  partial UUID, or a transcript path). glove resolves it to that transcript's
  canonical id before handing it to the harness.

Because glove re-renders the whole sandbox from the *current* config on every
run, **editing `glove-session.yml` before resuming changes the grants for the
resumed conversation** — e.g. add an extension or a mount you now need, then
resume with the new grant live. When a resume run grants **broader** access than
the session's `.glove/baseline.yml` (mounts, extensions, `allow_root`,
`allow_sensitive`), glove
prints a prominent warning: the prior conversation context (which may include
prompt-injected instructions) will run with the wider reach.

> Transcripts live under the session's `.glove/home/`. This is durable on-disk
> state — don't sync that tree to anywhere untrusted (`.glove/` carries a
> `.gitignore` of `*`, so a session inside a git repo never commits it).
>
> **The LLM API key is never in a file.** `extensions.llm.api_key` must be a
> reference: `keychain:<service>` (a macOS Keychain generic password) or
> `env:<VAR>`; a literal key is refused. glove resolves it in memory when the
> session launches (never during `glove plan` or `glove check`, which only checks
> that the Keychain item exists), and the effective config records
> only the reference. The compose file declares `GLOVE_LLM_API_KEY` without a value, glove supplies it in
> the environment of `compose` when it starts the session, and Pi's `models.json`
> refers to it as `"$GLOVE_LLM_API_KEY"`. Inside the sandbox only the harness
> process sees it; ring 1 strips it from every shell command. Store a key with
> `glove keychain set <service>` (it prompts; the key is never in argv).

## Extensions

An extension is a directory under `extensions/` with an `extension.yml`
manifest (`api: 1`): its settings schema, the endpoints (forwarders) the
harness may reach, image layers, Pi extensions / Vibe MCP servers, a brief for
the agent, and optionally hardened sidecars. Core validates all of it:

- **Settings** are typed; unknown keys, `<set-me>` placeholders and literal
  secrets are errors. Secrets are `keychain:`/`env:` references, resolved in
  memory and passed to containers only as compose secrets from glove's
  environment.
- **Slots** are exclusive: `inference` (required; `llm`), `egress`, `browser`.
  Two providers of one slot are refused.
- **Sidecars** get the hardening set (non-root, `cap_drop: ALL`,
  `no-new-privileges`, read-only rootfs, seccomp, pids/memory limits) from core;
  a fragment cannot set a security key. Exceptions come only from the manifest's
  `privileges:`, drawn from an allowlist, and are shown in `glove policy`.
  No extension publishes ports, joins the harness network, mounts the docker
  socket, or binds host paths other than its own session state.
- **The harness** only ever gets forwarders on its internal network.
- **Out-of-tree** extensions load from `extension_paths:` in
  `~/.glove/config.yml`, are labelled *out-of-tree*, and cannot take privilege
  exceptions (or reach host ports) unless listed in `trusted_extensions:`.

`llm` is the inference engine, picked like a gluetun VPN provider: `provider:`
names a catalog entry (`extensions/llm/providers/*.yml`). `location:` routes it:
`host` → a forwarder to this Mac; `lan` → a forwarder that dials exactly the
configured `host:port`; `internet` → a forwarder to the provider's HTTPS host,
aliased so TLS runs end to end. The harness never gets LAN or internet reach
itself. `model: auto` and `capabilities: auto` are resolved at launch from a
throwaway container on the harness network (the host never contacts the
server), and core renders the result into Pi `models.json` / Vibe `config.toml`
(vision → `input: ["text","image"]`).

## Toolchain

Python ≥ 3.11 managed with [uv](https://docs.astral.sh/uv/):

```sh
uv sync
uv run ruff check glove extensions tests   # lint
uv run pytest -q                           # unit suite (includes the layering check)
uv run lint-imports                        # core (glove/) must not import extensions/
# integration (need Docker; build the images first):
bash tests/integration/test_pi_nono.sh    # nono / Pi  (16 checks)
bash tests/integration/test_vibe_nono.sh  # nono / Vibe (10 checks)
bash tests/integration/test_pi_srt.sh     # srt  / Pi  (11 checks)
bash tests/integration/test_ring0_protect.sh  # ring-0 ro binds over .git/hooks etc. (15 checks)
bash tests/integration/test_session_dir.sh    # session dir lifecycle vs a stub llm (10 checks)
bash tests/integration/test_llm_host_stub.sh  # llm location: host vs a stub llama-server, Pi answers
bash tests/integration/test_llm_lan.sh HOST:PORT [KEYCHAIN_SERVICE]  # llm location: lan vs your server
```

glove is being restructured (v3) into a minimal core in `glove/` plus in-tree
extensions in `extensions/`. The import boundary is enforced by
[import-linter](https://import-linter.readthedocs.io/): `glove` must never import
`extensions`, the same way a kernel never depends on its modules.
