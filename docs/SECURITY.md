# glove security model

glove runs an agentic coding harness — an LLM that executes shell commands,
extensions, skills, and MCP servers on your behalf — and treats **the agent and
everything it spawns as untrusted**. The primary adversary is not a human
attacker but *the agent itself under prompt injection*: a poisoned web page,
README, or tool result that makes the model run a command it shouldn't.

## Three rings (defense in depth)

| Ring | Boundary | Mechanism | What it stops |
|---|---|---|---|
| 0 — Runtime | container / VM | namespaces, bind-mount allow-list, internal-only network, the hardening set (non-root, `cap_drop ALL`, `no-new-privileges`, read-only rootfs, seccomp, pids/mem/ipc) | escaping the namespace; reaching un-exposed host dirs; reaching the LAN/host; privilege escalation via setuid/caps |
| 1 — Enforcer | every process | **nono** (Landlock) by default, or **srt** (bubblewrap); wraps the harness *and* every shell command in a kernel policy | a shell command reading the harness home / secrets, writing outside `/work`, or opening the network — even though it runs *inside* ring 0 |
| 2 — Harness | tool calls | Pi extension / Vibe `pre_tool` hook route every `bash`/`!` through ring 1; block egress tools; the context file tells the agent the rules | the agent invoking an unsandboxed shell; native web-fetch tools |

A compromise must defeat **all three, in order**. Ring 1 also shrinks the kernel
attack surface the agent can even reach (no raw sockets, no `AF_UNIX` to the
container's own daemons, denied paths never opened), which is what makes a
ring-0 escape harder to *deliver*, not merely harder to *exploit*.

## Assets × adversaries × rings

| Asset | Adversary | Defended by | Notes |
|---|---|---|---|
| Host source outside the allow-list | prompt-injected shell cmd | rings 0 + 1 | only exposed dirs are bind-mounted; ring 1 denies the rest even inside the container |
| The harness's own config / extensions / session transcripts | shell cmd | ring 1 | harness home is writable to the harness process, **denied to tool commands** (Landlock omit / srt deny of the home mount) |
| LLM API key | shell cmd (`env`, reading config, `/proc/<harness>/environ`) | ring 1 | nono `deny_vars` (glob patterns) and srt `credentials.envVars` `mode: deny` (exact names: the LLM key plus every passthrough secret, applied as bwrap `--unsetenv`) remove secrets from wrapped commands, so the key is never in a tool's env. A tool command cannot read the harness's `/proc/<pid>/environ`: Landlock scoping denies it under nono, and under srt the kernel refuses it across bwrap's user namespace (weak mode; verified on Docker Desktop's 7.0 kernel, re-checked by `tests/integration/test_pi_srt.sh`), while strong mode has a separate PID namespace. Weak mode still shows the harness's PIDs and process names. Proxy credential injection, which would keep the key out of the *harness* env too, is deferred. |
| The network (LAN, host loopback, arbitrary internet) | shell cmd | rings 0 + 1 | harness is on an internal-only bridge; only single-purpose forwarder sidecars are routable; tool commands are `--block-net` |
| The operator's browser | prompt-injected `curl` | rings 1 + 6 | only the harness's browser tool path may reach the browser endpoint; shell commands cannot |
| The host / Docker Engine | container escape | ring 0 hardening | never `docker.sock`, never `--privileged`, never host-gateway on the harness |
| Host code execution via files the host trusts later (git hooks, `.git/config`, IDE/direnv settings) | shell cmd *or* the harness writing into `/work` | ring 0 | see "Planted host-trusted files" below |
| Other sessions' browser state | the host browser | host services | the host Chrome profile is per session (`<session>/chrome-profile`), and Chrome stops on `glove down` unless `browser.keep_browser: true` |

## Extensions (what a capability pack may and may not do)

Every capability (the model, search, the browser, …) is an extension in
`extensions/<name>/`. Core, not the extension, decides how its containers run:

- A fragment can declare only images, commands, env, volumes, networks and
  healthchecks. Core adds the hardening set to every sidecar (non-root,
  `cap_drop: ALL`, `no-new-privileges`, read-only rootfs, seccomp, private IPC,
  pids/memory limits). Exceptions come only from the manifest's `privileges:`,
  from an allowlist, and `glove policy` lists them. `low_ports` sets
  `net.ipv4.ip_unprivileged_port_start=0` in the sidecar's own network
  namespace (docker's default for every container; podman needs it stated),
  rather than granting `NET_BIND_SERVICE`.
- Never: published ports, `privileged`, host network/PID/IPC namespaces, the
  docker socket, host binds outside the extension's own session state (or an
  export root it owns, below), or a sidecar on the harness network. The harness reaches extensions only through
  single-purpose forwarders. Only the active egress provider joins the routable
  `wan` network.
- Secrets are references (`keychain:`/`env:`), resolved in memory and handed to
  containers as compose secrets from glove's environment; a literal secret in a
  setting is refused.
- Out-of-tree extensions (`extension_paths`) are labelled as such and get no
  privilege exceptions, host ports or host services unless trusted.
- `glove/` never imports `extensions/` (`uv run lint-imports`).
- **Export roots** are the only session data outside the session directory, and
  core owns them: `~/.glove/observe/<id>/` exists only for the in-tree
  `observe` extension, `~/.glove/control/<id>/` only while the in-tree `filter`
  extension is active (and then read-only in the gates). Binds are checked by
  path; any other extension gets neither.
- **The forwarder slot.** An extension filling `forwarder` (observe) may replace
  the socat forwarders, but only with services core names, networks and
  hardens: its hook cannot choose networks, aliases outside the endpoint's own
  name, security keys or privileges.
- **Low ports.** A forwarder listening below 1024 gets
  `net.ipv4.ip_unprivileged_port_start=0` in its own network namespace (Docker's
  default; Podman does not set it), so it still runs as the operator's uid with
  no capabilities.

The inference server is reached the same way: one `glove-<id>-llm` forwarder
that dials exactly the configured host (or the host gateway, or a cloud API on
443). The harness never gets a LAN or internet route of its own.

### Egress (`vpn`, `tor`, `direct`, `corporate`)

Web tools reach the internet only through the session's egress provider.
Egress consumers (SearXNG, the harness's `proxy` forwarder) sit on the
**internal** `glove-<id>-egress` network. Only the provider's tunnel container
(gluetun, tor or tinyproxy) is on the routable `glove-<id>-wan`. If the proxy
fails, a consumer has no other route out. v2's SearXNG, on a normal bridge with
public DNS, could have. Measured live: SearXNG cannot resolve or reach
`example.com` itself, and neither can a container on the harness network.

- **Fail closed at launch.** `glove up` starts the harness only after the
  provider's checks pass: gluetun healthy (a dead WireGuard handshake is told
  apart by tun0's byte counter), Tor's SOCKS port open, and `exit-ip-differs`
  (the exit IP seen through the proxy must differ from this machine's; an
  unknown IP on either side fails too). A failure shows the sidecar's last log
  lines, with key and password lines withheld, and stops the session's sidecars.
- **Privileges.** Only gluetun takes exceptions (root, `NET_ADMIN`,
  `/dev/net/tun`, writable rootfs; no sysctls). It is never on a network with
  the harness. tor, privoxy, tinyproxy, SearXNG and valkey run with the full
  sidecar hardening as the operator's uid. valkey is on a private network with
  SearXNG only. gluetun's control server listens on loopback, and since gluetun
  v3.40 every control route needs credentials, none of which glove configures.
- **Secrets.** The WireGuard key (or OpenVPN user/password) is a Keychain
  reference resolved at `glove up` and handed to gluetun as a compose secret. A
  **register hook** (an executable that must resolve inside the session's
  `local/`, which is never mounted, so a symlink into `work/` is refused) gets
  the account credentials on stdin. Its key goes to gluetun the same way; nothing
  is written to disk.
- **No way in through the proxy.** `web_fetch` refuses non-public destinations
  before the request is sent: non-global IP literals, single-label and local
  names, credentials in the URL. It follows redirects itself so every hop is
  checked. `direct`'s tinyproxy refuses the same shapes (CONNECT included) and
  allows CONNECT only to 443/80. Tor exits and gluetun's kill switch already
  refuse private destinations. **Known gap:** names are judged by shape and never
  resolved, so a public name that resolves privately passes both checks under
  `direct`. With observe on, the proxy gate's in-tunnel resolver closes this for
  vpn and tor (a name resolving to a private address is refused); `direct` has
  no in-tunnel resolver, so the gap stays there.
- **`direct` is not anonymous.** Its flows are labelled `route: direct`. Its
  brief tells the agent so.
- **tor's SOCKS port** is on the private `torlink` and on the internal egress
  network (observe's gates resolve names in-tunnel through it), never the
  harness network. Everything on the egress network already leaves only through
  Tor; tor has no ControlPort.
- **`corporate`: an allowlist, not a tunnel.** Its proxy is a netgate that
  resolves destinations itself (the host's resolver via Docker/Podman, so the
  corporate VPN's split DNS applies), checks the **resolved address**, applies a
  static default-block policy built from `allow_domains`/`allow_cidrs`/
  `from_interface`, and dials that same address (never re-resolving). The
  allowlist is also the SSRF guard's exception list, because corporate hosts are
  private. It comes only from `glove-session.yml`, reaches the gate only on its
  command line, and cannot come from `rules.json` (no such key; the corporate
  gate does not read `rules.json` at all). Refused whatever the allowlist says:
  loopback, link-local/metadata (`169.254.0.0/16`, `100.100.100.200`),
  multicast, the runtime's host gateway (resolved from its fixed names at
  start), the session's own /24, and names like `host.docker.internal`.
  `web_fetch` gets the same allowlist for its own pre-check. Measured live (a
  public host standing in for a corporate one): the allowed host is reached,
  everything else is refused with the gate's reason, and the host gateway,
  metadata and the session's network are refused even inside an allowed CIDR.
  **Untested:** a real corporate VPN (split DNS and routes via the host).

## Planted host-trusted files (ring 0)

`/work` is writable, and some files in it are later *executed or trusted by the
host*: git runs `.git/hooks/*` and honours `.git/config` (`core.hooksPath`,
`core.fsmonitor`, filter drivers …) the next time you run git on your Mac, and
IDEs and direnv act on `.vscode/`, `.envrc` and `.mcp.json`. An agent that
plants one gets code execution **outside** the sandbox. Landlock cannot express
"writable directory except these children", so glove adds nested read-only
binds after each rw mount (`glove/mounts.py:protected_paths`):

- **Always, at the root of every rw mount that is a git repo:** `.git/hooks`
  and `.git/config` are read-only, and so is an in-tree `core.hooksPath`
  directory. `.git` itself is re-bound (read-write) so that it is a mount
  point. Renaming or deleting it fails with `EBUSY`, which stops the agent from
  swapping in a fresh `.git` with its own hooks. Commits, branches and fetches
  still work.
- **With `protect_ide_files: true`:** `.vscode/`, `.envrc` and `.mcp.json` are
  read-only. When one is missing, glove binds an empty placeholder over it,
  which creates an empty file or directory in your repo. That side effect is
  why this setting is opt-in.
- Bind sources are resolved with realpath and must stay inside the mount, so a
  symlink can't expose another host path.

**Residual gaps:** paths that don't exist at start (for example `git init`
run inside a directory with no repo yet), nested repositories and submodules
(`.git/modules/*`), and `.git` files (worktrees) are not covered.
`tests/integration/test_ring0_protect.sh` checks this live.

## Network observability (the netgate): observe reads, filter writes

With the `observe` extension, the forwarders are replaced by the netgate
(`docs/planning/network-observability.md`). It changes what glove *records*,
never what the agent can *reach*. Writing rules is a separate grant, the
`filter` extension: without it no gate reads a rules file, none mounts
`~/.glove/control/`, and glove never creates `control/<id>/` (an invariant
test). Removing `filter` revokes the grant at the next `glove up` (the rules
file moves into the session dir, the directory goes, `status.json` stops
reporting `rules`).

- **Same reach.** Each gate forwarder has exactly the name, networks, port and
  target of the socat sidecar it replaces. A `tcp` gate dials only its configured
  target. An `http-proxy` gate dials only its configured upstream proxy; the
  agent picks the destination, but the upstream was already routable through the
  socat forwarder, so reach doesn't change. What *is* new is the SSRF surface of a
  general proxy, handled by the guard below.
- **SSRF guard (`http-proxy` mode).** Before anything is sent upstream, the gate
  refuses destinations that are not plainly public: non-global IP literals in any
  notation (`169.254.169.254`, `2130706433`, `[::ffff:127.0.0.1]`), single-label
  names (every container on the egress network, including gluetun's control
  server), and local suffixes (`localhost`, `.local`, `.internal` …). Requests
  are re-serialised from the parsed destination, never forwarded verbatim, so the
  upstream acts on exactly the host that was checked. Absolute-form requests are
  forced to one request per connection. **Known gap:** the guard judges a name
  by its shape and never resolves it (that would leak it). A public-looking name
  that resolves privately (DNS rebinding, `127.0.0.1.nip.io`) passes the shape
  check; with the egress provider's in-tunnel resolver (vpn, tor) the gate
  resolves it in-tunnel and refuses a private answer. The route is the egress
  provider's declaration, not a verified fact.
  Measured on glove-pi-search: gluetun's HTTP proxy forwards to gluetun's own
  control server (`gluetun:8000`, and `127.0.0.1:8000` inside its namespace),
  which can reconfigure the VPN. Only gluetun's control-server auth stood in the
  way. Under the gate, those requests are refused before they reach gluetun.
- **SearXNG behind its own gate.** With observe on, SearXNG leaves the egress
  network: it reaches the egress proxy only through its gate (`searxng-egress`)
  on the search extension's private network. The gate is never on the harness
  network and is never offered to the harness (tests and a live check assert
  SearXNG cannot reach the proxy directly). The SSRF guard and, with filter, the
  rules cover SearXNG's requests too.
- **`record: full` is a deliberate privacy trade.** It writes the method and
  URL of cleartext HTTP requests (and, opted in, headers with credentials
  redacted) to disk. HTTPS paths are never visible, because there is no TLS
  interception. glove warns at launch, and the mode is carried in `session.json`,
  `status.json` and `glove observe status`. `retain` and `glove down --wipe` bound
  how long any of it stays.
- **No new API.** Forwarders listen only on their forward port. The collector
  has `network_mode: none`, so it has no interface at all. Records travel over
  a Unix datagram socket on a tmpfs volume that only the gate containers mount.
- **No new privilege.** Gate containers run as the operator's uid with
  `cap_drop ALL`, `no-new-privileges`, a read-only rootfs and pids/mem limits.
  On rootless Podman they (and the collector) run `keep-id`, because they share
  a tmpfs volume owned by that uid; glove starts sidecars one at a time there
  (Podman 6.1 gives concurrently started keep-id containers a one-entry id map).
  They never get `NET_ADMIN`, never share the harness's network or PID
  namespace, and never mount its home.
- **Invisible to the agent.** Telemetry goes to `~/.glove/observe/<id>/net/`,
  which is bind-mounted into the collector only. The render refuses (no waiver)
  any harness mount that overlaps the observe export or `control/<id>/`: the
  agent must neither read its own flow record nor forge one. The one exception
  is the transcripts export (`observe/<id>/transcripts/`), which the harness
  writes as it always wrote its transcripts; a reader of that directory must
  treat it as agent-written data.
- **A control channel that can only say allow/block.** `rules.json`
  (`~/.glove/control/<id>/`, only with the filter grant) is mounted read-only
  into the gate containers and never into the harness. The same no-waiver render check applies,
  so the agent cannot read or rewrite its own rules. Its schema has no key for a
  path, command, mount, image or environment variable. Any unknown key rejects
  the whole file, and the gate keeps its last known-good set, so a buggy or
  compromised writer can at worst change which destinations are allowed. The
  built-in SSRF guard runs before the rules, so no rule can allow an internal
  destination; only the operator's `corporate` allowlist (session file,
  command line) widens it.
- **No host DNS.** Nothing on the host resolves a destination. An observe gate
  resolves only its configured target or upstream (as socat did) and glove's
  own ingress alias; the corporate egress gate, by design, resolves destinations
  in its container and checks the address before dialling it. In proxy mode the destination reaches the upstream as text. This was
  measured live by sniffing the gate's netns: only the upstream's name was ever
  queried. A destination IP is either a literal or reported `unavailable`.
- **Traffic the gate itself originates (M4, when configured).** A proxy gate
  sends DNS queries for destination names to the configured *in-tunnel*
  resolver (gluetun's DNS, which uses DoT through the VPN, or Tor `RESOLVE`), the same resolver the
  upstream uses anyway. With `exit_identity: via-proxy`, one gate also fetches an
  IP-echo URL through the tunnel every ~5 min. That service learns the exit IP
  and nothing about the operator. Neither is agent traffic, so neither appears
  in `flows.ndjson`.
- **Fail open on telemetry.** A stopped, slow or unwritable collector drops
  records (counted in `status.json`, logged by the collector), never traffic.

## The Docker Desktop (macOS) blast radius

Be precise about what "container root" means here:

1. **Container root ≠ host root.** On Docker Desktop every container runs inside
   *one shared Linux VM*. A full container escape yields **VM root**, not macOS
   root. glove's ring-0 hardening (non-root, `cap_drop ALL`, `no-new-privileges`,
   read-only rootfs, seccomp) is specifically to make that escape hard.
2. **What VM root can reach on the Mac** is (a) every directory in Docker
   Desktop's *File sharing* list (defaults: `/Users`, `/Volumes`, `/private`,
   `/tmp`, `/var/folders`) with the logged-in user's permissions, (b) the Docker
   Engine, (c) whatever the VM can route to (host loopback via
   `host.docker.internal`, the LAN, the VPN). That is a large radius —
   effectively "the user's account" — which is exactly why the hardening set is
   non-negotiable and why the operator steps below matter.
3. **The trivial escalations are configuration, not fate.** They come from
   mounting `/var/run/docker.sock`, `--privileged`, running as root with
   `CAP_SYS_ADMIN`, or over-broad bind mounts. glove does none of these and
   refuses to render a project that violates the hardening table unless an operator
   explicitly waives a row with `--i-know-what-i-am-doing <key>`.

## Operator recommendations

- **Narrow Docker Desktop File sharing** to just your code roots (Settings →
  Resources → File sharing). Removing `/Users` shrinks the VM-root blast radius
  dramatically. `glove doctor` reports the current list (best effort) and
  recommends narrowing.
- **Enable Enhanced Container Isolation (ECI)** if you have Docker Business — it
  gives each container a user namespace (Sysbox), blocks `docker.sock` mounts,
  and neuters `--privileged`. `glove doctor` reports whether it appears on.
- **Keep Docker Desktop patched.** Container-escape and VM-boundary bugs are a
  live class — e.g. CVE-2026-2664 and CVE-2026-6406 are examples of the kind of
  Docker Desktop / runtime vulnerability that ring 0 alone cannot survive. Ring 1
  raises the bar, but a patched engine is the baseline.
- **Prefer a per-container-VM runtime when available** — Apple `container`
  (macOS 26, Apple silicon) or a `utm`/`gondolin` VM gives each container its own
  kernel, so an escape yields a throwaway VM, not the shared one. glove keeps the
  runtime layer pluggable for exactly this.
- **Choose `enforcer: nono`** (default) over `srt` unless you specifically need
  srt: srt requires relaxing the seccomp profile to allow unprivileged user
  namespaces (a historical source of kernel LPE bugs) and wraps tool commands
  only, leaving the harness process on ring 0 alone.
- **Browser `host-mcp` with Vibe is refused by default.** Playwright's MCP always
  exposes `browser_run_code_unsafe`, which runs arbitrary JavaScript in the MCP
  process, and in `host-mcp` that process is on your Mac. Pi allowlists its
  browser tools. Vibe cannot filter MCP tools, so `vibe` + `host-mcp` needs
  `browser: {i_accept_host_rce: true}`. The host MCP is pinned
  (`playwright-core@1.63.0 mcp`), not `@latest`.

## What glove does NOT defend against

- **Kernel 0-days** — a Landlock/seccomp/namespace or hypervisor bug can defeat
  rings 0/1. Keep the host and Docker Desktop patched; prefer per-container VMs.
- **A malicious or already-compromised host** — glove trusts the machine it runs
  on. Host services (SSH tunnel, Chrome, Playwright) run with your full host
  trust by design.
- **Side channels** — timing, cache, `/proc` inference, etc. `srt.nested: strong`
  even exposes masked `/proc`/`/sys` to the whole container (documented, warned).
- **Denial of service beyond the limits** — the pids/memory/cpu caps bound
  resource exhaustion, but an agent can still burn its own CPU/quota.
- **The agent making bad but *authorized* changes** — glove constrains *where*
  and *what*, not *whether the edit was wise*. `/work` is writable; the agent can
  still break your code inside it. Use version control.
- **Supply-chain trust of the images/packages** themselves — glove pins the nono
  and Playwright versions and vendors the seccomp profile, but building images
  pulls from upstream registries.
