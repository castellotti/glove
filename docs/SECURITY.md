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
| LLM API key | shell cmd (`env`, reading config) | ring 1 | nono `deny_vars` / srt env masking strip secrets from wrapped commands; key never in a tool's env. (Full proxy credential-injection so the key isn't in the *harness* env either is deferred) |
| The network (LAN, host loopback, arbitrary internet) | shell cmd | rings 0 + 1 | harness is on an internal-only bridge; only single-purpose forwarder sidecars are routable; tool commands are `--block-net` |
| The operator's browser | prompt-injected `curl` | rings 1 + 6 | only the harness's browser tool path may reach the browser endpoint; shell commands cannot |
| The host / Docker Engine | container escape | ring 0 hardening | never `docker.sock`, never `--privileged`, never host-gateway on the harness |

## Network observability (the netgate)

With `observe.enabled`, the service forwarders are replaced by the netgate
(`docs/planning/network-observability.md`). It changes what glove *records*,
never what the agent can *reach*:

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
  that resolves privately (DNS rebinding, `127.0.0.1.nip.io`) passes the gate,
  and the upstream proxy's own policy is the backstop until the in-tunnel
  resolver (M4). Note too that `route: vpn|tor` is the operator's declaration,
  not a verified fact.
  Measured on glove-pi-search: gluetun's HTTP proxy forwards to gluetun's own
  control server (`gluetun:8000`, and `127.0.0.1:8000` inside its namespace),
  which can reconfigure the VPN. Only gluetun's control-server auth stood in the
  way. Under the gate, those requests are refused before they reach gluetun.
- **No new API.** Forwarders listen only on their forward port. The collector
  has `network_mode: none`, so it has no interface at all. Records travel over
  a Unix datagram socket on a tmpfs volume that only the gate containers mount.
- **No new privilege.** Gate containers run as the operator's uid with
  `cap_drop ALL`, `no-new-privileges`, a read-only rootfs and pids/mem limits.
  They never get `NET_ADMIN`, never share the harness's network or PID
  namespace, and never mount its home.
- **Invisible to the agent.** Telemetry goes to the session's `net/` dir, which
  is bind-mounted into the collector only. The render refuses (no waiver) any
  harness mount that overlaps `net/`: the agent must neither read its own flow
  record nor forge one.
- **No host DNS.** Nothing on the host resolves a destination. The gate resolves
  only its configured target or upstream (as socat did) and glove's own ingress
  alias. In proxy mode the destination reaches the upstream as text. This was
  measured live by sniffing the gate's netns: only the upstream's name was ever
  queried. A destination IP is either a literal or reported `unavailable`.
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
