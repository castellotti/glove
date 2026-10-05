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
| 1 — Enforcer | every process | **nono+srt** by default on Docker (srt/bubblewrap around the harness, nono/Landlock around every command); **nono** by default on Podman; or **srt** (tool commands only); wraps the harness *and* every shell command in a kernel policy | a shell command reading the harness home / secrets, writing outside `/work`, or opening the network — even though it runs *inside* ring 0 |
| 2 — Harness | tool calls | Pi extension / Vibe `pre_tool` hook / Claude Code's managed `CLAUDE_CODE_SHELL_PREFIX` route every `bash`/`!` through ring 1; block egress tools; the context file tells the agent the rules | the agent invoking an unsandboxed shell; native web-fetch tools |

A compromise must defeat **all three, in order**. Ring 1 also shrinks the kernel
attack surface the agent can even reach (no raw sockets, no `AF_UNIX` to the
container's own daemons, denied paths never opened), which is what makes a
ring-0 escape harder to *deliver*, not merely harder to *exploit*.

## Enforcers at a glance (ring 1)

| | `nono+srt` | `nono` | `srt` | `none` |
|---|---|---|---|---|
| Default on | Docker | Podman | — (opt-in) | — (debug) |
| Harness process | srt (bubblewrap) + glove's seccomp | nono (Landlock) | ring 0 only | ring 0 only |
| Every tool command | nono (Landlock), inside srt | nono (Landlock) | srt (bubblewrap) | unwrapped |
| Tool network | none | none | none (empty allowlist) | ring 0 (forwarders) |
| Secrets in a tool's env | stripped (`deny_vars` globs) | stripped (`deny_vars` globs) | stripped (exact names) | **present** |
| Harness home / transcripts from a tool | denied | denied | denied | **readable** |
| Writes outside `/work`, rw mounts, `/tmp` | denied | denied | denied | ring 0 (read-only rootfs) |
| `.git/hooks`, `.vscode`, `.envrc`, … in `/work` | ring 0 ro binds + srt deny (present at launch) | ring 0 ro binds | ring 0 ro binds | ring 0 ro binds |
| `.env` files in `/work` | hidden (present at launch) | readable | readable | readable |
| Keystrokes into the TUI (TIOCSTI) | refused (`glove-pty notty`) | refused (`glove-pty notty`) | refused (bwrap `--new-session`) | **possible** |
| User namespaces / mounts | srt only; denied below it | denied (default seccomp) | srt only; denied below it | denied (default seccomp) |
| Container seccomp profile | `nested-userns` (relaxed) | default | `nested-userns` (relaxed) | default |
| Podman | refused | yes | refused | yes |

Details and the reasons behind each row: "`nono+srt` and `srt`" and "Planted
host-trusted files" below. `glove policy` prints the effective policy and the
remaining gaps for a session.

## Assets × adversaries × rings

| Asset | Adversary | Defended by | Notes |
|---|---|---|---|
| Host source outside the allow-list | prompt-injected shell cmd | rings 0 + 1 | only exposed dirs are bind-mounted; ring 1 denies the rest even inside the container |
| The harness's own config / extensions / session transcripts | shell cmd | ring 1 | harness home is writable to the harness process, **denied to tool commands** (Landlock omit / srt deny of the home mount) |
| LLM API key | shell cmd (`env`, reading config, `/proc/<harness>/environ`) | ring 1 | nono `deny_vars` (glob patterns) and srt `credentials.envVars` `mode: deny` (exact names: the LLM key plus every passthrough secret, applied as bwrap `--unsetenv`) remove secrets from wrapped commands, so the key is never in a tool's env. A tool command cannot read the harness's `/proc/<pid>/environ`: Landlock scoping denies it under nono, and under srt the kernel refuses it across bwrap's user namespace (weak mode; verified on Docker Desktop's 7.0 kernel, re-checked by `tests/integration/test_pi_srt.sh`), while strong mode has a separate PID namespace. Weak mode still shows the harness's PIDs and process names. With `enforcer_options: {nono: {browsers: true}}` (for Chromium in shell commands) the tool profile reads all of `/proc`; Landlock still refuses another domain's `environ`, `mem`, fd links and `root` (verified under nono+srt with the key in a harness-side process: readable from the harness, denied to a wrapped command; `tests/integration/test_toolchains.sh`), while command lines, `status`, `/proc/net` and `/proc/sys` become readable. Proxy credential injection, which would keep the key out of the *harness* env too, is deferred. |
| The network (LAN, host loopback, arbitrary internet) | shell cmd | rings 0 + 1 | harness is on an internal-only bridge; only single-purpose forwarder sidecars are routable; tool commands are `--block-net` |
| The browser (and, in host mode, the operator's desktop) | prompt-injected `curl` | rings 1 + 6 | only the harness's browser tool path may reach the browser endpoint; shell commands cannot. See "Browser" below |
| The host / Docker Engine | container escape | ring 0 hardening | never `docker.sock`, never `--privileged`, never host-gateway on the harness |
| Host code execution via files the host trusts later (git hooks, `.git/config`, IDE/direnv settings) | shell cmd *or* the harness writing into `/work` | ring 0 | see "Planted host-trusted files" below |
| Other sessions' browser state | the browser | sidecar / host services | sidecar modes: an in-memory profile by default (`profile: session` keeps it under this session's `.glove/`; refused with Tor unless acknowledged). Host mode: the Chrome profile and ports are per session, and Chrome stops on `glove down` unless `keep_browser: true` |

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
  export root it owns, below, or — trusted extensions, on a setting the user
  chose — a named subdirectory of `work/`; all of `work/` only with the `work`
  privilege, below), or a sidecar on the harness network. The harness reaches extensions only through
  single-purpose forwarders. Only the active egress provider joins the routable
  `wan` network.
- **Seccomp exceptions** name a core profile; the only one is `chromium-userns`
  (glove's default plus unconditional `clone`, `clone3`, `unshare`, `chroot`,
  for Chromium's namespace sandbox). The harness can never use it (a hardening
  row). A runtime that cannot apply a requested profile refuses the session
  (`glove check` shows it): podman's compose inlines a custom profile and
  podman rejects it, so there it must be turned off explicitly, never dropped.
- Secrets are references (`keychain:`/`env:`), resolved in memory and handed to
  containers as compose secrets from glove's environment; a literal secret in a
  setting is refused. A read-only sidecar cannot take an environment-sourced
  compose secret (Docker refuses), so such a sidecar gets its secret the way the
  harness gets its LLM key: a `launch_env` hook fills an `environment:` key
  declared without a value, for that `compose up` only (it is in the container's
  config, like the harness's key; never in a glove file).
- **Channels** (`channels:`, in-tree or trusted only) are the one non-network
  edge into the harness: a session tmpfs volume at `/run/glove/<name>` shared
  with named sidecars of the same extension, writable by the harness and its
  commands (every enforcer grants exactly those paths, and no network). The
  harness mounts no other volume (re-checked on the merged project).
- **LAN hosts** (`via: lan`, in-tree or trusted only): an endpoint may dial a
  host:port the user named, for a sidecar only (never `harness: true`), over
  core's routable `lan` network, which only those forwarders may join
  (re-checked on the merged project). It exists for `ssh` (below). `lan` is a
  direct, untunnelled route (no egress provider, VPN or its DNS), so core takes
  only a private IPv4 address (10/8, 172.16/12, 192.168/16) or a LAN name (one
  label, or under `.lan`, `.local`, `.home.arpa`, `.internal`; never
  `*.docker.internal`, `localhost`, loopback, link-local or a public address).
  Residual: a name is resolved by the forwarder's resolver when it connects, so
  a LAN resolver that answers it with a public address is followed (name an IP
  to rule that out); and a private range also covers the Docker host's own
  bridge gateways.
- **The `work` privilege** (in-tree or trusted only) binds the harness's whole
  `/work`, read-write, at `/work` in one named sidecar, and `glove policy` lists
  it. It exists for `github` (below).
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
- **Names rendered into compose.** An extension's harness env keys (from its
  manifest or a `contribute` hook) must match `^[A-Z][A-Z0-9_]*$` and may not
  overwrite another extension's; endpoint and forwarder aliases must be
  hostnames. The render refuses any harness env key that is not a plain name,
  and the merged-project re-check fails if the harness's `cap_add`, `cap_drop`
  or `security_opt` differ from its hardening plan.
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

### Browser (`playwright`)

A browser is an exfiltration channel and a code-execution surface by design:
it runs whatever the web serves, and Playwright's MCP always offers
`browser_run_code_unsafe` (arbitrary JavaScript in the MCP process; the MCP
has no server-side switch for it). The controls:

- **Sidecar modes (`headless`, `novnc`).** Chromium and the MCP run in a
  sidecar as the operator's uid with no capabilities, a read-only root,
  `no-new-privileges`, private IPC and pids/memory/cpu limits, on an internal
  network whose only members are two forwarders. It has no DNS and no default
  route (verified live), so a compromised renderer or MCP reaches neither the
  internet around the egress nor the harness or its llm endpoint. The browser's
  proxy is fixed server-side; its traffic leaves only through the egress slot,
  and with `observe` every destination is a flow (`client: playwright`) with
  `filter` rules and the SSRF guard applied at the gate. The MCP never gets a
  CDP port or `--allow-unrestricted-file-access`. Chromium's own sandbox is
  on (`chromium-userns`, above); on podman it must be `off`, and then the
  container is the only boundary.
- **The tool allowlist.** Pi registers only the `tools` setting (never
  `browser_run_code_unsafe` in host mode, even if listed). Vibe gets a
  `disabled_tools` regex hiding every other `playwright_*` tool (verified
  live). That is a client-side filter: it keeps the model from calling the
  tool, it is not a boundary around the MCP.
- **Watching (`novnc`).** VNC and websockify listen on the sidecar's own
  loopback; nothing is published. `glove playwright view` opens a loopback
  listener only while it runs, pipes each connection through `docker|podman
  exec … socat`, and refuses requests whose `Host` or `Origin` is not that
  listener (other pages in the operator's browser, DNS rebinding). The two
  VNC passwords are generated in the sidecar's tmpfs at every start (never an
  env var, compose secret or host file) and reach noVNC in the URL fragment.
  View-only and the clipboard are enforced by the VNC server
  (`AcceptPointerEvents`/`AcceptKeyEvents` off unless `allow_control`;
  `AcceptCutText`/`SendCutText` off unless `clipboard:`), verified live with a
  raw RFB client. VncAuth is weak (8 characters, DES); it guards a listener that
  exists only on loopback and only while `view` runs. Anything the operator
  types in control is visible to the agent.
- **Downloads and uploads.** What the browser saves stays in the sidecar's
  state dir, which the agent's shell cannot read, unless `downloads: work`.
  `browser_file_upload` is confined to an empty directory unless
  `uploads: work` (then `work/browser-uploads/`, read-only).
- **Host mode** runs the browser and the MCP as the operator, on the desktop,
  with the host's network: refused when the egress is anonymising (vpn, tor),
  and with Vibe unless `i_accept_host_rce: true`. Its CDP and MCP ports are
  per-session loopback ports; any local process can drive them while they run.
- **Background traffic.** Chromium still contacts Google services
  (`accounts.google.com`, `clients2.google.com`, `update.googleapis.com`,
  `www.google.com` in live runs) through the egress; `filter` can block them.

## Relays: gh and git from shell commands (`relay`, `github`)

Shell commands have no network, under every enforcer, and that stays true.
`github` gives the agent `gh` and git's network verbs by *relaying* them: shims
in the harness image hand each invocation to a sidecar that holds the token and
runs the real command. What that adds, and what bounds it:

- **The token never enters the harness.** It is resolved from the Keychain in
  memory at `glove up` and reaches relayd's environment for that `compose up`
  (as the harness's LLM key reaches the harness). relayd passes it only to gh
  and git. The live test finds it in neither the harness's environment, its
  pid 1, nor any file under `/run`, `/tmp` or the home, and a wrapped command's
  `env` has no `GH_TOKEN`.
- **No socket, no route.** The shims talk over the `github` channel (files and
  FIFOs; glove's seccomp below srt forbids Unix sockets, which stays). A relayed
  command is not a network grant: the agent gets exactly what the policy runs.
- **The policy is the boundary of the new trust edge.**
  - `gh` runs only subcommands in `github.allow`. `auth`, `extension`, `alias`,
    `config`, `codespace`, `secret`, `variable`, `ssh-key` and `gpg-key` are
    never relayed (no `gh auth token`).
  - `gh api` is GET only: no GraphQL, no full URLs.
  - Every host named must be github.com.
  - git relays only `push`, `fetch`, `clone` and `ls-remote`, to
    `https://github.com/<owner>/<repo>` remotes, judged by the URLs they resolve
    to (`insteadOf` included). Options that run programs or read outside `/work`
    are refused, and so are their abbreviations.
  - The policy judges every argument token on its own: a parser that misread a
    boolean flag as taking a value would let an unchecked file argument through.
- **The sidecar binds `/work` read-write (the `work` privilege).** The agent
  controls everything in it, including `.git/config`, so:
  - git runs with command-scope config that overrides the repo's: no hooks, no
    fsmonitor, no SSH command, askpass, editor or pager, and no credential
    helper but ours, which answers for `https://github.com` only. Only https,
    with no submodule recursion, signing or gc. The unit tests run a hostile
    repo config against real git; none of its helpers run.
  - Every file argument (`--body-file`, …) is opened by relayd, inside `/work`
    only, and handed over as `/dev/fd/N`. So a symlink to `/proc/<pid>/environ`
    (the token) or out of `/work` is refused, even if swapped in after the
    check. Relayed commands get no stdin.
  - `gh pr checkout` and `gh issue develop` stay out of the default set: they
    would check out the agent's files in the sidecar, where `.gitattributes`
    filters could run. `git pull` is a relayed fetch plus a *local* merge.
- **Egress fence.** Whatever got past the policy, gh and git reach the network
  only through relayd's in-process CONNECT proxy, which tunnels to GitHub's
  hosts and refuses the rest. With `observe` the sidecar's only way out is its
  own gate (`client: github`), so each GitHub host is a flow and
  `glove filter` can block it. The relayed command line itself is not network
  traffic; it is visible in the transcript's shell call.
- **Residual risk.** The token can do whatever its scopes allow within the
  allowlist (push to any branch it can reach, comment, merge, close). Use a
  fine-grained token limited to the session's repositories, and narrow `allow`.
  A prompt-injected agent can push the contents of `/work` to a repository the
  token can write. The fence keeps that on GitHub; it cannot tell your
  repositories apart.

### `ssh`: the same relay, to named LAN hosts

- **The key never enters the harness.** It reaches the sidecar's environment at
  `compose up` and is loaded into an `ssh-agent` there; no key file exists. The
  live test finds no key material in the harness.
- **Routes:** each named host gets one forwarder (`via: lan`), the sidecar's
  only route; the harness has none. The live test checks that a shell command
  cannot reach the host, and that the sidecar cannot reach it (or the internet)
  except through its forwarder. With `observe`, every connection is a flow
  (`client: ssh`, `scope: lan`) and `glove filter` can block it.
- **The policy:**
  - destinations are the named hosts as their configured users;
  - options are an allowlist; refused: `-L`/`-R`/`-D`/`-W`, `-J`, `-i`, `-F`,
    `-A`, `-t`, and every `-o` but a few timeouts;
  - `ProxyCommand=none`, `ClearAllForwardings`, batch mode and the agent socket
    are pinned first in argv, where ssh keeps them;
  - host keys are checked strictly against the session's `known_hosts`, never
    learned.
- **Residual risk:** whatever the key may do on those hosts, a prompt-injected
  agent may do (the remote command is the agent's). Use a key made for the
  session, restricted in `authorized_keys` (`restrict`, `from=`, or a forced
  command), as an unprivileged user.

## Claude Code: managed settings and the shell prefix

Claude Code is the one harness whose ring-2 glue can live outside its writable
config home. glove renders `/etc/claude-code/managed-settings.json` (and
`managed-mcp.json`) to `.glove/harness/` and binds it read-only; managed
settings override every other scope, and an unparseable managed file stops
Claude Code from starting (fail closed).

- **`CLAUDE_CODE_SHELL_PREFIX`** = `/opt/glove/bin/glove-cc-prefix` (baked,
  read-only rootfs). Claude Code runs `<prefix> "<shell string>"` for the Bash
  tool (main agent and subagents), operator `!` commands, hooks and MCP stdio
  servers. The prefix reads the tool wrapper from
  `/etc/glove/enforcer/tool-wrapper.argv` (read-only), drops `NONO_*`/`SRT_*`
  from its environment, and execs `<wrapper> bash --norc -c "<string>"`. A
  missing or empty wrapper, or anything but one argument, exits 126 without
  running the command. The prefix is set **only** in managed settings: Phase-0
  testing showed the agent's user `settings.json` `env` overrides one in the
  process environment, but not a managed one (`test_cc_nono.sh` re-checks it
  with the user setting blanked). With `enforcer: none` no prefix is set (there
  is no wrapper to run under).
- **MCP stdio servers** are rendered as `glove-cc-prefix --mcp <name>`; on
  exactly that string the prefix execs `/etc/claude-code/mcp-<name>.argv`
  (read-only) without the tool wrapper, so the server runs under the harness's
  sandbox, with network, as under Pi and Vibe. The agent cannot produce that
  string: a Bash or `!` string always starts with Claude Code's snapshot
  `source`, and hooks are managed-only. An unknown name exits 126.
- **Project settings** (`/work/.claude/settings.json`, `settings.local.json`)
  are bound read-only at ring 0, on every enforcer (`trusted_files` in
  `harness.yml`; an empty placeholder when missing, created on the host, and
  `.claude` pinned as a mount point so it can't be renamed aside). Claude Code
  applies their `env` to processes it starts itself, outside ring 1: tested,
  a planted `LD_PRELOAD` loaded into its `git`/`cat`/`id`, `BASH_ENV` and
  exported functions ran in its shells and in the bash prefix before it could
  scrub anything. Their command settings (`apiKeyHelper`, `statusLine`, …)
  are closed the same way. Only what the operator brought in is loaded
  (`test_cc_nono.sh` plants both files with the Write tool and a command).
- **Locks:** `allowManagedHooksOnly`, `allowManagedPermissionRulesOnly`,
  `allowManagedMcpServersOnly` + `allowedMcpServers` (only glove-rendered MCP
  servers). A project's hooks and `.mcp.json` servers do not run.
- **Config home:** `Read(//home/agent/.claude/**)` and
  `Edit(//home/agent/.claude/**)` are denied to the agent's file tools (`//`
  is an absolute path; Edit rules cover every writing tool). Tool commands
  cannot reach the home at all (ring 1). Contributed skills are therefore
  linked from `/opt/glove/cc/.claude/skills` (baked, `--add-dir`), not the
  home, so a skill's files are readable by the path Claude Code shows.
- **Tools:** the built-in tools are pre-approved, as Pi and Vibe auto-approve;
  every command still runs under ring 1. `WebFetch` is denied unless the
  session has `webfetch` (see "Claude Code's own WebFetch" below). An extension's
  MCP allowlist (`tools`) becomes allow rules, and every other tool the server
  is known to have (`all_tools`) a deny rule, so Claude Code never offers it
  and no prompt can approve it (Playwright's `browser_run_code_unsafe`,
  `browser_evaluate`). A tool unknown to `all_tools` would prompt.
- **Network:** with a subscription token Claude Code dials only
  `api.anthropic.com`, through the `llm` forwarder (plus WebFetch through the
  egress proxy, with `webfetch`); non-essential traffic, telemetry, error
  reporting, auto-update, claude.ai connectors and artifacts are off.
- **Claude Code's own WebFetch (with `webfetch`).** glove keeps the tool Claude
  Code expects rather than substituting one, and points it at the egress:
  managed `HTTPS_PROXY`/`HTTP_PROXY` = the `proxy` endpoint, `NO_PROXY` = every
  session forwarder name and alias plus loopback (managed, so the agent cannot
  change either). Compared with Pi's `web_fetch` and Vibe's `fetch_url`, this
  is broader in these ways:
  - **no client-side destination guard.** Private, loopback and metadata
    destinations are refused only at the egress: tinyproxy's filter under
    `direct`, the tunnel under `tor`/`vpn`, the corporate gate's allowlist, and
    with `observe` the gate's SSRF guard (both verified live with `direct`:
    "proxy refused the connection"). Redirects are not followed across hosts by
    Claude Code itself, so a redirect into the LAN needs a second WebFetch call,
    which the egress refuses the same way;
  - **the harness process holds the raw egress proxy**, as Pi does. Anything in
    Claude Code that honours `HTTPS_PROXY` and is not a session forwarder goes
    out through the egress, not just WebFetch. Tool commands still have no
    network;
  - **domain preflight**: Claude Code asks `api.anthropic.com` whether it may
    fetch each domain, so Anthropic learns the domains fetched (over the
    inference link with `provider: anthropic`, otherwise through the egress).
    `skipWebFetchPreflight` is left unset: the blocklist is Claude Code's
    default safety check;
  - **page content goes to the inference provider**, summarised by a second
    model call (as any tool result does), and Claude Code's request headers
    identify it, so behind `tor`/`vpn` its fetches are distinguishable from a
    browser's.
- **Key:** `CLAUDE_CODE_OAUTH_TOKEN` (or `ANTHROPIC_API_KEY`) in the harness
  env only; nono's `*TOKEN*`/`*KEY*` globs and srt's exact-name list strip it
  from every tool command. glove never writes key material: with an API key,
  Claude Code itself asks once whether to use it and records the answer.
- **Gaps:** a glove MCP stdio server has the harness's rights (config home,
  network to the session's forwarders), as under Pi and Vibe. Project settings
  are protected in the working dir Claude Code starts in (its project root);
  whether it also loads a `.claude/settings*.json` from a subdirectory is
  **untested**. The project's
  `.claude/skills`, `agents` and `commands` stay writable (prompts; whatever
  they run goes through ring 1). A `statusLine` command is not overridden (the
  agent cannot write the settings that would add one).
- **No HTTP hooks to the session's forwarders.** Claude Code refuses an `http`
  hook whose host resolves to a private address (only loopback is allowed), and
  every glove forwarder is on a private network; `command` hooks run under the
  tool wrapper, without network. A live Layman gate for a gloved Claude Code
  would need a loopback relay inside the harness container: not built.

## Tool commands and the terminal (TIOCSTI)

nono's base policy grants `/dev/tty`, and Docker Desktop's kernel has
`dev.tty.legacy_tiocsti = 1`: a shell command could open the harness's terminal
and inject keystrokes into the TUI (type into Pi's prompt, answer a Vibe
approval). Every enforcer's tool wrapper therefore starts with
`glove-pty notty`, which gives up the controlling terminal (`TIOCNOTTY`) and
keeps the process group, so an aborted command is still killed with its group.
As a session leader it runs the command in a new session instead, tied to the
parent (`PR_SET_PDEATHSIG`). `glove-pty` is a static helper baked into every
harness image (`glove/enforcers/pty/glove-pty.c`); the entrypoint refuses to
start if the wrapper names it and it is missing.

## `nono+srt` and `srt`: what srt adds, and what glove changes in it

With `enforcer: nono+srt` the harness runs as
`glove-pty relay -- glove-srt srt-harness.json -- glove-pty ctty -- <harness>`
and every shell command as `glove-pty notty -- nono wrap --profile tool.json -- …`
inside it (srt must be outermost: bubblewrap needs mount/pivot_root, which
Landlock cannot grant).

| Property | `nono` | `nono+srt` |
|---|---|---|
| Harness process network | ring 0: the session's forwarders on an internal network | same (srt adds no network namespace, below) |
| Tool command network | none (Landlock) | none (Landlock) |
| `/work/.git/hooks`, `.git/config` | ring-0 ro binds where they exist (below) | also denied by srt |
| `.vscode`, `.idea`, `.envrc`, `.mcp.json`, `.claude/*`, shell rc files in `/work` | only with `protect_ide_files` | denied where they exist at launch |
| `.env` / `.env.*` in `/work` | readable | hidden from harness and tools (present at launch) |
| Namespaces / mounts / AF_UNIX / io_uring | default seccomp: no userns | relaxed profile for srt; glove's filter denies all of these to everything below srt |
| PID namespace around the harness and its commands | no | yes (srt's `apply-seccomp`) |
| TIOCSTI into the harness TUI | no (`glove-pty notty`) | no (same) |
| Kernel mechanisms between a tool and the container | Landlock | bubblewrap + seccomp + Landlock |
| Podman | yes | refused (compose can't apply the profile) |

- **glove's `apply-seccomp`.** srt's stock filter blocks AF_UNIX sockets and
  io_uring. Under the relaxed profile a process inside srt could still call
  `unshare(CLONE_NEWUSER)` or `clone(CLONE_NEWUSER)` (and `open_tree`), and a
  user namespace hands back every capability, mount included: verified with
  stock srt (`unshare -Urm` mounted a tmpfs). The `-srt` image compiles srt's
  own `apply-seccomp.c` (pinned commit) with glove's filter
  (`glove/enforcers/srt_image/glove-tighten.c`), which also denies any
  `CLONE_NEW*` on `unshare`/`clone`, `clone3` (`ENOSYS`, libc falls back to
  `clone`), `setns`, `mount`, `umount2`, `pivot_root`, `chroot` and the new mount
  API. srt runs it via `seccomp.applyPath`; it applies to `enforcer: srt` too.
  srt would silently fall back to its stock binary if that path were missing,
  so the harness entrypoint refuses to start without it, and the image tag is
  content-addressed (`-srt-<hash>`).
- **No network namespace for the harness.** Ring 0 already puts the harness on
  an internal network whose only hosts are the session's forwarders, with no
  external DNS; srt's allowlist would name the same forwarders, and confining
  the harness in srt's netns broke every client that speaks its own proxy
  protocol (web_fetch) and raw-TCP endpoints. srt's CLI always confines the
  network, so `glove-srt` (a small launcher on srt's library, validating the
  settings with srt's own schema) runs srt without it.
- **Only paths present at launch.** For a missing path bwrap creates an empty
  placeholder where the bind lands, which in `/work` is your project on the
  host (seen live: ~15 empty files while the session ran). `glove-srt` starts
  srt from the container's `/tmp`, so srt's built-in list lands there, and
  glove names only the `/work` paths that exist. A protected file created
  during the session (e.g. a new `.vscode/`) is writable, as with `nono`.
- **The terminal.** srt runs everything under `bwrap --new-session` (the
  TIOCSTI defence), so a TUI loses its controlling terminal: no SIGWINCH on
  resize, and a cooked-mode Ctrl-C signals srt. `glove-pty relay` (outside the
  sandbox) gives srt a fresh pty and forwards resizes; `glove-pty ctty` (inside)
  makes it the harness's terminal. The sandbox never holds an fd to your real
  terminal.
- **The harness env.** The harness keeps its env (it needs the LLM key); nono's
  `deny_vars` strip secret-shaped names from every command, and Landlock hides
  `/proc` from them. srt alone would not: an srt-only command can read the
  harness's `/proc/<pid>/environ` (same sandbox, same uid).

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
(`extensions/gate/`). It changes what glove *records*,
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
  rules cover SearXNG's requests too. The `fetcher` (`webfetch` for Vibe) is held the same way behind `webfetch-egress` (`client:
  webfetch`); without observe it dials the proxy on the internal egress network.
- **MCP sidecars.** `searxng-mcp` and `fetcher` serve MCP over HTTP to their
  harness forwarder only: they are not on the harness network, get the full
  sidecar hardening, and refuse a request whose Host is not their forwarder's
  name (DNS-rebinding protection). Their Python dependencies install from a
  hash-pinned `requirements.txt` onto a digest-pinned base image.
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
- **Keep the default** (`nono+srt` on Docker, `nono` on Podman) over `srt`: srt alone
  wraps tool commands only, leaving the harness process on ring 0 alone. Both
  srt enforcers relax the container's seccomp profile to allow unprivileged
  user namespaces (a historical source of kernel LPE bugs) because bubblewrap
  needs them; glove's `apply-seccomp` takes that back from everything srt
  wraps (below), so only srt's own processes hold it.
- **Prefer the browser sidecar modes** (`headless`, `novnc`) over `mode: host`:
  a compromised browser or MCP stays in a cap-less container on an internal
  network instead of running as you on your desktop. Host mode with Vibe is
  refused unless `i_accept_host_rce: true`: Vibe hides `browser_run_code_unsafe`
  but the MCP still serves it, on your Mac. The MCP is pinned
  (`playwright-core@1.63.0`), never `@latest`.

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
