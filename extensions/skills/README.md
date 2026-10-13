# skills

Loads Claude Code plugins, and plain directories of skills, into every harness
(Pi, Claude Code, Vibe). Each plugin is checked at plan time and baked into the
harness image; nothing is bind-mounted, and the agent sees only the baked copy.

```yaml
extensions:
  skills:
    # python: "3.12"                                  # the Python PEP 723 scripts run on
    plugins:
      connectors:                                     # your name for it: [a-z0-9-]
        path: skills/connectors-repo/plugins/connectors
        skills: [confluence, slack]                   # default: every skill it has
        env: { WIKI_SPACE: team }                     # plain values for the harness env
      notes:
        path: skills/notes-repo/notes
        mcp: true                                     # its .mcp.json servers
        tools: { notes: [search, fetch] }             # each server's allowed tools (required)
```

Clone plugins into the session's `skills/` directory (`git clone … skills/<repo>`).
Like `local/` it is never mounted into the harness and is refused as a mount or
a toolchain project. `path` may also name any other host directory, resolved
like a mount source, but never one an agent can write (`/work`, a read-write
mount, another session's `work/`: it could change what the next session bakes
and runs) or glove's state.

| Key | Meaning |
|---|---|
| `path` | a Claude Code plugin (`.claude-plugin/plugin.json`, skills under `skills/<name>/SKILL.md`), or a directory of `<name>/SKILL.md` dirs |
| `skills` | the skills to load; the rest are never staged, so never in the image |
| `env` | names → plain values, set in the harness (shell commands see them). A secret-shaped name (`*TOKEN*`, `*_PAT`, `*KEY*`, …) or a `keychain:`/`env:` reference is refused: secrets never enter the harness |
| `mcp` | `true`: each `.mcp.json` server becomes an MCP server for Claude Code and Vibe (Pi has no MCP; its skills still work through the shell) |
| `tools` | `{<server>: [tool, …]}`, required for every server when `mcp` is on: the tool inventory fails closed |
| `relay` | scripts that run in the plugin's relay sidecar, with their secrets and network (below) |

## What the image gets

- The plugin at `/opt/glove/plugins/<name>/`, read-only. The image tag hashes the
  tree, so an edit rebuilds on the next `glove up`: only this layer, which core
  renders after every other extension layer and the toolchains. `.git/`,
  `node_modules/`, `.venv/`, `__pycache__/` and `.DS_Store` are left out.
- In the Markdown of the baked copy that names them, `${CLAUDE_PLUGIN_ROOT}` becomes
  `/opt/glove/plugins/<name>` and `${CLAUDE_PLUGIN_DATA}` becomes
  `/work/.glove-plugin-data/<name>` (glove creates it). The host checkout is
  never changed.
- `bin/` is linked into `/usr/local/bin`. A name the image already has fails
  the build, so a plugin never shadows a system command.
- The skills, through glove's neutral `skills` contribution: Pi's
  `settings.json`, Claude Code's `--add-dir` (links under
  `/opt/glove/cc/.claude/skills`; skills, not "a plugin", so Claude Code's plugin
  refusal stays), Vibe's `skill_paths` (links under `/opt/glove/vibe/skills`).
  Plugin hooks, commands, agents and output styles are not loaded.

## Python scripts (PEP 723)

The scripts are usually `#!/usr/bin/env -S uv run --script` with inline
dependencies. A shell command has no network, so everything is baked:

- uv (pinned, checksum-verified) and a Python (`python:`, installed by uv);
- a wheelhouse of every script's dependencies (its inline list resolved by
  `uv pip compile --generate-hashes`; wheels only: a dependency with no wheel
  for the image fails the build). This layer depends only on the Python and
  the dependency lists, so editing a plugin never rebuilds it;
- one read-only environment per set of dependencies, installed from that
  wheelhouse. Each `uv run --script` shebang is pointed at its script's
  interpreter, and so is an `.mcp.json` `uv run --script <script>` command. The
  harness's `/tmp` is mounted noexec, so a compiled extension (a `.so`) could
  never load from a uv cache there.

An explicit `uv run --script <file>` still works for dependencies that are pure
Python: the harness env points uv at the wheelhouse (`UV_OFFLINE`,
`UV_FIND_LINKS`, `UV_PYTHON`, `UV_CACHE_DIR` under `/tmp`).

## MCP servers

A stdio server runs as `glove-confine <command> …`: under the session's tool
wrapper, the same per-command sandbox a shell command gets (`/work`, `/tmp`, no
network). It never gets the harness's own sandbox, whose network reaches the
session's forwarders (the LLM, and the egress proxy when `webfetch` is on).
Without an enforcer there is no wrapper, and the server does not start. An
`http` server passes through as `transport: http`. Any `${VAR}` other than the
two plugin variables is refused.

## Relayed scripts: `relay`

A script that needs a service and its credential can't run in the sandbox
(no network, no secrets). `relay` runs it in a sidecar of the plugin's own,
`skill-<name>` (relay's `relayd`, under [relay_policy.py](relay_policy.py)),
which holds the secrets and the only route to the service:

```yaml
      connectors:
        path: skills/connectors-repo/plugins/connectors
        relay:
          timeout: 300                                  # seconds one call may run (default 300)
          commands:
            scripts/wiki_query.py:                      # its path in the plugin
              hosts: [wiki.corp.example]                # exact, or *.<domain>; port 443 only
              allow: [search, fetch, children]          # the first non-flag argument; `*`: any
              out_flags: [-o, --output]                 # its value: a path under /work (written there)
              in_flags: [-f]                            # its value: a file under /work (read there)
              env:
                WIKI_SPACE: team                        # a plain value
                WIKI_PAT: keychain:corp-wiki-pat        # a secret: keychain:<service> | env:<VAR>
                # WIKI_PAT: {secret: keychain:corp-wiki-pat, refresh: local/mint-wiki.sh}
            scripts/chat.py:
              hosts: [chat.example.com, "*.chat.example.com"]
              allow: [read, history, search]
              files:                                    # in the script's own home, mode 0600
                ~/.config/chat/auth.json:
                  template: local/chat-auth.json.j2     # Jinja: {{ secrets.token }}
                  secrets: { token: keychain:corp-chat-token }
          check:                                        # through the relay, as the agent's calls go
            - "scripts/wiki_query.py search glove -n 1"
            - { run: "scripts/chat.py read general -n 1", required: true }
```

- **The harness side.** In the baked copy each relayed script is a shim,
  `exec glove-relay skill-<name> <script> "$@"`, at the path the skill names,
  so the skill is unchanged; the agent calls it by path (not through `uv
  run`). A relay sidecar is added only for a plugin with `relay:`, and with it
  the `relay` library and the need for an egress provider.
- **The sidecar.** It binds the plugin's staged copy read-only at the same
  path (`.glove/ext/skills/relay/<name>/`, written at `glove plan`/`up`). Each
  command runs with an environment built from nothing: its plain `env`, its
  secrets, its own `HOME` (and `TMPDIR`) on the sidecar's tmpfs with its
  `files`, and a proxy that is its own egress fence: only its `hosts`, on port
  443, through the session's egress provider (with `observe`, a gate labels its
  flows `client: skill-<name>`). A Python script runs on the relay's Python
  (3.12, standard library only: a relayed script that lists dependencies is
  refused), anything else by its own shebang. It trusts `corporate_ca` when the
  session sets one. It binds `/work` read-write (the `work` privilege) only
  when a command has `out_flags` or `in_flags`.
- **What runs.** `allow` is matched against the first argument that is not a
  flag; anything else is refused (`-h`/`--help` alone always works), so a
  script's minting, posting or saving subcommands run only when listed.
  `out_flags`/`in_flags` values (`-o x`, `--output=x`, `-ox`) are checked under
  `/work` (an input is opened by the relay, so what is checked is what the
  script reads), and so is any other argument that names a path (absolute, `~`,
  or with `..`): a positional file argument can't read the sidecar's own files.
  Relayed commands get no stdin: input goes in a file under `/work`.
- **Secrets** are resolved at `glove up`, in memory, and handed to the sidecar's
  environment at `compose up`; a `files:` template (a file in the session
  directory, never in `work/`) is rendered then too, with `{{ secrets.<k> }}`,
  and written only in the sidecar's tmpfs. Nothing is written on the host, and
  neither a secret nor its reference appears in the compose file. A
  secret-shaped `env` name with a plain value is refused (no literal secret in
  the session file).
- **Checks** run at `glove up` after the sidecar is up, as `exec-ok` verify
  checks: a failure is a warning (the session starts) unless `required: true`.
  Each is stopped after 60 seconds, so a hung service can't hold up the launch.

### When a credential expires

```sh
glove skills status [<plugin>]          # each relay's checks: ok, or the exit code (output withheld)
glove skills refresh <plugin> [--secret <service>]   # new values, then reload
glove skills reload <plugin>            # resolve its secrets again, recreate only its sidecar
```

`refresh` runs each Keychain secret's `refresh:` hook on this machine (in the
session directory, with the Keychain service name as its argument; it prints
the new value on stdout) and stores the value with `glove keychain set`; a
secret without a hook is prompted for. One secret has one hook wherever it is
used. Then it reloads the relay: the harness, its channel and the agent's
conversation keep running. `reload` re-resolves only the secrets: a change to
the relay's commands, hosts or `allow` takes the next `glove up`. glove ships
no hooks; a hook can run the plugin's own minting script here, where the
browser and the SSO session live. The agent's brief tells it to ask for
`glove skills refresh <plugin>` on a 401 or `invalid_auth`, never to mint or
store a credential itself.

A value that only a signed-in browser holds (a chat app's session cookie or a
token in its localStorage) can come from `glove playwright login` instead: name
it under the playwright extension's `login.capture`, with the same Keychain
service this relay's `env` references, sign in, then `glove skills reload
<plugin>` ([../playwright/README.md](../playwright/README.md#signing-in-on-the-host-glove-playwright-login-and-storage_state)).

## Refused at plan time

- a symlink that leaves the plugin (absolute, or resolving outside it);
- a file that looks like a credential, because image layers are not secret
  storage: `.env` and `.env.*` (but not `.env.example`/`.sample`/`.template`),
  `.netrc`, `.npmrc`, `.pypirc`, `.git-credentials`, `*.p12`, `*.pfx`, `*.jks`,
  `*.keystore`, `id_rsa*`/`id_ecdsa*`/`id_ed25519*`, and any file holding a PEM
  private key;
- a plugin an agent can write (`/work`, a read-write mount, another
  registered session's `work/`) or in the session's `.glove/`;
- in `relay`: a script that is not in what is baked (an unselected skill's) or
  lists dependencies, a command without `allow`, a bad host or flag, an `env`
  name the relay sets itself (`PATH`, `HOME`, the proxy, `RELAY_*`, …), a
  template or hook outside the session directory or in `work/`, a refresh hook
  for an `env:` secret (it stores into the Keychain), two hooks for one secret,
  and a check that names a command the relay does not run;
- an unknown key.

A script that needs a service and is not relayed can't reach it from the
sandbox; the brief tells the agent to say so rather than work around it.
