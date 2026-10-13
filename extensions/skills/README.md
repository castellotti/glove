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

## Refused at plan time

- a symlink that leaves the plugin (absolute, or resolving outside it);
- a file that looks like a credential, because image layers are not secret
  storage: `.env` and `.env.*` (but not `.env.example`/`.sample`/`.template`),
  `.netrc`, `.npmrc`, `.pypirc`, `.git-credentials`, `*.p12`, `*.pfx`, `*.jks`,
  `*.keystore`, `id_rsa*`/`id_ecdsa*`/`id_ed25519*`, and any file holding a PEM
  private key;
- a plugin an agent can write (`/work`, a read-write mount, another
  registered session's `work/`) or in the session's `.glove/`;
- an unknown key.

Scripts that need a service (an API with a token) can't reach it from the
sandbox; the brief tells the agent to say so rather than work around it.
