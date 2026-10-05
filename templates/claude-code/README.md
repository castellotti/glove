# claude-code template

Claude Code on your Anthropic account, for software work: `gh` and `git push`
relayed to a sidecar that holds the GitHub token, Claude Code's own WebFetch and
a sidecar Chromium (`browser_*` tools) through a direct egress, and Python (uv) and
Node (pnpm, Playwright with a baked Chromium) in the image.

```sh
glove new claude-code ~/work/project-1 && cd ~/work/project-1
$EDITOR glove-session.yml        # every <set-me>: the two Keychain services
claude setup-token               # on the host, once: a subscription token
glove keychain set <service>     # for each keychain:<service> you referenced
glove check && glove up
```

- **The model.** `auth: oauth` takes a token from `claude setup-token` (a Claude
  subscription). For an API key, drop `auth`. To switch accounts, point
  `api_key` at another Keychain service and relaunch.
- **GitHub.** Use a fine-grained token scoped to the repositories this session
  works on. `extensions/github/README.md` lists what is relayed and refused.
- **Shell commands are offline.** The toolchains are baked at build time, so add
  what a project needs there (or `project:` for its lockfile). Local Playwright
  works from a shell command because of `enforcer_options: {nono: {browsers:
  true}}`; README "Toolchains" says what that opens.
- **ssh** to LAN hosts is commented out; `extensions/ssh/README.md` explains the
  key and `known_hosts`.
