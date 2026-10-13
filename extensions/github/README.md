# github

Lets the agent run `gh`, and git's network commands (`git push`, `fetch`,
`pull`, `clone`, `ls-remote`), from its shell, against github.com, GitHub
Enterprise hosts, or both. The commands are relayed (see
[`relay`](../relay/README.md)) to a sidecar that holds the tokens. A token
never enters the harness: not its environment, not a file, not a command's
output. The sandbox still gets no route out. Works with every harness (Pi, Vibe,
Claude Code) and every enforcer.

```yaml
extensions:
  direct: {}                         # any egress provider
  github:
    token: keychain:<service>        # a github.com token; a reference, never the value
    # hosts:                         # GitHub Enterprise hosts, a token each
    #   - {host: github.example.internal, token: keychain:<service>}
    # allow: ["pr list", "pr view", "api"]   # gh subcommands relayed (default below)
    # git: [fetch, clone, ls-remote] # git verbs relayed (default: these and push)
    # timeout: 600                   # seconds one relayed command may run
```

`token`, `hosts` or both: the relay serves exactly those hosts. Use
**fine-grained tokens** limited to the repositories the session works on. The
sidecar can do whatever a token allows, within the policy below.

### GitHub Enterprise hosts

- **A token per host.** gh takes github.com's from `GH_TOKEN`; an Enterprise
  host's from a `hosts.yml` relayd writes into gh's config dir on the sidecar's
  tmpfs (0600; `GH_ENTERPRISE_TOKEN` holds one token for every host, so it is
  not used). git has one credential helper per host, each answering with that
  host's token only.
- **The default host.** With Enterprise hosts only (no `token`), the first is
  gh's default (`GH_HOST`), so `gh api user` and `-R OWNER/REPO` reach it.
  Another is named by `--hostname`, `-R HOST/OWNER/REPO` or the repository's
  remote. The harness's own `GH_HOST` never reaches the sidecar.
- **Network.** The fence admits each host and its subdomains (`api.`,
  `uploads.`, … under subdomain isolation). Behind the `corporate` egress each
  must be in `allow_domains` too, subdomains included (`'*.<host>'`; for
  github.com also `'*.githubusercontent.com'`), and `glove check` warns when
  one isn't. The
  gate also checks the address a name resolves to: a host on a private address
  passes only when `allow_cidrs` (or `from_interface`'s routes) cover it.
- **A private CA.** The sidecar trusts the session's `corporate_ca`.
- **GitHub Enterprise Server only.** A GitHub Enterprise Cloud tenant
  (`*.ghe.com`) is refused: gh treats it like github.com and would send it
  `GH_TOKEN`, github.com's token, rather than its own.
- **Read-only git.** `git: [fetch, clone, ls-remote]` refuses `git push`
  (`git pull` is a fetch). gh writes (`pr create`, `issue comment`, …) are
  `allow`'s to leave out.

## What the agent sees

- **Shims in the harness image.** `/usr/local/bin/gh` relays every call. The
  `/usr/local/bin/git` shim relays `push`, `fetch`, `clone` and `ls-remote`, and
  runs every other git command locally (`/usr/bin/git`, with no network).
  `git pull` is a relayed `git fetch` followed by a local `git merge FETCH_HEAD`
  (or `git rebase` with `--rebase`).
- **A brief** (`brief.md`) states the rules.
- **`safe.directory: '*'`** in the harness's git config (`harness.git_config`,
  which glove adds to `GIT_CONFIG_PARAMETERS`; also `safe.directory=*` in the
  sidecar). Docker Desktop's file sharing shows a
  directory that `git init` or `git clone` just made as root's (or 65534 under
  srt), so without it git refuses every fresh checkout as "dubious ownership".
  Everything in `/work` belongs to the agent, so there is no other user's
  repository to guard against.

## The policy (`relay_policy.py`)

**gh**

- Only subcommands in `allow` are relayed. The default set:
  - `pr`: list, view, create, status, diff, checks, comment, review, edit, close,
    reopen, merge, ready
  - `issue`: list, view, create, comment, edit, close, reopen, status
  - `repo view`, `repo clone`
  - `run`: list, view, watch, rerun, cancel, download
  - `workflow`: list, view
  - `release`: list, view
  - `api`, `browse`, `status`, `search`
- **Never relayed**, whatever `allow` says: `auth` (so `gh auth token` is
  refused), `extension`, `alias`, `config`, `codespace`, `secret`, `variable`,
  `ssh-key`, `gpg-key`.
- **`gh pr checkout` and `gh issue develop` are left out** because they would
  check out files in the sidecar.
- **`gh api` is GET only.**
  - Refused: `-X` with any other method, `-F`, `--input`, GraphQL, a full URL,
    and method-override headers.
  - `-f` fields need `-X GET`; without it, gh would send a POST.
- **Served hosts only.** `--hostname`, `-R HOST/OWNER/REPO` and repository URLs
  must all name github.com (with `token`) or a listed Enterprise host.
- **File and directory arguments stay inside `/work`.** This covers
  `--body-file`/`-F`, `-D`/`--dir` and `gh repo clone`'s directory. relayd
  opens each file itself and passes `/dev/fd/N`, so a symlink to `/proc/*/environ`
  or out of `/work` is refused.
- **Refused outright:** `--recover`, `--template` on `create`, `--`, and combined
  or attached short options (`-dF x`, `-Fx`).

**git**

- **Only the verbs in `git` are relayed** (of `push`, `fetch`, `clone` and
  `ls-remote`; all four by default), and only to
  `https://<served host>/<owner>/<repo>` remotes. For a remote name, the check uses
  the URLs that remote actually resolves to, including any `url.*.insteadOf`
  rewrite. For push it uses the push URL; with no remote given, the branch's
  default.
- **Refused options:** those that run programs or reach outside `/work`
  (`--upload-pack`, `--receive-pack`, `--exec`, `--template`, `-c`/`--config`,
  `--reference`, `--separate-git-dir`, `--recurse-submodules`, `--signed`, …).
  Their abbreviations and combined short options are refused too.
- **The repository's own config is defanged.** git reads command-scope config
  (`GIT_CONFIG_COUNT`) after the repo's, so these settings override whatever the
  repo sets:
  - no hooks (`core.hooksPath=/dev/null`) and no fsmonitor;
  - no SSH command, askpass, editors or pager;
  - no other credential helpers: ours answer one served host each, with its token;
  - https as the only protocol;
  - no submodule recursion, no signing, no gc or maintenance;
  - `safe.bareRepository=explicit`.

**Network**

Every child's traffic goes through relayd's fence, which tunnels only to the
served hosts: for github.com, github.com, api.github.com, uploads.github.com,
codeload.github.com and `*.githubusercontent.com`; for an Enterprise host, the
host and its subdomains. From there it goes through the egress proxy.

## The sidecar (`gh`)

- **Image:** relay's image, running relayd with `relay_policy.py` (bound
  read-only from this extension).
- **Hardening:** core's full sidecar set (session uid, `cap_drop: ALL`,
  read-only rootfs, seccomp, limits). It joins no harness network.
- **Network:** with `observe`, it leaves the egress network. Its only way out is
  then its own gate (the `github-egress` endpoint, `client: github`,
  `tool: gh`), so every GitHub host it contacts is in the flow record and
  `glove filter` can block it.
- **The `work` privilege:** it binds the harness's whole `/work`, read-write, at
  `/work`. `gh pr create`, `git push` and `git clone` work on the agent's
  checkout. This is a new trust edge, listed in `glove policy` and in
  [docs/SECURITY.md](../../docs/SECURITY.md#relays-gh-and-git-from-shell-commands-relay-github).
- **The tokens** reach relayd's environment at `compose up`
  (`RELAY_GITHUB_TOKEN`, and `RELAY_GITHUB_TOKEN_<n>` for the n-th of `hosts`),
  from `launch_env` in `hooks.py`, resolved in memory. `glove check` checks that
  each reference exists. It is not a compose secret, because Docker
  can't put an environment-sourced secret file into a read-only container. relayd
  passes it only to gh and git.

## Tested

- `tests/integration/test_github.sh` runs live against the model stub, with real
  agent tool calls under nono and nono+srt.
  - **Harness side:** the channel is there, and the token is in neither the
    harness's environment nor its files.
  - **Refusals:** the policy's refusals hold.
  - **Public GitHub:** `gh --version`, `git ls-remote`, `git clone` into `/work`
    and `git pull` work through the sidecar. A shell command still has no
    network.
  - **With `OBSERVE=1`:** flows are labelled `client: github`.
- `GH_KEYCHAIN=<service>` adds read-only checks with a real token: `gh api user`,
  `gh pr list` and `gh api` against a public repository. These passed live,
  30/30 with `OBSERVE=1` under nono+srt.
- Adding `GH_SCRATCH_REPO=<owner/repo>` also pushes a throwaway branch and
  deletes it again. This passed live, 35/35 under nono+srt. The repository
  needs at least one branch; otherwise the push is skipped.
- `tests/integration/test_github_ghes.sh` serves two stand-in Enterprise hosts
  (`stubs/ghes_stub.py`, in the relay image: gh's REST user endpoint and git
  smart HTTP, a token per host, HTTPS from a throwaway CA given as
  `corporate_ca`) behind the `corporate` egress, with `git: [fetch, clone,
  ls-remote]`. gh reaches the default host and the other by `--hostname`, each
  with its own token; `git ls-remote`, `clone` and `pull` work; push, github.com
  and a github.com remote are refused; no token is in a shell command's
  environment or a session file. 16/16 with Pi on Docker (nono+srt) and Podman
  (nono), and with Claude Code on Docker. A real GHES is **untested**.
