# github

Lets the agent run `gh`, and git's network commands (`git push`, `fetch`,
`pull`, `clone`, `ls-remote`), from its shell. The commands are relayed (see
[`relay`](../relay/README.md)) to a sidecar that holds the GitHub token. The
token never enters the harness: not its environment, not a file, not a command's
output. The sandbox still gets no route out. Works with every harness (Pi, Vibe,
Claude Code) and every enforcer.

```yaml
extensions:
  direct: {}                         # any egress provider
  github:
    token: keychain:<service>        # a GitHub token; a reference, never the value
    # allow: ["pr list", "pr view", "api"]   # gh subcommands relayed (default below)
    # timeout: 600                   # seconds one relayed command may run
```

Use a **fine-grained token** limited to the repositories the session works on.
The sidecar can do whatever the token allows, within the policy below.

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
- **github.com only.** `--hostname`, `-R HOST/OWNER/REPO` and repository URLs
  must all name github.com.
- **File and directory arguments stay inside `/work`.** This covers
  `--body-file`/`-F`, `-D`/`--dir` and `gh repo clone`'s directory. relayd
  opens each file itself and passes `/dev/fd/N`, so a symlink to `/proc/*/environ`
  or out of `/work` is refused.
- **Refused outright:** `--recover`, `--template` on `create`, `--`, and combined
  or attached short options (`-dF x`, `-Fx`).

**git**

- **Only `push`, `fetch`, `clone` and `ls-remote` are relayed**, and only to
  `https://github.com/<owner>/<repo>` remotes. For a remote name, the check uses
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
  - no other credential helpers: ours answers for `https://github.com` only;
  - https as the only protocol;
  - no submodule recursion, no signing, no gc or maintenance;
  - `safe.bareRepository=explicit`.

**Network**

Every child's traffic goes through relayd's fence, which tunnels only to
github.com, api.github.com, uploads.github.com, codeload.github.com and
`*.githubusercontent.com`. From there it goes through the egress proxy.

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
- **The token** reaches relayd's environment at `compose up`, from `launch_env`
  in `hooks.py`, resolved in memory. It is not a compose secret, because Docker
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
