# toolchains

Shell commands have no network, so `npm install`/`pip install` can't run in the
box. `toolchains` declares pinned runtimes and their packages, and glove installs
them **at image build time** (the build has network) into the session's derived
image, as this extension's image layers:

```yaml
extensions:
  toolchains:
    blocks:                         # a list; order is install and PATH order; one block per lang
      - lang: node
        version: "22.23.3"          # required, exact X.Y.Z (official tarball, SHASUMS256-checked)
        manager: npm                # npm (default) | pnpm[@ver] | yarn[@1.x] (classic only; 2+ refused)
        project: projects/web       # optional; relative to the session dir; its manifest + lockfile are baked
        install: ci                 # npm: ci (default) | install; pnpm/yarn: frozen (default) | install
        config_files: [.npmrc]      # optional project config baked beside the manifest (public, no credentials)
        install_flags: ["--legacy-peer-deps"]  # optional flags appended to the project install
        packages: ["tsx@4.19.2"]    # optional global tools
        browsers: [chromium]        # optional Playwright engines (chromium | firefox | webkit)
      - lang: python
        version: "3.12"             # required, X.Y or X.Y.Z (uv-managed CPython; uv is pinned by glove)
        manager: uv                 # uv (default) | pip
        project: projects/tool
        install: sync               # uv: sync (default, `uv sync --locked --no-install-project`) | requirements; pip: requirements
        packages: ["rich==15.0.0"]
```

This used to be the session key `toolchains:` (the same
list); a session file that still has it is refused with this pointer.

- **Everything lands under `/opt/glove/toolchains/`.** That path is on the
  read-only rootfs and never under a runtime mount (anything baked under `/work`
  or the harness home would be hidden by the bind). Every enforcer already lets
  the harness and its commands read `/opt/glove`, so no policy changes. No mount
  can land there: glove's mount points are only `/work`, `/mnt/…` and the
  harness home.
- **The runtime finds it through env.** The image prepends the bins to `PATH`
  (Node's `bin` plus the project's `node_modules/.bin`, then the Python venv's
  `bin`). The harness env adds `PLAYWRIGHT_BROWSERS_PATH` and `VIRTUAL_ENV`.
  These are set only if absent, so an explicit `env:` entry wins. There is no
  `NODE_PATH`, because nono strips it (and `NODE_OPTIONS`/`PYTHONPATH`) from every
  wrapped command. Instead a node project's `node_modules` is linked into the
  pinned node's own global folder (`<runtime>/lib/node`), so `require` finds the
  deps from any directory under every enforcer. With no project, the global
  `packages` take that folder instead (so `require('playwright')` works from a
  shell command anywhere). The harness always runs on the
  image's own interpreter, toolchain or not: Pi starts as
  `/usr/local/bin/node /usr/local/bin/pi`, and Vibe's hook runs as
  `/usr/local/bin/python3 /opt/glove/vibe-hook`. Claude Code is a native
  binary started as `/usr/local/bin/claude`.
- **Lockfile-strict by default.** `npm ci`, `pnpm install --frozen-lockfile`,
  `yarn install --frozen-lockfile` and `uv sync --locked --no-install-project`
  are the defaults.
  `glove check` fails early on an unknown `lang`/`manager`/`install`, a missing
  `version`, or a missing lockfile. It also refuses a `project` that isn't a
  directory or that exposes a private path (`.glove/`, `local/`, the session
  file, `~/.glove`), and core refuses a baked file an agent can write (under a
  read-write mount, `/work` included), as for every extension's `copy_host`.
- **Only the manifest and lockfile are baked** (`package.json` plus its lockfile,
  `pyproject.toml` plus `uv.lock`, or `requirements.txt`), never the project's
  tree, source, `.npmrc` or `.git`. A symlinked manifest is refused, so nothing
  outside the project is ever copied in. The project's own package is not
  installed (`--no-install-project`). The agent works on its copy under `/work`.
  So an install that needs more than those files fails at build time: npm/pnpm
  workspaces, `file:`/path dependencies, a root `postinstall` script, or a
  `requirements.txt` that includes another file.
- **Project config and install flags (`config_files`, `install_flags`, off by
  default).** Some projects only install with their own settings, e.g. a
  committed `.npmrc` with `legacy-peer-deps = true` or a private `registry`.
  `config_files` names extra files in the project directory to bake beside the
  manifest, before the install runs (`.npmrc`, `.yarnrc`, `pnpm-workspace.yaml`,
  `uv.toml`, …). Each must be a plain file name (no path, so it can't leave the
  project), a regular file (not a symlink), and not already baked by the install
  mode. Config files are **public build inputs**: image layers are not secret
  storage, so `glove check` refuses one with a credential-like key (`_auth`,
  `_authToken`, `npmAuthToken`, `password`, `token`, `secret`, …, even an
  `${ENV}` reference, including yarn v1's quoted `"//host/:_authToken" "…"`) or
  a URL with userinfo (`user:pass@`, or a bare token as `https://ghp_…@host`;
  only ssh's `git@` passes). A registry that needs a token can't be baked.
  `install_flags` appends flags to the project install command (every manager:
  npm, pnpm, yarn, uv, pip), never to the global `packages` step. Each flag is a
  single long option, `--flag` or `--flag=value` (value: letters, digits,
  `._/@:-`), and must be on the **install mode's allow-list**: e.g.
  `--legacy-peer-deps`, `--force`, `--ignore-scripts`, `--registry=…` (npm);
  `--no-dev`, `--extra=…`, `--index-url=…` (uv sync); `--no-deps`,
  `--require-hashes` (pip). Flags that move the install (`--prefix`, `--global`,
  `--target`), weaken the lockfile (`--no-frozen-lockfile`, uv's `--frozen`) or
  TLS (`--trusted-host`), or load another config file are not on it; the error
  lists what is. Shell metacharacters (`;`, `&&`, `$()`, backticks) are refused,
  and so is a URL value with credentials. All of this is checked at plan time.
  A baked `.npmrc` applies only to the project install too. Both feed the image
  tag (the file's contents, the flags), and a block without them renders
  exactly as before.
- **Content-addressed and layered for the cache.** The derived image tag changes
  with any block field and the manifest and lockfile contents, so a stale image
  is never reused. Editing the project's source never rebuilds anything. Layers
  run every block's runtime first, then global tools, then project installs and
  browsers, so a lockfile bump never re-downloads a runtime.
- **The workspace shadow.** The baked dependencies live at
  `/opt/glove/toolchains/node/project/node_modules`, not inside `/work`.
  Plain `require` finds them from anywhere and the CLIs are on `PATH`, but a
  bundler, dev server, test runner or ES `import` resolves `./node_modules` from
  the project root. So the agent's context file tells it to run `ln -s
  /opt/glove/toolchains/node/project/node_modules node_modules` in its copy under
  `/work` (the project in `/work` must match the baked lockfile). Python has no
  such problem: the venv is active wherever the command runs.
- **Browsers.** `browsers` runs `playwright install --with-deps` at build time,
  which installs the engines and their OS libraries. The engines launch offline
  from a shell command under `enforcer: srt` (with `chromiumSandbox: false`, after
  `mkdir -p "$TMPDIR"`). Under `nono` and the default `nono+srt`, Chromium
  needs `/proc` (`/proc/self/maps`, `/proc/sys`), which nono's per-command
  profile doesn't grant, so it doesn't start. `enforcer_options: {nono:
  {browsers: true}}` opts in (with this extension, refused unless a block bakes
  `browsers`; `glove plan` shows the option beside the enforcer): the tool profile reads all of `/proc`, and
  Chromium starts with `chromiumSandbox: false`. Other processes' `environ`,
  memory and fd links stay closed (Landlock refuses access to processes outside
  the command's own sandbox, so the harness's env stays hidden); their
  command lines and `/proc/net` become readable. Verified live under
  `nono+srt` (Docker) and plain `nono` (Podman's default; there the harness's
  Landlock domain is each command's parent). The agent is
  told which applies. For browsing the internet, use the `playwright` extension (a
  sidecar). The engines are installed by the
  project's own `playwright` when its `package.json` depends on it, otherwise by
  the global one from `packages`.
- **OS libraries** a toolchain needs go in `apt_packages`; the two compose.
- **Layer order.** Its layers are `stage: late`: after every other extension's
  layers (its `PATH` never affects their build steps) and before the layers that
  copy host trees (the `skills` extension's plugins).

Not selected (or `blocks: []`), nothing toolchain-specific renders: image tags,
compose env, policies and the context file are unchanged.
