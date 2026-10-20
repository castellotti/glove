# Writing a glove extension (`api: 2`)

An extension adds something to a glove session: a sidecar the harness reaches
through a forwarder, an image layer, an MCP server, skills, a brief for the
agent, or host-side steps at launch. It is a directory holding an
`extension.yml` manifest and, optionally, a Jinja compose fragment, `hooks.py`
(host Python that core calls at fixed points) and `cli.py` (a
`glove <name> …` subcommand).

Core owns every security decision. A manifest *declares* what the extension
needs; core checks it, renders it and applies the hardening set. An extension
cannot set a container's security keys, publish a port, join the harness
network or mount the docker socket. The README's
[Extensions](../README.md#extensions) section describes what each key means for
a session. This document is the contract an extension author codes against.

- [Where extensions come from](#where-extensions-come-from)
- [The manifest](#the-manifest)
- [Hooks](#hooks)
- [Slot exports](#slot-exports)
- [`glove.api`](#gloveapi)
- [An extension's CLI](#an-extensions-cli)
- [Migrating from `api: 1`](#migrating-from-api-1)

## Where extensions come from

- **In-tree:** `extensions/<name>/` in glove itself.
- **Out-of-tree:** from `extension_paths:` in `~/.glove/config.yml`, each
  entry an extension's directory or a directory of them. These are labelled
  *out-of-tree* (`glove ext`, `glove plan`), and none may reuse another's
  name.
- **Trusted:** an out-of-tree extension the user also lists under
  `trusted_extensions:`. Only an in-tree or trusted extension may use the keys
  marked *trust* below, and only its hooks see host paths.

A session selects an extension by naming it under `extensions:` in
`glove-session.yml`, with its settings. A *library* extension (`auto: true`,
`selectable: false`) is added when another extension requires it, and is never
selected directly.

## The manifest

`extension.yml` must say `api: 2`. Any other version is refused at discovery
("extension 'x' is written for api 1; glove speaks api 2"), as is an unknown
key or a value of the wrong type. The table below is
[`glove/manifest.py`](../glove/manifest.py) `KEYS`; a test checks that each
key appears here.

Legend:
- **when:** the key, or its items or entries, take a `when:` predicate (see
  the README).
- **hook:** a `contribute` hook may return it too. `cat`: its list is
  appended to the manifest's. `add`: it adds names; a name the manifest also
  sets is refused, unless the manifest's entry is `when:`-excluded.
- **trust:** in-tree or trusted only.

| key | type | when: | hook | trust | what |
|---|---|---|---|---|---|
| `api` | `2` | | | | the version |
| `name` | slug (`[a-z][a-z0-9-]*`) | | | | unique; the directory's name in practice |
| `summary` | str | | | | one line for `glove ext` |
| `provides` | list of slots | | | | `egress`, `inference`, `browser`, `forwarder`; a slot has one provider per session |
| `requires` | list: extension, slot, or `{extension\|slot, when}` | items | | | a required library with `auto: true` is added; anything else must be selected |
| `auto` | bool | | | | a library, added when required |
| `selectable` | bool | | | | `false`: a library only |
| `settings` | map name → `{type, default, required, …}` | | | | `type`: `string`, `enum` (`values`), `bool`, `int`, `number`, `list`, `map`, `secret`, `path` (`within: session`); `pattern`, `also` (literals accepted besides the type, e.g. `auto`). A `secret` is a `keychain:`/`env:` reference, never a value |
| `host_files` | bool | | | yes | the hooks read files in the session directory that no other key declares (see [the context](#the-context)) |
| `validate` | list of `{when, error}` or `{when, require, message}` | items | | | cross-setting rules, checked when the session is planned |
| `exports` | map | | `add` | | values other extensions and templates read; a slot's are typed ([slot exports](#slot-exports)) |
| `endpoints` | map name → `{port, target, harness, aliases, listen_networks, observe, interpose}` | entries | `add` | `host_port`, `address` | a forwarder. `target` is one of `service` (+ `network`), `slot`, `host_port`, `address` (+ `via: llm\|wan\|lan`). `observe` is the forwarder provider's annotation (observe's gate: `mode`, `tool`, `client`, …; `feeds` names the egress endpoints its target dials out on, when its network has several) |
| `networks` | map name → `{internal, when}` | entries | | | the extension's own networks; private ones are internal |
| `services` | path to a compose fragment (Jinja) | in the template | | | its sidecars; core adds the hardening set and refuses security keys |
| `images` | map name → `{build}` | | | | sidecar images, tagged by content |
| `privileges` | map service → privileges | items | `add` | yes | exceptions from the allowlist: `cap_add`, `devices`, `user_root`, `read_only`, `seccomp` (a core profile), `low_ports`, `work`; `hint` explains a refusal |
| `limits` | map service → `{pids, memory, …}` | | | | defaults: 256 pids, 512m |
| `secrets` | map name → a `secret` setting, or `{from, when}` | entries | | | compose secrets, resolved in memory at launch |
| `channels` | map name → `{services, read_only, trust, when}` | entries | `add` | yes | a tmpfs directory shared by the harness and these sidecars, at `/run/glove/<name>` |
| `outputs` | map name → `{services, when}` | entries | | yes | `<session>/<name>/`: written by the sidecars, read-only at `/work/<name>` |
| `inputs` | map name → `{services, when}` | entries | | yes | `<session>/<name>/`: written by the harness, read-only in the sidecars |
| `mounts` | map name → `{setting, when}` | entries | | | a read-only harness bind of a directory named by a `path` setting with no default |
| `trust` | list of services | | `cat` | | these sidecars trust the session's CAs |
| `verify` | list of checks `{name, kind, service, …}` | items | `cat` | | run at `glove up`; `kind`: `container-healthy`, `tcp-open`, `http-ok`, `http-refused`, `exit-confirmed`, `exec-ok` (argv only in its own sidecars) |
| `harness` | map: `image`, `env`, `git_config`, `brief`, `mcp`, `skills`, `<harness>` | parts | `add` | | what the harness gets ([below](#harness)) |
| `hooks` | path, relative (`hooks.py`) | | | | [hooks](#hooks) |
| `cli` | path, relative (`cli.py`) | | | | [an extension's CLI](#an-extensions-cli) |

### `harness:`

- `image`: `{"*" | <harness>: layer(s)}`: packages, `copy`, `run`, `env` (image
  `ENV` lines; a value may extend one, `PATH: "/x/bin:$PATH"`; never git's
  `GIT_CONFIG_*`: use `git_config`). Only a hook's
  layers may `copy_host`. Layers render in extension order, then those with
  `stage: late` (e.g. the toolchains), then those that `copy_host`.
- `env`: `{VAR: value}` or `{VAR: {value, when, shell: false}}`. A variable is
  set by one extension only.
- `git_config`: pairs added to git's config in the harness.
- `brief`: a file (or `{file, when}`) the agent reads at start.
- `mcp`: a list of servers: `name`, `transport` (`stdio` or `http`), `url` or
  `command`/`args`/`env`, and `tools`/`all_tools`.
- `skills`: `SKILL.md` directories, inside the extension or `{mount, path}`.
- `<harness>` (`pi`, `vibe`, `claude-code`): a section only that harness's
  adapter reads. Core renders it, applying `when:`, before the adapter sees it.

A `contribute` hook's `harness:` may hold `image`, `env`, `skills` (container
paths), `mcp` and `brief` (its text, taken as is: not a template).

### Hook-only keys

A `contribute` hook may also return keys whose values exist only at plan
time. A manifest may not set them.

| key | type | hook | what |
|---|---|---|---|
| `vars` | map | `add` | the extension's own fragment reads them as `{{ vars.x }}` |
| `egress_hosts` | list of hosts (`*.x` for subdomains) | `cat` | the names its sidecars reach; `glove check` warns when a filtering egress doesn't admit one |
| `secret_refs` | map label → secret reference | `add` | secrets nested deeper than a `secret` setting, which `glove check` verifies exist |

## Hooks

`hooks.py` holds functions marked `@hook`:

```python
from glove.api import HookContext, hook


@hook
def contribute(ctx: HookContext) -> dict:
    hosts = ctx.settings["hosts"]
    return {"endpoints": {f"ssh-{h['name']}": {...} for h in hosts}}
```

`@hook` on a name glove doesn't call fails at import. A function named like a
hook but not marked is refused, so a forgotten decorator can't skip a hook
silently. Other functions in the module (helpers, things its CLI uses) are
fine.

Core calls an extension's hooks only when the session selects it. Every hook
is optional.

| hook | signature | when | may | returns |
|---|---|---|---|---|
| `contribute` | `(ctx)` | planning (`check`, `plan`, `up`, `doctor`), in dependency order | read host files | manifest keys (`hook` column above) |
| `materialize` | `(ctx)` | rendering (`plan`, `up`) | write under `ctx.state_dir` (and its export dirs) | `None` |
| `forwarder` | `(ctx, endpoint)` | the network plan; the `forwarder` slot's provider only | nothing (pure) | `{service, facts, aliases}`, or `None` for core's own forwarder |
| `launch_env` | `(ctx, resolve_secret)` | `up`, before `compose up` | read the Keychain, run host commands, start host processes (stopped by its `teardown`, also when `glove up` then fails before compose starts); values stay in memory | `{secrets: {its secret: value}, env: {VAR: value}}` |
| `resolve` | `(ctx, exports, probe)` | `up`, once the sidecars are healthy | only through `probe` | `(exports, notes)` |
| `diagnose` | `(ctx, check, run)` | `up`, after one of its verify checks failed | `run(service, argv)` in its own sidecars | a hint, or `None` |
| `doctor` | `(ctx, probe)` | `doctor`, `check` | `probe`, `None` offline | `[(name, status, detail)]`, status `ok`, `info`, `skip`, `warn` or `fail` |
| `teardown` | `(ctx)` | `down`, `rm`, before the containers stop | stop what its `launch_env` started on the host | `None` |

- `teardown` runs outside a launch: its context is a CLI's (the settings the
  last `glove up` used, the session id, `state_dir` and the host paths its
  manifest declares), with no plan behind it, and possibly when `launch_env`
  never ran or only partly ran: stop only what is running. A failure is a
  warning; the containers still stop.

- A forwarder's `service` may set only `image`, `command`, `entrypoint`,
  `environment`, `volumes`, `tmpfs`, `depends_on`, `healthcheck`, `init`,
  `restart`, `stop_grace_period`, `stop_signal` and `labels`. Core names it,
  joins its networks and hardens it.
- Every result is checked against the table above. A `ValueError` (or
  `ConfigError`) from a hook is reported as `extension 'x': <hook>: <message>`
  without a traceback. Raise one for a bad setting. Any other exception is a
  bug, and its traceback names the extension and hook.

### The context

`ctx` is a frozen `HookContext`. Its mappings are read-only, and its names are
those of the fragment's template context.

| field | what |
|---|---|
| `name`, `harness`, `renders`, `trusted`, `active` | this extension, the session's harness, what the harness renders (`mcp`, `skills`), whether it is trusted, the selected extensions |
| `settings` | its settings, validated, defaults applied |
| `session` | `{id, subnet, secrets_dir}` |
| `names` | `{project, harness_network, prefix}` |
| `slot` | `{slot: {provider, **exports}}`, for the slots filled so far |
| `endpoint`, `own_endpoints` | every endpoint declared so far (`{host, port, url, harness, aliases, interposed, target_kind}`); its own (`{host, port}`) |
| `state_dir` | its own state directory (`.glove/ext/<name>/`) |
| `assets` | its own directory |
| `images`, `libs` | image tags: its own, and its libraries' |
| `mount`, `output`, `input` | as in the fragment, when declared |
| `session_dir` | the session directory, **only if** the manifest declares a reason: a `path` setting, `mounts`, `outputs`/`inputs`, or `host_files: true` |
| `work_dir` | `work/`, **only if** it declares `outputs`/`inputs`, a `work` privilege, or `host_files: true` (a `work` privilege its `contribute` hook returns counts for the hooks after it) |
| `export_dirs` | the export roots it owns (in-tree only) |
| `forwarders`, `grants` | the network plan, for the `forwarder` slot's provider (in-tree or trusted); each forwarder's `endpoint` is what its `forwarder` hook was told (none for a second hop) |
| `enforcer`, `enforcer_options` | the session's enforcer and its options (defaults applied), read-only |

An untrusted out-of-tree extension never gets `session_dir`, `work_dir`,
`export_dirs`, `forwarders` or `grants`. **This is hygiene, not a sandbox.** A
hook is host Python running with your rights. What contains an extension is
not selecting or trusting one you haven't read.

### Loading

`hooks.py` and `cli.py` load as modules of the package `glove_ext.<name>`
(with `-` as `_`), rooted at the extension's directory, so an extension imports its own files
relatively:

```python
from . import relay_policy
from .host import login
```

From core, an extension imports only `glove.api`. An in-tree extension may
import another in-tree extension it requires, directly or through another
(`extensions.<x>`). An
out-of-tree extension that needs shared code ships it itself.

## Slot exports

Core and other extensions read some of a slot provider's `exports`. These are
checked by type (`glove/manifest.py` `SLOT_EXPORTS`) after `contribute` and
again after `resolve`. A templated int or bool (`proxy_port: "{{ settings.port }}"`)
renders as a string, and is read back as one. Keys not listed are allowed, and
only the provider's own templates read them.

| slot | key | type |
|---|---|---|
| `egress` | `proxy_host`, `proxy_port`, `proxy_url` | str, int, str (required) |
| | `network` | str (default `egress`) |
| | `route` | str |
| | `anonymising` | bool |
| | `resolver` | `dns://…` or null |
| | `exit_identity` | `{url}` or `{source, volume, file}` |
| | `shares` | list of volume names a forwarder may mount read-only |
| | `guard_hosts`, `guard_cidrs` | list of str |
| `inference` | `base_url`, `api`, `model` | str (required) |
| | `api_key_secret`, `api_key_kind`, `auth_header`, `auth_scheme` | str or null |
| | `api_key_injected` | bool |
| | `capabilities`, `extra_models`, `probe_headers` | map, list, map |
| `browser` | `host_ports` | `{mcp, cdp}` |

## `glove.api`

An extension imports only these names from core. Each is re-exported from
where core keeps it. `tests/test_api_surface.py` holds the list and the
signatures, so a change is deliberate.

| group | names |
|---|---|
| errors | `ConfigError`, `ExtensionError` (a `ConfigError`; both print as one line) |
| the hook protocol | `HookContext`, `hook` |
| secrets (values stay in memory) | `resolve_secret`, `is_secret_ref`, `keychain_service`, `keychain_set`, `secret_exists` (an item is there; nothing read), `is_secret_env_name` |
| host paths (core's own rules) | `host_path`, `existing_host_path`, `overlaps`, `exposes_private` (a path the harness must never see, e.g. `.glove/`), `resolve_ca_file` |
| naming | `scoped(session_id, name)` (`glove-<id>-<name>`, a container, network or volume of the session), `HOST_GLOB` |
| image building | `apt_bootstrap`, `STAGE_IGNORE`, `run_body`, `fetch_steps` (a checksum-checked download), `uv_steps` |
| the session's enforcer | `tools_run_browsers(enforcer, options)` (can Chromium start in a shell command?) |
| rendering, with core's checks | `render_value`, `active_items`, `tool_names`, `mcp_server` |
| an extension's CLI | `ext_session`, `ExtSession`, `reload_sidecar` |

Harness adapters (in-tree only) also import `glove.api.harness`.

## An extension's CLI

`cli.py` exports `app`, a `typer.Typer`. glove mounts it as `glove <name> …`.
It finds its session with `ext_session`:

```python
from glove.api import ConfigError, ext_session, reload_sidecar, resolve_secret


@app.command("reload")
def reload(directory: Path | None = DIR_OPT) -> None:
    try:
        s = ext_session("mine", directory)   # launched=False: a session not yet started
        reload_sidecar(s, "mine", s.hooks.fresh_env(s.settings, resolve_secret))
    except ConfigError as e:
        raise _fail(str(e)) from e
```

- `ext_session(name, directory=None, *, launched=True)` finds the session at
  or above `directory` and returns an `ExtSession`. It refuses a directory
  that isn't a session, one never launched, or one that doesn't enable `name`
  (with a mapping of settings).
- `ExtSession` has these fields:
  - `name` (the extension), `root`, `file`, `work`, `id` (`None` only with
    `launched=False`);
  - `runtime` (`docker` or `podman`);
  - `compose_file`;
  - `settings` (validated, defaults applied);
  - `hooks` (its `hooks.py`, or `None`; loaded the first time it is read);
  - `manifest`.

  It has these methods:
  - `container(service)` (its name);
  - `running(service)`;
  - `rendered(service)` (that service as the last `glove up` rendered it);
  - `export_dir(root)` (the owner only);
  - `state_dir()` (its state directory, created private);
  - `context()` (a `HookContext` for calling its own helpers outside a
    launch: its settings, `session` with the `id` only, `state_dir`,
    `assets`, and the host paths its manifest declares; nothing that exists
    only while planning).
- `reload_sidecar(s, service, env, *, wait=30)` recreates one running sidecar
  with `env` (resolved by the caller, held in memory) and waits until it is
  healthy. Nothing else is re-planned: when the settings changed, `glove up`
  applies them.

## Migrating from `api: 1`

- `api: 2` in `extension.yml`.
- `trust_corporate_ca:` → `trust:`. `conflicts:` and `host_services:` are
  gone: an extension that runs something on the host starts it in
  `launch_env` and stops it in `teardown`.
- Mark each hook `@hook`. Read `ctx.settings`, not `ctx["settings"]`.
  `ctx["state"]` is `ctx.state_dir`.
- `doctor(ctx)` → `doctor(ctx, probe)`.
- A `contribute` hook returns its harness parts under `harness:` (`image`,
  `env`, `skills`, `mcp`), and no longer replaces a name the manifest sets.
- Hooks that read files in the session directory, without a `path` setting,
  `mounts` or `outputs`/`inputs` to show for it, add `host_files: true`.
- Import from `glove.api` only. Replace `load_module` with relative imports,
  and `sessiondir`/`registry`/`session` in a CLI with `ext_session` and
  `reload_sidecar`.
