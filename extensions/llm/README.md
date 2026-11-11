# llm — the inference engine

Fills the required `inference` slot. Pick a provider the way gluetun picks a VPN
provider: one `provider:` name from the catalog (`providers/<name>.yml`, data
only) plus a few settings. Everything provider-specific stays here; core only
sees the resulting *model descriptor* (base URL, wire API, model id,
capabilities, whether the key is injected).

```yaml
extensions:
  llm:
    provider: openai-compatible  # the default for any OpenAI-API server (vLLM, NInfer, SGLang, …)
                                 # | openai-responses-compatible | anthropic-compatible | llama.cpp | ollama
                                 # | lmstudio | openai | anthropic | mistral | openrouter
    location: lan              # host (this Mac) | lan | internet
    endpoint: <host>:<port>    # host/lan; cloud providers use the catalog host. A URL's path is
                               # the full API prefix, ending in the catalog's (…/openai/v1)
    model: auto                # or an id
    capabilities: auto         # or explicit keys, e.g. {vision: true}; probes fill the rest
    api_key: keychain:<service>  # optional for local servers; a reference, never the key
    extra_models: []           # e.g. [{id: some-vision-model, vision: true}]
    harness: {}                # this model's native harness settings, e.g. Pi's {defaultThinkingLevel: xhigh}
```

## `harness`: settings tied to the model

`harness` is passed to the harness's own config as written, flat (no
`settings:` level), so the tuning sits beside the model it is for:

```yaml
    harness:                   # Pi: settings.json; `model` overrides the model's models.json entry
      defaultThinkingLevel: xhigh
      compaction: {reserveTokens: 49152, keepRecentTokens: 32000}   # reserve ≥ max_tokens, plus slack
      model: {compat: {thinkingFormat: qwen}}
```

On Claude Code it is `settings.json` (e.g. `env: {ANTHROPIC_DEFAULT_OPUS_MODEL: …}`), on Vibe `config.toml`.
Settings that are not about the model go in the
[`harness-config`](../harness-config/README.md) extension; glove merges the two.

## Auth

`api_key` is a reference (`keychain:<service>` or `env:<VAR>`), resolved in
memory at launch. With an API key the harness never holds it: the key goes
only to the `llm-auth` sidecar (below), and the harness's variable holds the
public placeholder `glove-injected` (Pi/Vibe: `GLOVE_LLM_API_KEY`; Claude Code:
`ANTHROPIC_API_KEY`, which the adapter pre-approves in `.claude.json` so Claude
Code doesn't ask about it). glove's launch-time probe sends no key either: it
goes through `llm-auth` too.

`auth: oauth` takes a subscription token instead of an API key, where the
provider's catalog entry allows it: `anthropic` allows it for `claude-code`
only (a token from `claude setup-token`). The token is injected too (below,
"With a subscription token"): `CLAUDE_CODE_OAUTH_TOKEN` holds the placeholder,
and `llm-auth` sends it as a bearer token with the catalog's OAuth
headers. A catalog entry's `headers` (e.g. `anthropic-version`) go on every
request of glove's launch-time probe.

Anthropic's model list is paginated and names dated snapshots; the probe follows
every page (`models_cursor`) and accepts an alias such as `claude-haiku-4-5` for
its snapshot `claude-haiku-4-5-20251001` (`dated_aliases`).

A model object's `aliases` (llama.cpp's router, `--models-preset`, lists a
preset's `alias =` names there) are accepted as `model:` too, and sent as written.

## Routing

The harness reaches inference only through `glove-<id>-llm`. Where that leads
depends on the key.

**With an API key** (the key is injected):

```
harness ─▶ llm (forwarder) ─▶ llm-auth (holds the key) ─▶ llm-upstream (forwarder) ─▶ server
```

- `llm-auth` (`image/llm_auth.py`, Python stdlib only) runs as the session uid
  with no capabilities, `no-new-privileges` and a read-only rootfs, on the
  internal `glove-<id>-llmauth` network only. Its peers are the two forwarders;
  the harness can reach neither `llm-auth` nor `llm-upstream`.
- For each request (a kept-alive connection's included) it checks the method
  and path against an allowlist: the paths the harnesses send for the
  provider's API (measured per harness release, `API_PATHS` in `hooks.py`),
  the model list and the catalog's capability probe. Anything else is a 403,
  and the connection closes. A chunked request body is refused (411).
- It drops the client's credentials (`Authorization`, `x-api-key`, `api-key`)
  and hop-by-hop headers, sets `Host` to the server's, adds the key in the
  catalog's auth header, and streams the answer back unbuffered.
- For a cloud provider it does the TLS itself, to the provider's name
  (certificate verified against the image's CA store); `llm-upstream` only
  relays TCP. The harness's hop to `llm-auth` is plain HTTP on an internal
  network (TLS by the provider's name with a token, below).
- Its log names the method, path and status of each request, never a header
  value.

`llm-upstream` dials:

| `location` | `llm-upstream` dials | over |
|---|---|---|
| `host` | `host.docker.internal:<port>` (endpoint must be `127.0.0.1:<port>`) | `glove-<id>-hostgw` |
| `lan` | exactly the configured `host:port` | `glove-<id>-llm` (a normal bridge; Docker Desktop routes it to your LAN) |
| `internet` | the provider's HTTPS host on 443 | `glove-<id>-llm` |

**With a subscription token** (`auth: oauth`): Claude Code also calls
Anthropic's account API at the fixed `https://api.anthropic.com`, which
`ANTHROPIC_BASE_URL` doesn't move. So the harness keeps the provider's own
name, and `llm-auth` answers it:

```
harness ─https://api.anthropic.com─▶ llm (forwarder, alias api.anthropic.com:443)
  ─▶ llm-auth :8443 (TLS as api.anthropic.com, holds the token) ─▶ llm-upstream ─▶ api.anthropic.com:443
```

- At each start `llm-auth` makes a session CA (EC P-256, `pathlen:0`,
  name-constrained to the provider's host), signs a leaf for that name and
  deletes the CA key at once; the leaf key goes once loaded. Both live only on
  its `/tmp` tmpfs. Every `glove up` makes a new CA, so `llm-auth` is never
  restarted on its own (a new CA would be untrusted by the running harness;
  if it dies, the model is unreachable until the next `glove up`).
- It publishes `ca.pem` in the `llm-ca` channel, which only `llm-auth` writes
  and the harness reads (`read_only`, mounted at `/run/glove/llm-ca`). Core
  adds it to the harness's CA bundle (with `corporate_ca`, when set), built
  as the harness starts: Node adds it to its roots, verification stays on.
  glove's launch probe trusts the same bundle. The
  healthcheck is a handshake verified by name, so "healthy" also means "the
  CA is published".
- The allowlist adds the catalog's `oauth.paths` (GET only; the list and when
  Claude Code calls each are in `providers/anthropic.yml`): remote settings,
  policy limits, profile, usage and WebFetch's domain preflight. Feedback,
  transcript sharing and account writes are a 403. `llm-auth` adds the token
  to each, including the two Claude Code sends without one (`HEAD /api/hello`,
  the preflight).

**Without a key** (a local server), `glove-<id>-llm` dials the table's target
itself. For `internet` the provider hostname is then an alias of the
forwarder on the harness network, so the harness speaks TLS to the real name
(correct SNI and certificate) and still reaches nothing else. Docker's DNS
would answer that alias to the forwarder itself, so it dials a second hop,
`glove-<id>-llm-out`, which is not on the harness network and dials the real
host.

`route: egress` (cloud inference through the session's VPN/Tor) is not
implemented yet.

With `observe`, the forwarders record flows as `tool: llm`, `scope: local |
lan | cloud`. With an injected key each model call is two flows: `llm`
(client `harness`; plain HTTP, or TLS by the provider's name with a
subscription token) and `llm-upstream` (client `llm`; for a cloud provider it
carries the TLS SNI). `glove filter` rules apply at both.

## `model: auto` and `capabilities: auto`

Resolved at `glove up`/`run`, after the forwarder starts, from a throwaway
hardened container on the harness network (the launch never contacts the
server from the host):

- `GET /v1/models`: exactly one model → used; several or none → error listing them.
- the catalog's capability probe: `openai-compatible` reads `max_model_len`
  from `/v1/models` (vLLM, NInfer, llama.cpp); llama.cpp reads `/props`
  (`modalities.vision`, `n_ctx`); ollama and LM Studio read their native model
  APIs. With `capabilities: auto`, a failed probe fails the launch.
- explicit `capabilities:` keys win and the probe fills the rest; a conflict is
  a warning, not an error. Vision can't be discovered through the OpenAI API,
  so a vision model on a generic server needs `capabilities: {vision: true}`.

## `glove check`: the server answers

`glove check` asks the server for `/v1/models` as the launch does (the same
public headers, the same model rule), without the key, and fails when it does not answer, when `model:` is
not listed, or (`model: auto`) when it lists other than exactly one. With
`api_key` set, a 401/403 still counts as an answer; a server that lists no
models is taken at its word, as at launch. Like every other probe, it runs in a
throwaway, hardened container, never on this machine: on the runtime's default
bridge (nothing of the session is up yet), dialling the server as `llm-upstream`
does: direct (never through a proxy), over IPv4, and `location: host` through
`host.docker.internal`. `--offline` and `--no-container` skip it.

## Responses API servers (`openai-responses-compatible`)

Some models refuse function tools with a reasoning effort on chat/completions.
gpt-6-luna answers HTTP 400 "Function tools with reasoning_effort are not
supported … in /v1/chat/completions", so `openai-compatible` can run it only at
effort `none`. `openai-responses-compatible` speaks the OpenAI Responses API
instead. Pi sends `reasoning.effort` and the tools in one `POST …/responses`,
and every thinking level works with tools (`off` sends effort `none`).

```yaml
extensions:
  llm:
    provider: openai-responses-compatible
    location: host
    endpoint: http://localhost:6655/openai/v1   # the full API prefix, /v1 included
    model: gpt-6-luna
    capabilities: {vision: true, context_window: 1050000, max_tokens: 32768, reasoning: true}
    api_key: keychain:<service>
```

- **Pi only.** The catalog's `harnesses: [pi]` makes `glove check` (and the
  plan) refuse it for Claude Code and Vibe, which do not speak this API.
- **The endpoint is the full API prefix.** The harness posts to
  `<endpoint>/responses`, and the model list is at the endpoint minus the
  catalog's `/v1`, plus `/v1/models`. `http://localhost:6655/openai/v1` gives
  `…/openai/v1/responses` and `…/openai/v1/models`. An endpoint path that
  doesn't end in `/v1` (e.g. `…/openai`) is refused: the model list would
  still answer, so `glove check` would pass, but every turn would post to
  `…/openai/responses`. The same holds for every provider whose catalog
  names a `base_path` (`openai-compatible` posts to `<endpoint>/chat/completions`).
- llm-auth allows `POST <prefix>/responses` and the model list, and nothing
  else (`chat/completions` included). Pi 1.4.0 calls only `responses.create`
  (streamed, `store: false`).
- **Set `capabilities:` explicitly.** There is no capability probe: a gateway
  lists many models, and none of them reports its window in a way glove can
  match to the model (else the catalog defaults apply). The default is
  `reasoning: true`, the reason to pick this provider; set
  `capabilities: {reasoning: false}` for a model that refuses an effort.
- Pi's `models.json` gets no `compat` block: pi-ai's defaults for this API
  (no strict mode, no grammar tools) are what a gateway wants. A
  `harness: {model: {compat: …}}` override may set the Responses API's keys
  (`supportsStrictMode`, …); the chat/completions keys glove checks
  (`thinkingFormat`, `maxTokensField`) are refused, since Pi would load them
  and ignore them. A reasoning
  model's `thinkingLevelMap` is the same as on chat/completions; `max`
  clamps to `xhigh`.

## When a server gets its own provider

Use `openai-compatible` for anything that speaks the OpenAI API. Add a
dedicated entry only when a server offers something the generic path cannot:

- a native capability endpoint (llama.cpp `/props`, ollama `/api/show`,
  LM Studio `/api/v0`);
- a different wire protocol (`anthropic-messages`, `openai-responses`, `mistral-conversations`);
- a fixed cloud host and required key (openai, openrouter);
- in future, a server-specific feature or optimization worth configuring
  (e.g. speculative/MTP decoding flags, an in-session `sidecar` runtime).

An entry is `providers/<name>.yml` (see `llama.cpp.yml`) plus its name in the
`provider` enum in `extension.yml`. An API only some harnesses speak takes
`harnesses: [<name>, …]` (`openai-responses-compatible`: `[pi]`), checked
when the session is planned. `tests/test_llm.py` validates every catalog
file and refuses a local-server entry whose only probe is `/v1/models`, since
that adds nothing over `openai-compatible`.
