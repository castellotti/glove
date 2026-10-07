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
                                 # | llama.cpp | ollama | lmstudio | openai | anthropic | mistral | openrouter
    location: lan              # host (this Mac) | lan | internet
    endpoint: <host>:<port>    # host/lan; cloud providers use the catalog host
    model: auto                # or an id
    capabilities: auto         # or explicit keys, e.g. {vision: true}; probes fill the rest
    api_key: keychain:<service>  # optional for local servers; a reference, never the key
    extra_models: []           # e.g. [{id: some-vision-model, vision: true}]
```

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
  sets the harness's `NODE_EXTRA_CA_CERTS` to it: Node adds it to its roots,
  verification stays on. glove's launch probe trusts the same file. The
  healthcheck is a handshake verified by name, so "healthy" also means "the
  CA is published".
- The allowlist adds the catalog's `oauth.paths` (GET only; the list and when
  Claude Code calls each are in `providers/anthropic.yml`): remote settings,
  policy limits, profile, usage and WebFetch's domain preflight. Feedback,
  transcript sharing and account writes are a 403. `llm-auth` adds the token
  to each, including the two Claude Code sends without one (`HEAD /api/hello`,
  the preflight).
- `corporate_ca` also sets `NODE_EXTRA_CA_CERTS`; the two together are refused
  at plan time for now.

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
hardened container on the harness network (the host never resolves or contacts
the server):

- `GET /v1/models`: exactly one model → used; several or none → error listing them.
- the catalog's capability probe: `openai-compatible` reads `max_model_len`
  from `/v1/models` (vLLM, NInfer, llama.cpp); llama.cpp reads `/props`
  (`modalities.vision`, `n_ctx`); ollama and LM Studio read their native model
  APIs. With `capabilities: auto`, a failed probe fails the launch.
- explicit `capabilities:` keys win and the probe fills the rest; a conflict is
  a warning, not an error. Vision can't be discovered through the OpenAI API,
  so a vision model on a generic server needs `capabilities: {vision: true}`.

## When a server gets its own provider

Use `openai-compatible` for anything that speaks the OpenAI API. Add a
dedicated entry only when a server offers something the generic path cannot:

- a native capability endpoint (llama.cpp `/props`, ollama `/api/show`,
  LM Studio `/api/v0`);
- a different wire protocol (`anthropic-messages`, `mistral-conversations`);
- a fixed cloud host and required key (openai, openrouter);
- in future, a server-specific feature or optimization worth configuring
  (e.g. speculative/MTP decoding flags, an in-session `sidecar` runtime).

An entry is `providers/<name>.yml` (see `llama.cpp.yml`) plus its name in the
`provider` enum in `extension.yml`. `tests/test_llm.py` validates every catalog
file and refuses a local-server entry whose only probe is `/v1/models`, since
that adds nothing over `openai-compatible`.
