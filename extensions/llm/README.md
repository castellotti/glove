# llm — the inference engine

Fills the required `inference` slot. Pick a provider the way gluetun picks a VPN
provider: one `provider:` name from the catalog (`providers/<name>.yml`, data
only) plus a few settings. Everything provider-specific stays here; core only
sees the resulting *model descriptor* (base URL, wire API, model id,
capabilities, whether a key is passed).

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

`api_key` is a reference (`keychain:<service>` or `env:<VAR>`), resolved at
launch and handed to the harness only in its environment. The harness's adapter
names the variable (Pi/Vibe: `GLOVE_LLM_API_KEY`; Claude Code:
`ANTHROPIC_API_KEY`, or `CLAUDE_CODE_OAUTH_TOKEN` with `auth: oauth`).

`auth: oauth` takes a subscription token instead of an API key, where the
provider's catalog entry allows it: `anthropic` allows it for `claude-code`
only (a token from `claude setup-token`). The launch-time probe then sends it as
a bearer token with the catalog's OAuth headers. A catalog entry's `headers`
(e.g. `anthropic-version`) go on every probe.

Anthropic's model list is paginated and names dated snapshots; the probe follows
every page (`models_cursor`) and accepts an alias such as `claude-haiku-4-5` for
its snapshot `claude-haiku-4-5-20251001` (`dated_aliases`).

## Routing

Each location renders exactly one forwarder, `glove-<id>-llm`, the only thing
the harness can reach for inference:

| `location` | forwarder dials | over |
|---|---|---|
| `host` | `host.docker.internal:<port>` (endpoint must be `127.0.0.1:<port>`) | `glove-<id>-hostgw` |
| `lan` | exactly the configured `host:port` | `glove-<id>-llm` (a normal bridge; Docker Desktop routes it to your LAN) |
| `internet` | the provider's HTTPS host on 443 | `glove-<id>-llm` |

For `internet` the provider hostname (e.g. `api.openai.com`) is an alias of the
forwarder on the harness network, so the harness speaks TLS to the real name
(correct SNI and certificate) and still reaches nothing else. Docker's DNS would
answer that alias to the forwarder itself, so it dials a second hop,
`glove-<id>-llm-out`, which is not on the harness network and dials the real
host. `route: egress`
(cloud inference through the session's VPN/Tor) is not implemented yet.

With `observe`, the forwarder records flows as `tool: llm`, `scope:
local | lan | cloud`.

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
