# harness-config

Passes settings straight to the harness's own config file. Its keys are the
harness's native ones, written flat (no `settings:` level):

| Harness | Rendered into | Notes |
|---|---|---|
| Pi | `settings.json` | `model` overrides the model's `models.json` entry; `env` is deep-merged; `extensions` and `skills` follow glove's |
| Vibe | `config.toml` | lists extend glove's; `mcp_servers` are added after the extensions' servers |
| Claude Code | `settings.json` | `permissions` (`defaultMode`, `allow`, `deny`) join glove's managed rules instead |

```yaml
extensions:
  harness-config:              # Vibe
    include_commit_signature: false
    show_thinking_nodes: true
```

Settings tied to the model (Pi's `defaultThinkingLevel`, `compaction`, a model's
`compat`; Claude Code's `ANTHROPIC_DEFAULT_*_MODEL` env) go in the `llm`
extension's `harness` setting instead, beside the model they tune:

```yaml
extensions:
  llm:
    provider: openai-compatible
    model: my-model
    harness:                   # Pi
      defaultThinkingLevel: xhigh
      compaction: {reserveTokens: 49152, keepRecentTokens: 32000}
```

glove merges both, mappings key by key; a key the two set to different values
is refused. The config files are read-only in the container (glove renders them
at each start), so this file is the one place a lasting setting lives.

glove's own switches for the harness are not native config: they are the
top-level `harness_options:` (`tools_allow`, and a harness's `protect:` opt-ins
such as Vibe's `project_skills`), which core checks.
