## Vibe's settings

Vibe's `config.toml` is read-only here (glove renders it at each start). A
choice made in Vibe's UI, such as `/theme` or `/model`, lasts for this run at
most and is never saved; Vibe shows no error. If the user wants a lasting
choice, tell them it goes in the session file (`glove-session.yml`):
`harness_config` for Vibe's config, or the `llm` extension's `model`.

## Where you can write

Your `write_file` and `edit` tools write only where a shell command can: the working
directory, the session's read-write mounts and `/tmp`. Anywhere else (your own
config home included) the call is refused.
