## Pi's settings

Pi's settings files are read-only here (glove renders them at each start). A
choice made in Pi's UI, such as `/model` or `/settings`, lasts for this run at
most and is never saved, even when Pi reports it as saved. If the user wants a
lasting choice, tell them it goes in the session file (`glove-session.yml`):
`harness_config` for Pi's settings, or the `llm` extension's `model`.
