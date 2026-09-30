# filter

Network rules, the **write** grant (requires `observe`). glove creates
`~/.glove/control/<id>/` (0700, yours), mounts it read-only into every gate and
the collector, and passes `--rules`: `rules.json` is enforced within about a
second and its load result (with the enforced file's SHA-256) is in
`status.json`. `session.json` and the registry row carry
`grants.filter = {"granted": true, "since": …}`.

```yaml
extensions:
  observe: {}
  filter: {}
```

CLI (the same file and writer contract as Layman: validate with the gate's own
validator, atomic rename; never creates the directory):

```
glove filter block '*.doubleclick.net' [--port N] [--terminate] [--allow] [--note TEXT]
glove filter unblock <rule-id|target>
glove filter rules [--json]          # rules + whether the file on disk is enforced
glove filter validate FILE|- [--env ID] [--session ID] [--json]
```

**Revocation.** Remove `filter:` and the next `glove up` moves `rules.json` to
`.glove/ext/filter/rules.revoked.json`, removes `control/<id>/`, sets
`grants.filter.granted: false`, and re-creates the gates without the mount or
`--rules` (`status.json` stops reporting `rules`).

The built-in SSRF guard runs before the rules; no rule can widen it.
