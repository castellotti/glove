# keychain

A library extension, never selected on its own. It owns `glove keychain set`
and the code that **writes** a `keychain:<service>` secret. `playwright`
(`glove playwright login`) and `skills` (`glove skills refresh`) import it, and
require it when they store one (`login:`, a plugin `relay:`), so it is then
added automatically. It renders nothing.

**Reading** a reference stays in core (`glove.api.resolve_secret`,
`secret_exists`): every launch resolves secrets, in memory, wherever they were
written from.

## One reference, the OS's credential store

`keychain:<service>` means "this host's credential store", so a session file
works unchanged on macOS and Linux:

| host | store | tool | item |
|---|---|---|---|
| macOS | the login Keychain | `security` | a generic password, service `<service>`, account `$USER` |
| Linux with a desktop session (Ubuntu: GNOME Keyring; KWallet) | the Secret Service, over D-Bus | `secret-tool` (package `libsecret-tools`) | attributes `application=glove service=<service>`, label `glove: <service>` |
| Linux without a Secret Service (a server, SSH) | none | `secret-tool` fails | glove shows its reason; use `env:<VAR>` |

There is no fallback to a file: a secret is never written to disk by glove.

## Writing: never in argv

- **Prompted** (`glove keychain set <service>`): the tool asks, with no echo
  (`security … -w` as the last option; `secret-tool store` on a terminal).
  Only on a terminal: piped, `secret-tool` would store what it reads, cut at
  8 KB; use `--stdin`.
- **Given** (`--stdin`, `glove playwright login`, `glove skills refresh`): one
  line, on the tool's stdin. Each tool takes a bounded value per write:
  - macOS: `security -i` reads one command line of at most ~4 KB and runs the
    overflow as commands of its own, echoing them (the secret's tail
    included). ASCII only (`security -w` prints anything else hex-encoded).
  - Linux: `secret-tool store` keeps the first 8 KB of stdin, prints "password
    is too long" and **exits 0** (libsecret 0.21.4, Ubuntu 24.04): a signed-in
    browser state would be stored cut off.

  So a longer value is stored in parts (`<service>.part<n>`, each within the
  tool's limit) under a head `glove-parts:<n>:<sha256>`. Core joins them when
  reading and refuses a set whose hash doesn't match; a shorter value stored
  later deletes the old parts.

## Checking without reading

`glove check` asks whether each `keychain:` item exists. On macOS that reads
only the item's attributes (no decrypt, no prompt). `secret-tool` has no such
lookup, so on Linux it reads the secret and discards it; a locked collection
may raise an unlock prompt.

## Status

macOS: in use. Linux (`secret-tool`): unit tests, and an Ubuntu container with
`dbus-run-session` and an unlocked `gnome-keyring-daemon`
(`tests/integration/test_keychain_linux.sh`); **untested** on a real Ubuntu
desktop.
