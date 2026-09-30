# pi-search template

Private web research with Pi: `web_search` (a per-session SearXNG) and
`web_fetch`, both leaving only through the session's egress provider, which is a
VPN tunnel by default (Tor or direct are one line away).

```sh
glove new pi-search ~/work/research-1 && cd ~/work/research-1
$EDITOR glove-session.yml        # llm + vpn settings (every <set-me>)
glove keychain set <service>     # for each keychain:<service> you referenced
glove check && glove up
```

What `glove up` does, in order: builds the images, starts the egress provider,
SearXNG and the forwarders, then runs the verify checks. For vpn and tor the
session starts only when the exit IP differs from this machine's. Then it
attaches Pi.

OCR (`glove-ocr`, tesseract, ocrmypdf, poppler) comes from the `ocr`
extension, offline in the shell like every tool.
