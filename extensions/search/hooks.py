"""`search` extension hooks: render SearXNG's settings for the session.

`materialize()` runs when the session is rendered (`glove plan`/`up`) and
writes `.glove/ext/search/searxng/settings.yml` (bound read-only into the
SearXNG sidecar). It is the v2 pi-search `configure.py`, ported:

* the base settings follow the egress route (`settings/tor.yml` for Tor,
  `settings/default.yml` otherwise);
* engines in an active group are removed (`use_default_settings.engines.remove`),
  and `engines: {name: enable|disable}` overrides win over groups;
* every outgoing request goes through the egress provider's proxy;
* the SearXNG secret key is generated once per session and kept in
  `.glove/ext/search/secret_key` (0600, not mounted anywhere).
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Any

import yaml

SETTINGS = Path(__file__).parent / "settings"

# Engine → categories. A group removes every engine carrying its category.
ENGINE_DB: dict[str, set[str]] = {

    # Google (Alphabet)
    "google":               {"blocks_tor", "security_mode"},
    "google images":        {"blocks_tor", "security_mode"},
    "google news":          {"blocks_tor", "security_mode"},
    "google videos":        {"blocks_tor", "security_mode"},
    "google scholar":       {"blocks_tor", "security_mode"},
    "google play apps":     {"blocks_tor", "security_mode"},
    "google play movies":   {"blocks_tor", "security_mode"},
    "youtube":              {"blocks_tor", "security_mode"},
    "youtube_api":          {"blocks_tor", "security_mode"},

    # Microsoft
    "bing":                 {"blocks_tor", "security_mode"},
    "bing images":          {"blocks_tor", "security_mode"},
    "bing news":            {"blocks_tor", "security_mode"},
    "bing videos":          {"blocks_tor", "security_mode"},
    "azure":                {"security_mode"},
    "github":               {"security_mode"},
    "github code":          {"security_mode"},

    # Yahoo / Verizon / AOL
    "yahoo":                {"blocks_tor", "security_mode"},
    "yahoo news":           {"blocks_tor", "security_mode"},
    "aol":                  {"security_mode"},
    "aol images":           {"security_mode"},
    "aol videos":           {"security_mode"},

    # Russian state-linked platforms
    "yandex":               {"blocks_tor", "security_mode"},
    "yandex images":        {"blocks_tor", "security_mode"},
    "yandex music":         {"security_mode"},

    # Chinese state-linked platforms
    "baidu":                {"blocks_tor", "security_mode"},
    "baidu images":         {"blocks_tor", "security_mode"},
    "baidu kaifa":          {"blocks_tor", "security_mode"},
    "360search":            {"blocks_tor", "security_mode"},
    "360search videos":     {"blocks_tor", "security_mode"},
    "sogou":                {"blocks_tor", "security_mode"},
    "sogou images":         {"blocks_tor", "security_mode"},
    "sogou videos":         {"blocks_tor", "security_mode"},
    "sogou wechat":         {"blocks_tor", "security_mode"},
    "bilibili":             {"security_mode"},
    "naver":                {"security_mode"},
    "naver images":         {"security_mode"},
    "naver news":           {"security_mode"},
    "naver videos":         {"security_mode"},

    # Other data-harvesting / ToS-permitting platforms
    "startpage":            {"security_mode"},
    "startpage images":     {"security_mode"},
    "startpage news":       {"security_mode"},
    "reddit":               {"security_mode"},
    "ebay":                 {"security_mode"},
    "dailymotion":          {"security_mode"},
    "flickr":               {"security_mode"},
    "flickr_api":           {"security_mode"},
    "pinterest":            {"security_mode"},
    "cloudflareai":         {"security_mode"},
    "deviantart":           {"security_mode"},

    # Requires paid/registered API key
    "wolframalpha":         {"requires_license"},
    "wolframalpha_api":     {"requires_license"},

    # Consistently blocks Tor exits
    "karmasearch":          {"blocks_tor"},
    "karmasearch images":   {"blocks_tor"},
    "karmasearch videos":   {"blocks_tor"},

    # Phones home at startup
    "wikidata":             {"phones_home", "blocks_tor"},

    # Clean engines — no category; no group will target these
    "duckduckgo":           set(),
    "duckduckgo images":    set(),
    "duckduckgo news":      set(),
    "duckduckgo videos":    set(),
    "duckduckgo weather":   set(),
    "brave":                set(),
    "brave.images":         set(),
    "brave.news":           set(),
    "brave.videos":         set(),
    "wikipedia":            set(),
    "wikibooks":            set(),
    "wikisource":           set(),
    "wikiquote":            set(),
    "wikinews":             set(),
    "wikimini":             set(),
    "wikicommons.images":   set(),
    "wikicommons.files":    set(),
    "wikispecies":          set(),
    "wikiversity":          set(),
    "wikivoyage":           set(),
    "wiktionary":           set(),
    "stackoverflow":        set(),
    "stackexchange":        set(),
    "superuser":            set(),
    "askubuntu":            set(),
    "serverfault":          set(),
    "openverse":            set(),
    "openstreetmap":        set(),
    "photon":               set(),
    "gitlab":               set(),
    "codeberg":             set(),
    "hackernews":           set(),
    "lobste.rs":            set(),
    "qwant":                set(),
    "qwant images":         set(),
    "qwant news":           set(),
    "qwant videos":         set(),
    "mojeek":               set(),
    "mojeek images":        set(),
    "mojeek news":          set(),
    "wiby":                 set(),
    "marginalia":           set(),
    "mwmbl":                set(),
    "pubmed":               set(),
    "arxiv":                set(),
    "semantic scholar":     set(),
    "crossref":             set(),
    "openalex":             set(),
    "base":                 set(),
    "core.ac.uk":           set(),
    "annas archive":        set(),
    "library genesis":      set(),
    "library of congress":  set(),
    "peertube":             set(),
    "vimeo":                set(),
    "piped":                set(),
    "odysee":               set(),
    "mastodon users":       set(),
    "mastodon hashtags":    set(),
    "tootfinder":           set(),
    "lemmy posts":          set(),
    "lemmy users":          set(),
    "lemmy communities":    set(),
    "lemmy comments":       set(),
    "lingva":               set(),
    "libretranslate":       set(),
    "openmeteo":            set(),
    "national vulnerability database": set(),
    "arch linux wiki":      set(),
    "nixos wiki":           set(),
    "mdn":                  set(),
    "docker hub":           set(),
    "pypi":                 set(),
    "npm":                  set(),
    "crates.io":            set(),
    "pkg.go.dev":           set(),
    "rubygems":             set(),
    "hex":                  set(),
    "repology":             set(),
}

GROUPS = ("blocks_tor", "requires_license", "phones_home", "security_mode")


class SearchError(ValueError):
    pass


def remove_list(groups: dict[str, Any], engines: dict[str, Any]) -> list[str]:
    """Engines to remove. Precedence: `disable` > `enable` > group rules."""
    unknown = sorted(set(groups) - set(GROUPS))
    if unknown:
        raise SearchError(f"search.groups: unknown group(s) {unknown} (known: {list(GROUPS)})")
    for name, v in engines.items():
        if str(v).lower() not in ("enable", "disable"):
            raise SearchError(f"search.engines.{name} must be enable|disable, got {v!r}")
    active = {g for g, on in groups.items() if on}
    remove = {e for e, cats in ENGINE_DB.items() if cats & active}
    remove |= {n.lower() for n, v in engines.items() if str(v).lower() == "disable"}
    remove -= {n.lower() for n, v in engines.items() if str(v).lower() == "enable"}
    return sorted(remove)


def settings_doc(ctx: dict[str, Any], secret_key: str) -> dict[str, Any]:
    s = ctx["settings"]
    egress = ctx["slot"].get("egress") or {}
    route = egress.get("route")
    if not egress.get("proxy_url"):
        raise SearchError("search needs an egress provider (vpn, tor or direct)")
    base = yaml.safe_load((SETTINGS / ("tor.yml" if route == "tor" else "default.yml")).read_text()) or {}
    remove = remove_list(dict(s.get("groups") or {}), dict(s.get("engines") or {}))
    doc: dict[str, Any] = {"use_default_settings": {"engines": {"remove": remove}} if remove else True}
    doc.update(base)
    doc.setdefault("server", {})["secret_key"] = secret_key
    doc["valkey"] = {"url": f"valkey://glove-{ctx['session']['id']}-valkey:6379/0"}
    # using_tor_proxy stays off even for Tor: SearXNG accepts it only with
    # socks5h:// proxies, and every consumer here uses the one HTTP proxy_url
    # (privoxy for Tor). tor.yml carries the longer timeouts instead.
    doc["outgoing"] = {**(doc.get("outgoing") or {}), "proxies": {"all://": [egress["proxy_url"]]},
                       "using_tor_proxy": False}
    return doc


def contribute(ctx: dict[str, Any]) -> dict[str, Any]:
    s = ctx["settings"]
    remove_list(dict(s.get("groups") or {}), dict(s.get("engines") or {}))  # validate at plan time
    return {}


def materialize(ctx: dict[str, Any]) -> None:
    state = Path(ctx["state_dir"])
    key_file = state / "secret_key"
    if not key_file.exists():
        fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secrets.token_hex(32))
    out = state / "searxng"
    out.mkdir(exist_ok=True)
    doc = settings_doc(ctx, key_file.read_text().strip())
    (out / "settings.yml").write_text("# Generated by glove (search extension) — edit glove-session.yml instead.\n"
                                      + yaml.safe_dump(doc, sort_keys=False))
