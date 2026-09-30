/**
 * glove-pi-searxng — web_search via a private SearXNG instance.
 *
 * Baked into the glove/pi image and loaded with `pi -e`. SEARXNG_URL is injected
 * by glove and points at the `search` forwarder sidecar
 * (glove-<session>-search:8080). The extension only ever talks to that endpoint.
 */
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

const SEARXNG_URL = process.env.SEARXNG_URL ?? "http://localhost:8080";

export default function (pi: ExtensionAPI) {
  pi.registerTool({
    name: "web_search",
    label: "Web Search",
    description:
      "Search the web using a private SearXNG metasearch engine. " +
      "Returns titles, URLs, and content snippets.",
    promptSnippet: "Search the web for current information, documentation, or references",
    promptGuidelines: [
      "Use web_search to find up-to-date information from the web.",
      "After finding URLs, use the browser_ tools to open pages.",
      "SearXNG shares one exit IP — do not hammer it; on a rate-limit error, back off.",
    ],
    parameters: Type.Object({
      query: Type.String({ description: "Search query" }),
      categories: Type.Optional(Type.String({
        description: "Comma-separated categories: general, news, science, images, videos, it",
      })),
      time_range: Type.Optional(Type.String({ description: "day, month, or year" })),
      language: Type.Optional(Type.String({ description: "Language code, e.g. 'en'" })),
      max_results: Type.Optional(Type.Number({ description: "Max results (default 10)" })),
    }),

    async execute(_toolCallId: string, p: any, signal?: AbortSignal) {
      const maxResults = p.max_results ?? 10;
      const url = new URL(`${SEARXNG_URL}/search`);
      url.searchParams.set("q", p.query);
      url.searchParams.set("format", "json");
      if (p.categories) url.searchParams.set("categories", p.categories);
      if (p.time_range) url.searchParams.set("time_range", p.time_range);
      if (p.language) url.searchParams.set("language", p.language);

      let data: any;
      try {
        const res = await fetch(url.toString(), { signal });
        if (res.status === 429) {
          return {
            content: [{ type: "text", text: "SearXNG rate-limited (429). Back off; do not retry immediately." }],
            details: {},
          };
        }
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        data = await res.json();
      } catch (err: any) {
        if (err?.name === "AbortError") throw err;
        return {
          content: [{ type: "text", text: `SearXNG unreachable at ${SEARXNG_URL} (${err?.message}).` }],
          details: {},
        };
      }

      const results = (data.results ?? []).slice(0, maxResults);
      if (results.length === 0) {
        return { content: [{ type: "text", text: `No results for: ${p.query}` }], details: {} };
      }
      const formatted = results
        .map((r: any, i: number) => `${i + 1}. ${r.title}\n   URL: ${r.url}\n   ${r.content ?? ""}`)
        .join("\n\n");
      const engines = [...new Set(results.map((r: any) => r.engine).filter(Boolean))];
      const footer = `\n\n[Sources: ${engines.join(", ")} | ${results.length} shown]`;
      return { content: [{ type: "text", text: formatted + footer }], details: {} };
    },
  });
}
