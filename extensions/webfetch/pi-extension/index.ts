/**
 * web_fetch — retrieve a full web page as readable text, routed through the
 * session's egress proxy (glove `webfetch` extension; GLOVE_FETCH_PROXY).
 *
 * Runs inside the Pi harness process. The proxy is attached PER REQUEST via
 * undici's `dispatcher` option, never with setGlobalDispatcher() — a global
 * dispatcher would hijack all Node traffic including LLM requests.
 */
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { fetch, ProxyAgent } from "undici";
import { convert } from "html-to-text";
import http from "node:http";
import { refusal } from "./guard.ts";

const PROXY = process.env.GLOVE_FETCH_PROXY ?? "";
const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

const dispatcher = PROXY ? new ProxyAgent(PROXY) : undefined;

/** The egress gate's refusal text if it answers a CONNECT for `url` with 403, else null. */
function tunnelRefusal(url: URL): Promise<string | null> {
  if (!PROXY) return Promise.resolve(null);
  const proxy = new URL(PROXY);
  const port = url.port || (url.protocol === "https:" ? "443" : "80");
  return new Promise((resolve) => {
    const req = http.request({ host: proxy.hostname, port: proxy.port, method: "CONNECT",
                               path: `${url.hostname}:${port}`, timeout: 15000 });
    req.on("connect", (res, socket, head) => {
      socket.destroy();
      resolve(res.statusCode === 403 ? (head.toString("utf-8").trim() || "refused (403)") : null);
    });
    req.on("response", (res) => {
      let body = "";
      res.on("data", (c) => (body += c));
      res.on("end", () => resolve(res.statusCode === 403 ? body.trim() || "refused (403)" : null));
    });
    req.on("timeout", () => { req.destroy(); resolve(null); });
    req.on("error", () => resolve(null));
    req.end();
  });
}

function policyRefusal(url: URL, why: string) {
  return { content: [{ type: "text" as const, text:
    `Refused by this session's network policy for ${url}: ${why}. Do not retry or look for another ` +
    `route; tell the user if you need this source.` }], details: {} };
}

export default function (pi: ExtensionAPI) {
  pi.registerTool({
    name: "web_fetch",
    label: "Web Fetch",
    description:
      "Fetch a URL and return its main text content (HTML converted to " +
      "readable text). Routed through the session's egress proxy. Use this " +
      "for reading a specific page found via web_search. For JavaScript-heavy " +
      "pages that render nothing useful here, ask the operator about the browser tools.",
    promptSnippet: "Fetch and read the text of a specific web page",
    promptGuidelines: [
      "Use web_fetch to read a page's content after finding its URL with web_search.",
      "It returns readable text, not rendered JS. If a page needs JS, say so and ask before using browser_ tools.",
      "Shares one exit IP — do not hammer it; on a rate-limit error, back off, do not retry immediately.",
    ],
    parameters: Type.Object({
      url: Type.String({ description: "Absolute http(s) URL to fetch" }),
      max_chars: Type.Optional(
        Type.Number({ description: "Truncate output to this many characters (default 20000)" }),
      ),
      raw: Type.Optional(
        Type.Boolean({ description: "Return raw HTML instead of converted text (default false)" }),
      ),
    }),

    async execute(_toolCallId: string, p: any, signal?: AbortSignal) {
      if (!dispatcher) {
        return {
          content: [{ type: "text", text:
            "web_fetch is not configured: GLOVE_FETCH_PROXY is unset, so there is no " +
            "egress path. Refusing to fetch directly." }],
          details: {},
        };
      }
      let url: URL;
      try {
        url = new URL(p.url);
      } catch {
        return { content: [{ type: "text", text: `Invalid URL: ${p.url}` }], details: {} };
      }
      const first = refusal(url);
      if (first) {
        return { content: [{ type: "text", text: `Refused: ${first}. web_fetch reads public web pages only.` }],
                 details: {} };
      }

      const maxChars = p.max_chars ?? 20000;
      const timeout = AbortSignal.timeout(45000);
      const abort = signal ? AbortSignal.any([signal, timeout]) : timeout;

      let res: Awaited<ReturnType<typeof fetch>>;
      try {
        // Follow redirects by hand so every hop passes the destination guard.
        for (let hop = 0; ; hop++) {
          res = await fetch(url.toString(), {
            dispatcher,
            signal: abort,
            redirect: "manual",
            headers: { "User-Agent": UA, Accept: "text/html,application/xhtml+xml,*/*;q=0.8" },
          });
          const loc = res.headers.get("location");
          if (res.status < 300 || res.status >= 400 || !loc) break;
          if (hop >= 5) {
            return { content: [{ type: "text", text: `Too many redirects from ${p.url}` }], details: {} };
          }
          const next = new URL(loc, url);
          const why = refusal(next);
          if (why) {
            return { content: [{ type: "text", text: `Refused a redirect to ${next}: ${why}.` }], details: {} };
          }
          await res.body?.cancel();
          url = next;
        }
      } catch (err: any) {
        if (err?.name === "AbortError") throw err;
        const cause = err?.cause?.code || err?.cause?.message || err?.message || "unknown";
        // undici does not say why a tunnel failed; ask the proxy once. A 403 is a
        // policy decision (a filter rule, the corporate allowlist, the SSRF
        // guard), not a network failure.
        const refused = await tunnelRefusal(url);
        if (refused !== null) return policyRefusal(url, refused);
        return {
          content: [{ type: "text", text:
            `Fetch failed for this URL (${cause}). This is a per-request failure, not ` +
            `necessarily an egress outage. Over Tor many sites block exit-node traffic — ` +
            `retry once or try a different source. If web_search is also failing, the ` +
            `egress itself may be down.` }],
          details: {},
        };
      }

      if (res.status === 429) {
        return { content: [{ type: "text", text:
          "Rate-limited (HTTP 429). Back off; do not retry immediately." }], details: {} };
      }
      if (!res.ok) {
        if (res.status === 403 && res.headers.get("content-type")?.startsWith("text/plain")) {
          const text = await res.text();
          if (text.startsWith("glove netgate refused")) return policyRefusal(url, text.trim());
        }
        return { content: [{ type: "text", text: `HTTP ${res.status} for ${url}` }], details: {} };
      }

      const ctype = res.headers.get("content-type") ?? "";

      const MAX_BODY = 5 * 1024 * 1024;
      let body: string;
      if (!res.body) {
        body = "";
      } else {
        const chunks: Buffer[] = [];
        let bytes = 0;
        for await (const chunk of res.body as AsyncIterable<Uint8Array>) {
          chunks.push(Buffer.from(chunk));
          bytes += chunk.byteLength;
          if (bytes >= MAX_BODY) break;
        }
        body = Buffer.concat(chunks, Math.min(bytes, MAX_BODY)).toString("utf-8");
      }

      const isHtml = /html|xml/i.test(ctype);
      let out: string;
      if (p.raw) {
        out = body;
      } else if (!isHtml) {
        out = `[content-type: ${ctype || "unknown"}]\n\n` + body;
      } else {
        out = convert(body, {
          wordwrap: false,
          selectors: [
            { selector: "img", format: "skip" },
            { selector: "script", format: "skip" },
            { selector: "style", format: "skip" },
            { selector: "nav", format: "skip" },
            { selector: "a", options: { ignoreHref: true } },
          ],
        });
      }

      const finalUrl = url.toString();
      let text = out.trim();
      let footer = `\n\n[fetched: ${finalUrl} | ${ctype.split(";")[0] || "?"} | via egress]`;
      if (text.length > maxChars) {
        text = text.slice(0, maxChars);
        footer = `\n\n[truncated to ${maxChars} chars]` + footer;
      }
      return { content: [{ type: "text", text: text + footer }], details: { url: finalUrl } };
    },
  });
}
