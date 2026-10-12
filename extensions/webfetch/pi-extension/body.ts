/**
 * What web_fetch makes of a response it won't read as text: binary bodies and
 * rate limits. No dependencies; webfetch_mcp.py has the same rules (a test
 * runs both on the same cases).
 */

/** Bytes of the body read to look for NUL before deciding. */
export const SNIFF = 4096;

const TEXT = new RegExp("^(text/.+|[^/]+/([^/]+\\+)?(json|xml|yaml)|" +
  "application/(x-)?(javascript|ecmascript|yaml|toml|ndjson|sql|graphql|sh|shellscript))$");
const UNKNOWN = ["", "application/octet-stream", "binary/octet-stream"];

/** Whether a response is binary: by its content type, or for a text or
 *  unlabelled one by a NUL in the first SNIFF bytes of `head`. */
export function isBinary(ctype: string, head: Uint8Array): boolean {
  const mime = ctype.split(";")[0].trim().toLowerCase();
  if (!UNKNOWN.includes(mime) && !TEXT.test(mime)) return true;
  return head.subarray(0, SNIFF).includes(0);
}

/** The agent's text for a binary response (`length`: Content-Length, else the
 *  bytes read, as a lower bound). */
export function binaryNotice(tool: string, url: string, ctype: string, length: string | null, read: number,
                             canDownload: boolean): string {
  const size = length && /^\d+$/.test(length) ? `${length} bytes` : read ? `≥${read} bytes` : "size unknown";
  return `[binary: ${ctype.split(";")[0].trim() || "unknown type"}, ${size}] ${url}\n` +
    `${tool} returns text only. ` +
    (canDownload
      ? "Use web_download to save the file, then open it with a shell tool the session has " +
        "(e.g. pdftotext, 7z)."
      : "This session has no web_download: ask the operator to provide this file.");
}

/** The agent's text for a 429, with the server's Retry-After (seconds or an
 *  HTTP date) when it sent one. */
export function rateLimited(retryAfter: string | null, now: number = Date.now()): string {
  const v = (retryAfter ?? "").trim();
  // a date counts only in RFC 9110's one form (IMF-fixdate), as it reads back
  // (Date.parse also takes other forms, and rolls 31 Feb over)
  const date = /^\d+$/.test(v) ? NaN : Date.parse(v);
  const s = /^\d+$/.test(v) ? Number(v)
    : !isNaN(date) && new Date(date).toUTCString() === v ? Math.round((date - now) / 1000) : NaN;
  return "Rate-limited (HTTP 429). Back off; " +
    (Number.isFinite(s) ? `the server asks to wait ${Math.max(0, s)} s before retrying.` : "do not retry immediately.");
}
