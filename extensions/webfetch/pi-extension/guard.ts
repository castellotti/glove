/**
 * Destination guard for web_fetch: refuse anything that is not plainly a
 * public internet host, before the request reaches the egress proxy. The
 * `direct` egress proxy sits on an ordinary bridge, so without this a fetch
 * could reach this machine (host.docker.internal) or its LAN; the tunnelled
 * providers are covered by their own policies (Tor exits, gluetun's kill
 * switch), and this is defence in depth there.
 *
 * Judged by shape only, never resolved (resolving would leak the name). A
 * public-looking name that resolves to a private address is not caught here;
 * the proxy's own filter is the backstop. Checked on every redirect hop.
 */
import { isIP } from "node:net";

const LOCAL_SUFFIXES = [".localhost", ".local", ".internal", ".lan", ".home.arpa", ".intranet", ".corp"];

function v4(ip: string): number[] {
  return ip.split(".").map(Number);
}

function publicV4(ip: string): boolean {
  const [a, b, c] = v4(ip);
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 100 && b >= 64 && b <= 127) return false; // CGNAT
  if (a === 169 && b === 254) return false; // link-local, cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 192 && b === 0 && (c === 0 || c === 2)) return false;
  if (a === 198 && (b === 18 || b === 19)) return false;
  if (a === 198 && b === 51 && c === 100) return false;
  if (a === 203 && b === 0 && c === 113) return false;
  return true;
}

function publicV6(ip: string): boolean {
  const h = ip.toLowerCase();
  const mapped = h.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return publicV4(mapped[1]);
  if (h === "::" || h === "::1") return false;
  if (/^(fc|fd)/.test(h) || /^fe[89ab]/.test(h) || /^ff/.test(h)) return false;
  if (h.startsWith("::ffff:") || h.startsWith("64:ff9b:") || h.startsWith("2001:db8:")) return false;
  return true;
}

/** Why `url` must not be fetched, or null when it may be. */
export function refusal(url: URL): string | null {
  if (url.protocol !== "http:" && url.protocol !== "https:") return "not an http(s) URL";
  if (url.username || url.password) return "URLs with credentials are not fetched";
  const host = url.hostname.replace(/^\[|\]$/g, "").toLowerCase().replace(/\.$/, "");
  const kind = isIP(host);
  if (kind === 4) return publicV4(host) ? null : `${host} is not a public address`;
  if (kind === 6) return publicV6(host) ? null : `${host} is not a public address`;
  if (!host.includes(".")) return `${host} is a local (single-label) name`;
  if (host === "localhost" || LOCAL_SUFFIXES.some((s) => host.endsWith(s))) return `${host} is a local name`;
  return null;
}
