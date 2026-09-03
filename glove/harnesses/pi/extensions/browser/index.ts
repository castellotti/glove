/**
 * glove-pi-browser — gives Pi the same browser as Vibe.
 *
 * Pi has no MCP client, so this extension IS one: it connects to the Playwright
 * MCP server (the `browser` forwarder sidecar → host Playwright → shared Chrome
 * via CDP) and re-exposes its tools as native Pi tools. MCP result content maps
 * 1:1 to Pi content, so image blocks (screenshots) flow straight into Pi's
 * vision, and screenshots also land in the host --output-dir (research/<coll>/media).
 *
 * BROWSER_MCP_URL is injected by glove from the browser sidecar. One persistent
 * MCP client is kept for the whole session, so the browser context/page is
 * stable across tool calls.
 */
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const BROWSER_MCP_URL = process.env.BROWSER_MCP_URL ?? "http://localhost:8931/mcp";

// Curated surface — the tools the media crawl needs. Others from the server are
// ignored to keep Pi's tool list focused.
const ALLOW = new Set([
  "browser_navigate",
  "browser_navigate_back",
  "browser_snapshot",
  "browser_take_screenshot",
  "browser_click",
  "browser_type",
  "browser_hover",
  "browser_select_option",
  "browser_press_key",
  "browser_wait_for",
]);

function mapContent(blocks: any[]): any[] {
  const out = (blocks ?? []).map((c) =>
    c?.type === "image"
      ? { type: "image", data: c.data, mimeType: c.mimeType ?? "image/png" }
      : { type: "text", text: typeof c?.text === "string" ? c.text : "" },
  );
  return out.length ? out : [{ type: "text", text: "(no content)" }];
}

export default async function (pi: ExtensionAPI) {
  const client = new Client({ name: "glove-pi-browser", version: "0.1.0" });

  try {
    await client.connect(new StreamableHTTPClientTransport(new URL(BROWSER_MCP_URL)));
  } catch (err: any) {
    // Browser not reachable — register a diagnostic so Pi still starts cleanly.
    pi.registerTool({
      name: "browser_status",
      label: "Browser status",
      description: "Reports why the browser is unavailable.",
      parameters: { type: "object", properties: {} } as any,
      async execute() {
        return {
          content: [{
            type: "text",
            text: `Browser MCP unreachable at ${BROWSER_MCP_URL} (${err?.message}). ` +
              `Ensure glove started the chrome + playwright host services.`,
          }],
          details: {},
        };
      },
    });
    return;
  }

  const { tools } = await client.listTools();
  for (const t of tools) {
    if (ALLOW.size && !ALLOW.has(t.name)) continue;
    pi.registerTool({
      name: t.name,
      label: t.name,
      description: t.description ?? `Browser tool ${t.name} (via Playwright MCP)`,
      // MCP inputSchema is JSON Schema, which Pi accepts as tool parameters.
      parameters: (t.inputSchema ?? { type: "object", properties: {} }) as any,
      async execute(_toolCallId: string, args: any) {
        try {
          const res: any = await client.callTool({ name: t.name, arguments: args ?? {} });
          return { content: mapContent(res?.content), details: {} };
        } catch (err: any) {
          return {
            content: [{ type: "text", text: `browser tool ${t.name} failed: ${err?.message}` }],
            details: {},
          };
        }
      },
    });
  }
}
