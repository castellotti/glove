// glove `playwright` (novnc): keep the page the agent is using in front.
//
// Loaded by the MCP for every page (`browser.initPage` in mcp.json). Headed
// Chromium shows whichever window or tab was raised last: a popup, a tab a
// link opened, or another MCP client's window (each client of an ephemeral
// profile gets its own context, and so its own window) can cover the page the
// agent is still acting on, and the operator watching sees the wrong one. The
// MCP raises a page only when the agent selects it with `browser_tabs`.
//
// Every tab tool starts with `context.ensureTab()` (playwright-core 1.63's
// defineTabTool), and the MCP's Tab is reachable from the page through its
// `tabSymbol` property, set before init pages run. So this wraps that
// context's ensureTab, once, to bring the tab it returns to the front. It only
// raises; it never navigates, clicks or reads the page. If a later MCP version
// moves either internal, it logs once and does nothing. While the operator
// solves a challenge (`glove playwright solve`: glove-pw-capture's `.current`
// exists) it raises nothing, so the agent's next call can't cover their window.
"use strict";

const fs = require("fs");
const CAPTURING = "/tmp/capture/.current";
const WRAPPED = Symbol("glove.front");
let warned = false;

// `.current` is "<id> <pid>" while a recorder runs; a recorder killed outright leaves it
// behind, and its pid may be reused: it counts only while that pid is still the recorder
function capturing() {
  try {
    const pid = Number.parseInt(fs.readFileSync(CAPTURING, "utf8").split(/\s+/)[1], 10);
    return fs.readFileSync(`/proc/${pid}/cmdline`, "latin1").includes("glove-pw-capture");
  } catch {
    return false;
  }
}

exports.default = async ({ page }) => {
  const sym = Object.getOwnPropertySymbols(page).find((s) => s.description === "tabSymbol");
  const context = sym && page[sym] && page[sym].context;
  if (!context || typeof context.ensureTab !== "function") {
    if (!warned) console.error("glove: cannot keep the agent's page in front (MCP internals changed)");
    warned = true;
    return;
  }
  if (context[WRAPPED]) return;
  context[WRAPPED] = true;
  const ensureTab = context.ensureTab.bind(context);
  context.ensureTab = async (...args) => {
    const tab = await ensureTab(...args);
    if (!capturing()) await tab.page.bringToFront().catch(() => {});
    return tab;
  };
};
