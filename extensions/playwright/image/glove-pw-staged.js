// glove `playwright`: a download is on disk once, not twice.
//
// Required into the MCP's process (glove-pw-start). Chromium stages a download
// in /data/staging (hooks.py STAGING) and the MCP saves it with
// fs.promises.copyFile (playwright-core 1.63 saveAs; separate binds, so never a
// rename); Playwright deletes the staged file only when the context closes,
// which for a shared context is when the sidecar stops. This deletes it once
// its copy is complete (a failed copy keeps it; Playwright's own unlink ignores
// a missing file). Saving the same download twice (browser_run_code_unsafe)
// now fails. The Dockerfile checks the pinned playwright-core still calls copyFile.
"use strict";

const fs = require("fs");

// PW_STAGING: set only by the tests (tests/test_sidecar_modes.py)
const STAGING = (process.env.PW_STAGING || "/data/staging").replace(/\/*$/, "/");
const copyFile = fs.promises.copyFile;

fs.promises.copyFile = async function (from, ...rest) {
  await copyFile.call(this, from, ...rest);
  if (String(from).startsWith(STAGING)) await fs.promises.unlink(from).catch(() => {});
};
