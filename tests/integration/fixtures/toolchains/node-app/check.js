// Resolves a dependency and launches the baked Chromium, offline.
const isNumber = require("is-number");
const { chromium } = require("playwright");
(async () => {
  const browser = await chromium.launch({ chromiumSandbox: false });
  const page = await browser.newPage();
  await page.setContent("<title>glove-offline</title>");
  console.log(`is-number=${isNumber(42)} title=${await page.title()}`);
  await browser.close();
})().catch((e) => { console.error(e); process.exit(1); });
