// Site-wide checks: every registered lab has a working page, nothing overflows on phones.
const { test, expect } = require("@playwright/test");

async function registry(page) {
  await page.goto("/index.html");
  return page.evaluate(() => window.MVWA.MODULES.map((m) => ({ id: m.id, objectives: m.objectives.length })));
}

test("Landing page lists every lab with its objectives", async ({ page }) => {
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  const mods = await registry(page);
  for (const m of mods) await expect(page.locator(`a[href="labs/${m.id}.html"]`).first()).toBeVisible();
  const total = mods.reduce((n, m) => n + m.objectives, 0);
  await expect(page.locator("body")).toContainText(String(total));
  expect(errors).toEqual([]);
});

test("Every lab page loads cleanly and fits a 360px screen", async ({ browser }) => {
  const ctx = await browser.newContext({ viewport: { width: 360, height: 780 } });
  const page = await ctx.newPage();
  const errors = [];
  page.on("pageerror", (e) => errors.push(page.url() + ": " + e.message));
  const mods = await registry(page);
  for (const path of ["/index.html", ...mods.map((m) => `/labs/${m.id}.html`)]) {
    await page.goto(path);
    await page.waitForLoadState("load");
    const width = await page.evaluate(() => document.documentElement.scrollWidth);
    expect(width, `${path} horizontal overflow`).toBeLessThanOrEqual(360);
    if (path !== "/index.html") {
      for (const level of ["low", "medium", "high"]) {
        await page.click(`.segmented button[data-level="${level}"]`);
        await expect(page.locator(`[data-show-level~="${level}"]`).first()).toBeVisible();
      }
    }
  }
  expect(errors).toEqual([]);
  await ctx.close();
});
