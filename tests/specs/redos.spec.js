const { test } = require("@playwright/test");
const { openLab, setLevel, expectDone, expect } = require("./helpers");

async function submit(page, email) {
  await page.fill("#email", email);
  await page.click("#signup-btn");
  await expect(page.locator("#signup-btn")).toBeEnabled({ timeout: 20_000 });
  return page.textContent("#signup-result");
}

test.describe("ReDoS", () => {
  test.beforeEach(async ({ page }) => { await openLab(page, "redos"); });

  test("Low: a long near-match blocks and then times out", async ({ page }) => {
    await setLevel(page, "low");
    await submit(page, "a".repeat(30) + "!");
    await expectDone(page, "dos-block");
    expect(await submit(page, "a".repeat(36) + "!")).toContain("503");
    await expectDone(page, "dos-timeout");
  });

  test("Medium: the length limit still allows a multi-second stall", async ({ page }) => {
    await setLevel(page, "medium");
    expect(await submit(page, "a".repeat(40) + "!")).toContain("too long");
    await submit(page, "a".repeat(31) + "!");
    await expectDone(page, "dos-medium");
  });

  test("High: linear-time pattern validates instantly", async ({ page }) => {
    await setLevel(page, "high");
    const res = await submit(page, "a".repeat(200) + "!");
    const ms = Number(/validated in ([\d.]+) ms/.exec(res)[1]);
    expect(ms).toBeLessThan(50);
    expect(await submit(page, "alex@example.com")).toContain("201");
  });

  test("Benchmark draws the chart", async ({ page }) => {
    await setLevel(page, "low");
    await page.click("#bench-btn");
    await expect(page.locator("#bench-btn")).toBeEnabled({ timeout: 90_000 });
    expect(await page.locator("#chart .bar").count()).toBeGreaterThanOrEqual(8);
  });
});
