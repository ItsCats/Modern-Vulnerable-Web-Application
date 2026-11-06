const { test } = require("@playwright/test");
const { openLab, setLevel, expectDone, isDone, expect } = require("./helpers");

const request = async (page, path) => { await page.fill("#api-path", path); await page.click("#api-form button"); };

test.describe("Insecure direct object reference", () => {
  test.beforeEach(async ({ page }) => { await openLab(page, "idor"); });

  test("Low: other customers' invoices and the admin key", async ({ page }) => {
    await setLevel(page, "low");
    await request(page, "/api/users/1043");
    expect(await isDone(page, "idor-invoice")).toBe(false);
    await request(page, "/api/invoices/5003");
    await expectDone(page, "idor-invoice");
    await request(page, "/api/users/1001");
    await expectDone(page, "idor-admin");
  });

  test("Medium: base64 references decode and re-encode", async ({ page }) => {
    await setLevel(page, "medium");
    await page.click('[data-view="5002"]');
    await expect(page.locator("#api-path")).toHaveValue(/aW52b2ljZTo1MDAy/);
    await request(page, "/api/invoices/" + Buffer.from("invoice:5001").toString("base64"));
    await expectDone(page, "idor-medium");
  });

  test("High: foreign objects 404, own objects load", async ({ page }) => {
    await setLevel(page, "high");
    await request(page, "/api/users/1001");
    await expect(page.locator("#api-response")).toContainText("404");
    await page.click('[data-view="5002"]');
    await expect(page.locator("#api-response")).toContainText("200 OK");
  });
});
