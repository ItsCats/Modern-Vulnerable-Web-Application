const { test } = require("@playwright/test");
const { openLab, setLevel, expectDone, isDone, clearObjective, expect } = require("./helpers");

const visit = (page) => page.click("#evil-visit");

test.describe("Cross-site request forgery", () => {
  test.beforeEach(async ({ page }) => { await openLab(page, "csrf"); });

  test("Low: forged POST and zero-click GET", async ({ page }) => {
    await setLevel(page, "low");
    await visit(page);
    await expectDone(page, "csrf-transfer");
    await page.selectOption("#evil-template", "get");
    await visit(page);
    await expectDone(page, "csrf-get");
  });

  test("Forms submit the selected <select> option", async ({ page }) => {
    await setLevel(page, "low");
    await page.fill("#evil-html", '<form action="https://bank.harbor.test/transfer" method="POST"><select name="to"><option value="jordan">J</option><option value="mallory" selected>M</option></select><input type="hidden" name="amount" value="5"></form>');
    await visit(page);
    await expect(page.locator("#req-log")).toContainText("to=mallory&amount=5");
  });

  test("Medium: Referer check blocks the plain attack but not its bypasses", async ({ page }) => {
    await setLevel(page, "medium");
    await visit(page);
    await expect(page.locator("#req-log")).toContainText("403");
    expect(await isDone(page, "csrf-medium")).toBe(false);

    await page.fill("#evil-url", "https://bank.harbor.test.attacker.test/claim");
    await visit(page);
    await expectDone(page, "csrf-medium");

    await clearObjective(page, "csrf-medium");
    await page.fill("#evil-url", "https://prizes.attacker.test/claim");
    await page.selectOption("#evil-template", "noref");
    await visit(page);
    await expectDone(page, "csrf-medium");
  });

  test("High: forged requests fail, the real form still works", async ({ page }) => {
    await setLevel(page, "high");
    const balance = await page.textContent("#balance");
    await visit(page);
    await page.selectOption("#evil-template", "get");
    await visit(page);
    await expect(page.locator("#balance")).toHaveText(balance);
    await page.click("#transfer-form button");
    await expect(page.locator("#balance")).not.toHaveText(balance);
  });
});
