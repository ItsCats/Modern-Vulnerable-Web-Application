// Shared helpers for lab specs.
const { expect } = require("@playwright/test");

/** Open a lab page, fail the test on any uncaught page error, and return the error list. */
async function openLab(page, id, query = "") {
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto(`/labs/${id}.html${query}`);
  await expect(page.locator("#lab-head h1")).toBeVisible();
  return errors;
}

/** Switch the lab's security level using the segmented control. */
async function setLevel(page, level) {
  await page.click(`.segmented button[data-level="${level}"]`);
  await expect(page.locator(`.segmented button[data-level="${level}"]`)).toHaveAttribute("aria-pressed", "true");
}

/** Whether an objective has been recorded as complete. */
async function isDone(page, objectiveId) {
  return page.evaluate((id) => !!window.MVWA.progress.all()[id], objectiveId);
}

/** Assert an objective is (or is not) complete, polling briefly for async labs. */
async function expectDone(page, objectiveId, done = true) {
  await expect.poll(() => isDone(page, objectiveId), { message: `objective ${objectiveId}` }).toBe(done);
}

/** Forget a single objective so it can be earned again in the same test. */
async function clearObjective(page, objectiveId) {
  await page.evaluate((id) => {
    const p = window.MVWA.progress.all();
    delete p[id];
    window.MVWA.store.set("progress", p);
  }, objectiveId);
}

module.exports = { openLab, setLevel, isDone, expectDone, clearObjective, expect };
