/*!
 * Modern Vulnerable Web Application — home page
 *
 * Renders the lab catalogue and progress from the shared registry in core.js.
 */
(function () {
  "use strict";

  var M = window.MVWA;
  if (!M) return;

  var esc = M.escapeHtml;

  var severityClass = M.severityClass;

  function pct(done, total) {
    return total ? Math.round((done / total) * 100) : 0;
  }

  var CHECK = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg>';
  var ARROW = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12h14M13 6l6 6-6 6"/></svg>';

  function labCard(mod, index) {
    var s = M.progress.moduleStats(mod);
    var done = s.total > 0 && s.done === s.total;
    var num = String(index + 1).padStart(2, "0");
    var status = done
      ? '<span class="lab-status done">' + CHECK + "Completed</span>"
      : '<span class="lab-status">' + (s.done > 0 ? "Continue" : "Start lab") + ARROW + "</span>";

    return (
      '<a class="lab-card' + (done ? " done" : "") + '" href="labs/' + esc(mod.id) + '.html">' +
        '<div class="lab-card-top">' +
          '<span class="lab-num">LAB ' + num + "</span>" +
          '<span class="badge ' + severityClass(mod.severity) + '"><span class="dot"></span>' + esc(mod.severity) + "</span>" +
        "</div>" +
        "<h3>" + esc(mod.title) + "</h3>" +
        "<p>" + esc(mod.summary) + "</p>" +
        '<div class="tags">' +
          '<span class="badge">' + esc(mod.owasp) + "</span>" +
          '<span class="badge mono">' + esc(mod.cwe) + "</span>" +
        "</div>" +
        '<div class="lab-card-foot">' +
          '<div class="progress-track" aria-hidden="true"><div class="progress-fill" style="width:' + pct(s.done, s.total) + '%"></div></div>' +
          '<span class="progress-label">' + s.done + "/" + s.total + " objectives</span>" +
          status +
        "</div>" +
      "</a>"
    );
  }

  function contributeCard() {
    return (
      '<a class="lab-card lab-card-extra" href="' + esc(M.REPO_URL) + '" target="_blank" rel="noopener">' +
        '<div class="lab-card-top"><span class="lab-num">CONTRIBUTE</span></div>' +
        "<h3>Add a lab of your own</h3>" +
        "<p>Each lab is a self-contained page plus one entry in the module registry, with a simulated back-end and its vulnerable and fixed code. Ideas and pull requests are welcome.</p>" +
        '<div class="lab-card-foot"><span class="lab-status">View the repository' + ARROW + "</span></div>" +
      "</a>"
    );
  }

  function renderLabs() {
    var grid = document.getElementById("lab-grid");
    if (!grid) return;
    grid.innerHTML = M.MODULES.map(labCard).join("") + contributeCard();
  }

  function renderOverall() {
    var t = M.progress.totals();
    var p = pct(t.done, t.total);
    var label = document.getElementById("overall-label");
    var fill = document.getElementById("overall-fill");
    var track = document.getElementById("overall-track");
    var reset = document.getElementById("reset-progress");
    if (label) label.textContent = t.done + " of " + t.total + " objectives";
    if (fill) fill.style.width = p + "%";
    if (track) {
      track.setAttribute("aria-valuenow", String(p));
      track.setAttribute("aria-valuetext", t.done + " of " + t.total + " objectives complete");
    }
    if (reset) reset.disabled = t.done === 0;
  }

  function renderStats() {
    var t = M.progress.totals();
    var set = function (id, v) { var el = document.getElementById(id); if (el) el.textContent = String(v); };
    set("stat-labs", M.MODULES.length);
    set("stat-objectives", t.total);
    set("stat-levels", M.LEVELS.length);
  }

  function renderAll() {
    renderLabs();
    renderOverall();
  }

  function init() {
    ["repo-link", "repo-link-2"].forEach(function (id) {
      var a = document.getElementById(id);
      if (a && M.REPO_URL) a.href = M.REPO_URL;
    });

    renderStats();
    renderAll();

    var reset = document.getElementById("reset-progress");
    if (reset) {
      reset.addEventListener("click", function () {
        var t = M.progress.totals();
        if (!t.done) return;
        var ok = window.confirm(
          "Reset all progress?\n\nThis clears " + t.done + " completed objective" + (t.done === 1 ? "" : "s") +
          " across every lab. It cannot be undone."
        );
        if (!ok) return;
        M.progress.resetAll();
        M.toast("Progress reset", "All lab objectives have been cleared.");
      });
    }

    M.progress.onChange(renderAll);

    // Keep the page in sync when a lab is completed in another tab.
    window.addEventListener("storage", function (e) {
      if (!e.key || e.key.indexOf("mvwa:progress") === 0) renderAll();
    });
    // Refresh when returning via the back/forward cache.
    window.addEventListener("pageshow", function (e) { if (e.persisted) renderAll(); });
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
