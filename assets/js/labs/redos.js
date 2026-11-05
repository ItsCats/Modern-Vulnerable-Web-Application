/* Lab 07 — Regular Expression Denial of Service */
(function () {
  "use strict";
  var M = window.MVWA, $ = M.$, esc = M.escapeHtml;

  var TIMEOUT_MS = 4000;
  var VULN_RE = "^([a-zA-Z0-9_.-]+)+@([a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,}$";
  var SAFE_RE = "^[a-zA-Z0-9_.-]+@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,}$";
  var MEDIUM_MAX = 32, HIGH_MAX = 254;

  // The "server": runs the regex off the main thread so the tab never freezes.
  var WORKER_SRC =
    "self.onmessage = function (e) {" +
    "  var re = new RegExp(e.data.pattern);" +
    "  var t = performance.now();" +
    "  var ok = re.test(e.data.input);" +
    "  self.postMessage({ ok: ok, ms: performance.now() - t });" +
    "};";
  var workerUrl = null;
  try { workerUrl = URL.createObjectURL(new Blob([WORKER_SRC], { type: "text/javascript" })); } catch (e) { /* ignore */ }

  function runRegex(pattern, input) {
    return new Promise(function (resolve) {
      if (!workerUrl || typeof Worker === "undefined") {
        // Fallback (should not happen in modern browsers): refuse rather than freeze the tab.
        resolve({ error: "Web Workers are unavailable in this browser." });
        return;
      }
      var w = new Worker(workerUrl);
      var started = performance.now();
      var timer = setTimeout(function () {
        w.terminate();
        resolve({ timeout: true, ms: performance.now() - started });
      }, TIMEOUT_MS);
      w.onmessage = function (e) { clearTimeout(timer); w.terminate(); resolve(e.data); };
      w.onerror = function (e) { clearTimeout(timer); w.terminate(); resolve({ error: e.message || "Worker error" }); };
      w.postMessage({ pattern: pattern, input: input });
    });
  }

  // Server endpoint for the current level.
  function signup(email, level) {
    if (level === "medium" && email.length > MEDIUM_MAX) return Promise.resolve({ status: 400, error: "Email too long", ms: 0, rejected: true });
    if (level === "high" && email.length > HIGH_MAX) return Promise.resolve({ status: 400, error: "Invalid email", ms: 0, rejected: true });
    return runRegex(level === "high" ? SAFE_RE : VULN_RE, email).then(function (r) {
      if (r.error) return { status: 500, error: r.error, ms: 0 };
      if (r.timeout) return { status: 503, timeout: true, ms: r.ms };
      return { status: r.ok ? 201 : 400, ok: r.ok, ms: r.ms, error: r.ok ? null : "Invalid email" };
    });
  }

  /* ---------------- health widget ---------------- */
  var tick = null;
  function setHealth(state, ms) {
    var badge = $("#health-badge"), meter = $("#health-meter");
    var pct = Math.min(100, ms / TIMEOUT_MS * 100);
    meter.style.width = pct + "%";
    meter.style.backgroundColor = ms > 1000 ? "var(--danger)" : ms > 100 ? "var(--warn)" : "var(--ok)";
    $("#health-ms").textContent = Math.round(ms).toLocaleString() + " ms";
    if (state === "busy") { badge.className = "badge badge-warn"; badge.innerHTML = '<span class="dot"></span>Event loop blocked'; }
    else if (state === "down") { badge.className = "badge badge-danger"; badge.innerHTML = '<span class="dot"></span>Request timed out (503)'; }
    else { badge.className = "badge badge-ok"; badge.innerHTML = '<span class="dot"></span>Event loop idle'; }
  }

  function startTicker() {
    var t0 = performance.now();
    stopTicker();
    tick = setInterval(function () {
      var ms = performance.now() - t0;
      setHealth(ms > 50 ? "busy" : "idle", ms);
      $("#kv-stalled").textContent = Math.floor(ms / 5).toLocaleString();
    }, 50);
  }
  function stopTicker() { if (tick) clearInterval(tick); tick = null; }

  /* ---------------- sign-up form ---------------- */
  var busy = false;
  function setBusy(b) {
    busy = b;
    $("#signup-btn").disabled = b;
    $("#bench-btn").disabled = b;
  }

  $("#signup-form").addEventListener("submit", function (e) {
    e.preventDefault();
    if (busy) return;
    var email = $("#email").value;
    var level = M.getLevel();
    setBusy(true);
    $("#signup-result").innerHTML = '<p class="muted loading-dots" style="margin:0">Waiting for the server</p>';
    startTicker();
    signup(email, level).then(function (r) {
      stopTicker();
      setBusy(false);
      setHealth(r.timeout ? "down" : "idle", r.ms);
      $("#kv-last").textContent = r.timeout ? "> " + TIMEOUT_MS.toLocaleString() + " ms (killed)" : r.ms.toFixed(1) + " ms";
      $("#kv-stalled").textContent = Math.floor(r.ms / 5).toLocaleString();

      var out = $("#signup-result");
      if (r.timeout) {
        out.innerHTML = '<div class="alert alert-danger"><p><strong>503 Service Unavailable</strong> · The request ran for more than ' + TIMEOUT_MS / 1000 + " seconds and was killed. Every other user was locked out meanwhile.</p></div>";
      } else if (r.status === 201) {
        out.innerHTML = '<div class="alert alert-ok"><p><strong>201 Created</strong> · Account created for <span class="mono">' + esc(email) + "</span> in " + r.ms.toFixed(2) + " ms.</p></div>";
      } else {
        var slow = r.ms > 1000;
        out.innerHTML = '<div class="alert ' + (slow ? "alert-danger" : "alert-info") + '"><p><strong>' + r.status + " " + (r.status === 500 ? "Internal Server Error" : "Bad Request") + "</strong> · " + esc(r.error) +
          (r.rejected ? " (rejected before matching)" : " · validated in " + r.ms.toFixed(2) + " ms" + (slow ? ". The server was frozen the whole time." : ".")) + "</p></div>";
      }

      if (level !== "high" && (r.timeout || r.ms > 1000)) {
        M.complete("dos-block");
        if (level === "medium") M.complete("dos-medium");
      }
      if (level !== "high" && r.timeout) M.complete("dos-timeout");
    });
  });

  $("#payload-fill").addEventListener("click", function () {
    var n = Math.max(1, Math.min(60, parseInt($("#payload-n").value, 10) || 26));
    $("#payload-n").value = n;
    $("#email").value = new Array(n + 1).join("a") + "!";
  });

  /* ---------------- benchmark + chart ---------------- */
  var LENGTHS = [16, 18, 20, 22, 24, 26, 28, 29, 30, 31, 32, 33, 34];
  var benchData = [];

  function fmtMs(ms) { return ms >= 1000 ? (ms / 1000).toFixed(2) + " s" : ms.toFixed(ms < 10 ? 2 : 0) + " ms"; }

  function renderChart() {
    var host = $("#chart");
    var tip = $("#chart-tip");
    // Draw at the container's real width so text stays 11px on phones.
    var W = Math.max(300, Math.round(host.clientWidth || 720)), H = W < 480 ? 210 : 240;
    var padL = 40, padR = 8, padT = 18, padB = 30;
    var iw = W - padL - padR, ih = H - padT - padB;
    var max = TIMEOUT_MS;
    var ticks = [0, 1000, 2000, 3000, 4000];
    var band = iw / LENGTHS.length;
    var bw = Math.min(24, band * 0.6);
    var y = function (v) { return padT + ih - Math.min(v, max) / max * ih; };

    var svg = '<svg viewBox="0 0 ' + W + " " + H + '" role="img" aria-label="Bar chart of validation time against input length">';
    svg += '<g class="grid">';
    ticks.forEach(function (t) { svg += '<line x1="' + padL + '" x2="' + (W - padR) + '" y1="' + y(t) + '" y2="' + y(t) + '"/>'; });
    svg += "</g><g class=\"axis\">";
    ticks.forEach(function (t) { svg += '<text x="' + (padL - 8) + '" y="' + (y(t) + 4) + '" text-anchor="end">' + (t / 1000) + " s</text>"; });
    LENGTHS.forEach(function (n, i) { svg += '<text x="' + (padL + band * i + band / 2) + '" y="' + (H - 10) + '" text-anchor="middle">' + n + "</text>"; });
    svg += "</g>";

    var peak = null;
    benchData.forEach(function (d) { if (!d.rejected && (!peak || d.ms > peak.ms)) peak = d; });

    benchData.forEach(function (d) {
      var i = LENGTHS.indexOf(d.n);
      var cx = padL + band * i + band / 2;
      var v = d.rejected ? 0 : d.ms;
      var top = y(v), h = Math.max(0, padT + ih - top);
      var r = Math.min(4, h);
      var x = cx - bw / 2, bottom = padT + ih;
      // Rounded data-end, square at the baseline.
      var path = h > 0
        ? "M" + x + "," + bottom + "V" + (top + r) + "Q" + x + "," + top + " " + (x + r) + "," + top + "H" + (x + bw - r) + "Q" + (x + bw) + "," + top + " " + (x + bw) + "," + (top + r) + "V" + bottom + "Z"
        : "";
      svg += '<rect class="hit" x="' + (padL + band * i) + '" y="' + padT + '" width="' + band + '" height="' + ih + '" data-i="' + i + '"/>';
      if (path) svg += '<path class="bar' + (d.timeout ? " over" : "") + '" d="' + path + '"/>';
      if (d.rejected) svg += '<text class="lbl" x="' + cx + '" y="' + (bottom - 6) + '" text-anchor="middle">–</text>';
      if (d === peak && h > 0) svg += '<text class="val" x="' + cx + '" y="' + (top - 6) + '" text-anchor="middle">' + (d.timeout ? "timeout" : fmtMs(d.ms)) + "</text>";
    });
    svg += "</svg>";
    host.innerHTML = svg;
    host.appendChild(tip);

    M.$$(".hit", host).forEach(function (el) {
      el.addEventListener("mouseenter", function () {
        var n = LENGTHS[Number(el.getAttribute("data-i"))];
        var d = benchData.filter(function (x) { return x.n === n; })[0];
        var rect = host.getBoundingClientRect(), b = el.getBoundingClientRect();
        tip.textContent = "n = " + n + " · " + (!d ? "not run" : d.rejected ? "rejected (too long)" : d.timeout ? "timed out (> 4 s)" : fmtMs(d.ms));
        tip.style.left = (b.left - rect.left + b.width / 2) + "px";
        tip.style.top = (b.top - rect.top + 12) + "px";
        tip.classList.add("show");
      });
      el.addEventListener("mouseleave", function () { tip.classList.remove("show"); });
    });

    $("#bench-table").innerHTML = benchData.length ? benchData.map(function (d) {
      return '<tr><td class="mono">' + d.n + '</td><td class="num">' + (d.rejected ? "—" : d.timeout ? "&gt; 4 s" : fmtMs(d.ms)) + "</td><td>" +
        (d.rejected ? "Rejected (length limit)" : d.timeout ? "Timed out" : "Completed") + "</td></tr>";
    }).join("") : '<tr><td colspan="3" class="muted">Run the benchmark to collect data.</td></tr>';
  }

  $("#bench-btn").addEventListener("click", function () {
    if (busy) return;
    var level = M.getLevel();
    benchData = [];
    renderChart();
    setBusy(true);
    var i = 0, stopped = false;
    function next() {
      if (i >= LENGTHS.length) { setBusy(false); setHealth("idle", 0); return; }
      var n = LENGTHS[i++];
      if (stopped) { next(); return; }
      var input = new Array(n + 1).join("a") + "!";
      signup(input, level).then(function (r) {
        benchData.push({ n: n, ms: r.ms, timeout: !!r.timeout, rejected: !!r.rejected });
        if (r.timeout) stopped = true;  // no point waiting 4 s for every longer input
        renderChart();
        next();
      });
    }
    next();
  });

  renderChart();
  var resizeTimer = null, lastWidth = 0;
  window.addEventListener("resize", function () {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(function () {
      var w = $("#chart").clientWidth;
      if (w !== lastWidth) { lastWidth = w; renderChart(); }
    }, 150);
  });

  M.initLab({
    id: "redos",
    levels: {
      low: "Emails are validated with a pattern containing a nested quantifier, ([a-zA-Z0-9_.-]+)+, on the server's only thread.",
      medium: "Inputs longer than 32 characters are rejected before matching. The vulnerable pattern is unchanged.",
      high: "The pattern has no nested quantifiers and runs in linear time. Inputs are capped at 254 characters."
    },
    hints: [
      '<details class="hint"><summary>Hint: blocking the server</summary><div><p>The payload has to <em>almost</em> match and then fail at the very end. Many local-part characters followed by an invalid one works: try 28 × <code>a</code> followed by <code>!</code>.</p></div></details>',
      '<details class="hint"><summary>Hint: a full outage</summary><div><p>Each extra character roughly doubles the time. Run the benchmark to see the curve, then go a few characters beyond the point where it reaches one second.</p></div></details>',
      '<details class="hint"><summary>Hint: under the length limit</summary><div><p>32 characters is the most Medium accepts. Use all of them: 31 × <code>a</code> plus <code>!</code>.</p></div></details>'
    ].join(""),
    onLevel: function () { benchData = []; renderChart(); }
  });
})();
