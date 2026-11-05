/*!
 * Modern Vulnerable Web Application — core runtime
 *
 * Shared by every page: module registry, header / footer / sidebar rendering,
 * the security-level switch, objective tracking (localStorage), toasts and
 * small helpers. Written as a classic script (no modules, no build step) so the
 * site also works when opened straight from the file system.
 */
(function () {
  "use strict";

  var REPO_URL = "https://github.com/ItsCats/Modern-Vulnerable-Web-Application";
  var STORE_PREFIX = "mvwa:";

  /* ------------------------------------------------------------------------
   * Module registry — the single source of truth for labs and objectives.
   * --------------------------------------------------------------------- */
  var MODULES = [
    {
      id: "sql-injection",
      title: "SQL Injection",
      short: "SQLi",
      owasp: "A05:2025 Injection",
      cwe: "CWE-89",
      severity: "Critical",
      summary:
        "Bypass authentication and dump a real SQLite database (compiled to WebAssembly) through string-concatenated queries.",
      objectives: [
        { id: "sqli-login", label: "Log in as admin without knowing the password", detail: "Authentication bypass" },
        { id: "sqli-union", label: "Dump every username and password with a UNION query", detail: "Data exfiltration" },
        { id: "sqli-flag", label: "Discover the hidden table and read its flag", detail: "Schema enumeration via sqlite_master" },
        { id: "sqli-medium", label: "Defeat the keyword blocklist on Medium", detail: "Filter evasion" }
      ]
    },
    {
      id: "xss",
      title: "Cross-Site Scripting",
      short: "XSS",
      owasp: "A05:2025 Injection",
      cwe: "CWE-79",
      severity: "High",
      summary:
        "Execute JavaScript in a victim's browser through reflected and stored injection points, then steal their session cookie.",
      objectives: [
        { id: "xss-reflected", label: "Execute JavaScript through the search parameter", detail: "Reflected / DOM-based XSS" },
        { id: "xss-stored", label: "Plant a payload in the guestbook that runs on every visit", detail: "Stored XSS" },
        { id: "xss-cookie", label: "Exfiltrate the victim's session cookie", detail: "Session hijacking" },
        { id: "xss-medium", label: "Bypass the <script> tag filter on Medium", detail: "Filter evasion" }
      ]
    },
    {
      id: "csrf",
      title: "Cross-Site Request Forgery",
      short: "CSRF",
      owasp: "A01:2025 Broken Access Control",
      cwe: "CWE-352",
      severity: "High",
      summary:
        "Craft a malicious page that silently makes a logged-in banking customer transfer money to you.",
      objectives: [
        { id: "csrf-transfer", label: "Force the victim to send money to mallory", detail: "Forged state-changing request" },
        { id: "csrf-get", label: "Pull it off with a zero-click GET request", detail: "Unsafe HTTP methods" },
        { id: "csrf-medium", label: "Bypass the Referer check on Medium", detail: "Weak origin validation" }
      ]
    },
    {
      id: "idor",
      title: "Insecure Direct Object Reference",
      short: "IDOR",
      owasp: "A01:2025 Broken Access Control",
      cwe: "CWE-639",
      severity: "High",
      summary:
        "Tamper with object identifiers in a REST API to read other customers' invoices and the administrator's API key.",
      objectives: [
        { id: "idor-invoice", label: "Read an invoice that belongs to another customer", detail: "Horizontal privilege escalation" },
        { id: "idor-admin", label: "Retrieve the administrator's API key", detail: "Vertical privilege escalation" },
        { id: "idor-medium", label: "Defeat the “opaque” identifiers on Medium", detail: "Security through obscurity" }
      ]
    },
    {
      id: "path-traversal",
      title: "Path Traversal",
      short: "Traversal",
      owasp: "A01:2025 Broken Access Control",
      cwe: "CWE-22",
      severity: "High",
      summary:
        "Escape a document-download directory to read system files and the application's secrets.",
      objectives: [
        { id: "pt-passwd", label: "Read /etc/passwd from the server", detail: "Directory escape" },
        { id: "pt-env", label: "Steal the application's .env secrets file", detail: "Credential disclosure" },
        { id: "pt-medium", label: "Bypass the ../ filter on Medium", detail: "Filter evasion" }
      ]
    },
    {
      id: "command-injection",
      title: "OS Command Injection",
      short: "Command Inj.",
      owasp: "A05:2025 Injection",
      cwe: "CWE-78",
      severity: "Critical",
      summary:
        "Abuse a network diagnostics tool that shells out to ping, and run your own commands on the server.",
      objectives: [
        { id: "ci-exec", label: "Run an arbitrary command such as whoami or id", detail: "Remote code execution" },
        { id: "ci-flag", label: "Read the flag stored in /opt/app/flag.txt", detail: "Post-exploitation" },
        { id: "ci-medium", label: "Bypass the metacharacter blocklist on Medium", detail: "Filter evasion" }
      ]
    },
    {
      id: "redos",
      title: "Denial of Service (ReDoS)",
      short: "ReDoS",
      owasp: "A06:2025 Insecure Design",
      cwe: "CWE-1333",
      severity: "Medium",
      summary:
        "Freeze a single-threaded server with one crafted input by triggering catastrophic regex backtracking.",
      objectives: [
        { id: "dos-block", label: "Block the server for more than 1 second with one request", detail: "Algorithmic complexity attack" },
        { id: "dos-timeout", label: "Make a request time out entirely", detail: "Service outage" },
        { id: "dos-medium", label: "Still cause a 1 second stall under Medium's length limit", detail: "Insufficient mitigation" }
      ]
    }
  ];

  var LEVELS = [
    { id: "low", label: "Low", name: "Vulnerable" },
    { id: "medium", label: "Medium", name: "Weak mitigation" },
    { id: "high", label: "High", name: "Secure" }
  ];

  /* ------------------------------------------------------------------------
   * Storage (resilient to private mode / blocked storage)
   * --------------------------------------------------------------------- */
  var memoryStore = {};
  var store = {
    get: function (key, fallback) {
      try {
        var raw = window.localStorage.getItem(STORE_PREFIX + key);
        return raw === null ? fallback : JSON.parse(raw);
      } catch (e) {
        return key in memoryStore ? memoryStore[key] : fallback;
      }
    },
    set: function (key, value) {
      memoryStore[key] = value;
      try { window.localStorage.setItem(STORE_PREFIX + key, JSON.stringify(value)); } catch (e) { /* ignore */ }
    },
    remove: function (key) {
      delete memoryStore[key];
      try { window.localStorage.removeItem(STORE_PREFIX + key); } catch (e) { /* ignore */ }
    }
  };

  /* ------------------------------------------------------------------------
   * Helpers
   * --------------------------------------------------------------------- */
  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function $(sel, root) { return (root || document).querySelector(sel); }
  function $$(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }

  function getModule(id) {
    for (var i = 0; i < MODULES.length; i++) if (MODULES[i].id === id) return MODULES[i];
    return null;
  }

  function findObjective(objId) {
    for (var i = 0; i < MODULES.length; i++) {
      for (var j = 0; j < MODULES[i].objectives.length; j++) {
        if (MODULES[i].objectives[j].id === objId) return { module: MODULES[i], objective: MODULES[i].objectives[j] };
      }
    }
    return null;
  }

  function root() { return document.body.getAttribute("data-root") || ""; }

  var ICONS = {
    check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg>',
    github: '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 .5C5.65.5.5 5.65.5 12a11.5 11.5 0 0 0 7.86 10.92c.58.1.79-.25.79-.56v-2c-3.2.7-3.88-1.37-3.88-1.37-.52-1.33-1.28-1.69-1.28-1.69-1.05-.71.08-.7.08-.7 1.16.08 1.77 1.19 1.77 1.19 1.03 1.77 2.7 1.26 3.36.96.1-.75.4-1.26.73-1.55-2.55-.29-5.24-1.28-5.24-5.68 0-1.26.45-2.28 1.19-3.09-.12-.29-.52-1.46.11-3.05 0 0 .97-.31 3.17 1.18a11 11 0 0 1 5.77 0c2.2-1.49 3.17-1.18 3.17-1.18.63 1.59.23 2.76.11 3.05.74.81 1.19 1.83 1.19 3.09 0 4.41-2.69 5.38-5.26 5.67.41.36.78 1.06.78 2.14v3.17c0 .31.21.67.8.56A11.5 11.5 0 0 0 23.5 12C23.5 5.65 18.35.5 12 .5Z"/></svg>',
    moon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z"/></svg>',
    sun: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/></svg>'
  };

  /* ------------------------------------------------------------------------
   * Theme
   * --------------------------------------------------------------------- */
  function currentTheme() {
    var explicit = document.documentElement.getAttribute("data-theme");
    if (explicit) return explicit;
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  function applyStoredTheme() {
    var t = store.get("theme", null);
    if (t === "light" || t === "dark") document.documentElement.setAttribute("data-theme", t);
  }
  function toggleTheme() {
    var next = currentTheme() === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    store.set("theme", next);
    renderThemeButton();
  }
  function renderThemeButton() {
    var btn = $("#theme-toggle");
    if (!btn) return;
    var dark = currentTheme() === "dark";
    btn.innerHTML = dark ? ICONS.sun : ICONS.moon;
    btn.setAttribute("aria-label", dark ? "Switch to light theme" : "Switch to dark theme");
    btn.title = btn.getAttribute("aria-label");
  }
  applyStoredTheme();

  /* ------------------------------------------------------------------------
   * Progress
   * --------------------------------------------------------------------- */
  var listeners = [];
  var progress = {
    all: function () { return store.get("progress", {}); },
    isDone: function (objId) { return !!progress.all()[objId]; },
    complete: function (objId) {
      var data = progress.all();
      if (data[objId]) return false;
      data[objId] = Date.now();
      store.set("progress", data);
      var found = findObjective(objId);
      if (found) toast("Objective complete", found.objective.label, "ok");
      listeners.forEach(function (fn) { fn(objId); });
      return true;
    },
    moduleStats: function (mod) {
      var data = progress.all();
      var done = mod.objectives.filter(function (o) { return data[o.id]; }).length;
      return { done: done, total: mod.objectives.length };
    },
    totals: function () {
      var done = 0, total = 0;
      MODULES.forEach(function (m) { var s = progress.moduleStats(m); done += s.done; total += s.total; });
      return { done: done, total: total };
    },
    resetModule: function (mod) {
      var data = progress.all();
      mod.objectives.forEach(function (o) { delete data[o.id]; });
      store.set("progress", data);
      listeners.forEach(function (fn) { fn(null); });
    },
    resetAll: function () {
      store.set("progress", {});
      listeners.forEach(function (fn) { fn(null); });
    },
    onChange: function (fn) { listeners.push(fn); }
  };

  /* ------------------------------------------------------------------------
   * Toasts
   * --------------------------------------------------------------------- */
  function toast(title, message, type) {
    var stack = $(".toast-stack");
    if (!stack) {
      stack = document.createElement("div");
      stack.className = "toast-stack";
      stack.setAttribute("role", "status");
      stack.setAttribute("aria-live", "polite");
      document.body.appendChild(stack);
    }
    var el = document.createElement("div");
    el.className = "toast" + (type ? " toast-" + type : "");
    var strong = document.createElement("strong");
    strong.textContent = title;
    var span = document.createElement("span");
    span.textContent = message || "";
    el.appendChild(strong);
    el.appendChild(span);
    stack.appendChild(el);
    setTimeout(function () {
      el.classList.add("leaving");
      setTimeout(function () { el.remove(); }, 250);
    }, 4800);
  }

  /* ------------------------------------------------------------------------
   * Chrome: header, footer, sidebar
   * --------------------------------------------------------------------- */
  function renderHeader() {
    var mount = $("#site-header");
    if (!mount) return;
    var r = root();
    var page = document.body.getAttribute("data-page") || "";
    mount.outerHTML =
      '<header class="site-header"><div class="container">' +
      '<a class="brand" href="' + r + 'index.html" aria-label="MVWA home">' +
      '<span class="brand-mark">mv</span>' +
      '<span class="brand-name"><span>MVWA</span><small>Modern Vulnerable Web App</small></span></a>' +
      '<nav class="header-nav" aria-label="Primary">' +
      '<a href="' + r + 'index.html#labs"' + (page === "lab" ? ' class="active"' : "") + ">Labs</a>" +
      '<a class="hide-sm" href="' + r + 'index.html#how-it-works">How it works</a>' +
      '<a class="hide-sm" href="' + r + 'index.html#about">About</a>' +
      '<a class="icon-btn" href="' + REPO_URL + '" target="_blank" rel="noopener" aria-label="Source code on GitHub" title="Source code on GitHub">' + ICONS.github + "</a>" +
      '<button class="icon-btn" id="theme-toggle" type="button"></button>' +
      "</nav></div></header>";
    $("#theme-toggle").addEventListener("click", toggleTheme);
    renderThemeButton();
  }

  function renderFooter() {
    var mount = $("#site-footer");
    if (!mount) return;
    var r = root();
    mount.outerHTML =
      '<footer class="site-footer"><div class="container">' +
      "<p>Modern Vulnerable Web Application &middot; an intentionally insecure training environment. Everything runs locally in your browser.</p>" +
      '<nav aria-label="Footer">' +
      '<a href="' + r + 'index.html#labs">Labs</a>' +
      '<a href="' + r + 'index.html#about">Responsible use</a>' +
      '<a href="' + REPO_URL + '" target="_blank" rel="noopener">GitHub</a>' +
      "</nav></div></footer>";
  }

  function renderSidebar(activeId) {
    var mount = $("#lab-sidebar");
    if (!mount) return;
    var html = '<h4>Labs</h4><ol>';
    MODULES.forEach(function (m) {
      var s = progress.moduleStats(m);
      html += '<li><a href="' + m.id + '.html"' + (m.id === activeId ? ' aria-current="page"' : "") + ">" +
        "<span>" + escapeHtml(m.title) + "</span>" +
        '<span class="count' + (s.done === s.total ? " done" : "") + '">' + s.done + "/" + s.total + "</span></a></li>";
    });
    html += "</ol>";
    mount.innerHTML = html;
  }

  function severityClass(sev) {
    return sev === "Critical" ? "badge-danger" : sev === "High" ? "badge-warn" : "badge-accent";
  }

  /* ------------------------------------------------------------------------
   * Lab bootstrap
   * --------------------------------------------------------------------- */
  var levelHandlers = [];
  var activeModule = null;

  function getLevel() {
    var lvl = activeModule ? store.get("level:" + activeModule.id, "low") : "low";
    return lvl === "medium" || lvl === "high" ? lvl : "low";
  }

  function setLevel(lvl) {
    if (!activeModule) return;
    store.set("level:" + activeModule.id, lvl);
    applyLevel();
  }

  function applyLevel() {
    var lvl = getLevel();
    document.body.setAttribute("data-level", lvl);
    $$(".segmented button[data-level]").forEach(function (b) {
      b.setAttribute("aria-pressed", String(b.getAttribute("data-level") === lvl));
    });
    var desc = $("#level-desc");
    if (desc && activeModule && activeModule.levelText) {
      var meta = LEVELS.filter(function (l) { return l.id === lvl; })[0];
      desc.innerHTML = "<strong>" + meta.label + " — " + meta.name + ".</strong> " + activeModule.levelText[lvl];
    }
    levelHandlers.forEach(function (fn) { fn(lvl); });
  }

  function renderLabHead(mod) {
    var mount = $("#lab-head");
    if (!mount) return;
    var idx = MODULES.indexOf(mod) + 1;
    mount.innerHTML =
      '<div class="breadcrumbs"><a href="../index.html#labs">Labs</a> / Lab ' + String(idx).padStart(2, "0") + "</div>" +
      "<h1>" + escapeHtml(mod.title) + "</h1>" +
      '<div class="tags">' +
      '<span class="badge ' + severityClass(mod.severity) + '"><span class="dot"></span>' + mod.severity + "</span>" +
      '<span class="badge">' + escapeHtml(mod.owasp) + "</span>" +
      '<a class="badge mono" href="https://cwe.mitre.org/data/definitions/' + mod.cwe.replace("CWE-", "") + '.html" target="_blank" rel="noopener">' + mod.cwe + "</a>" +
      "</div>" +
      '<p class="summary">' + escapeHtml(mod.summary) + "</p>";
  }

  function renderLevelControl() {
    var mount = $("#level-control");
    if (!mount) return;
    var buttons = LEVELS.map(function (l) {
      return '<button type="button" data-level="' + l.id + '" aria-pressed="false"><span class="dot"></span>' + l.label + "</button>";
    }).join("");
    mount.innerHTML =
      '<div class="panel-body level-control">' +
      '<div><div class="label" id="level-label">Security level</div><div class="segmented" role="group" aria-labelledby="level-label">' + buttons + "</div></div>" +
      '<p class="level-desc" id="level-desc"></p>' +
      "</div>";
    $$(".segmented button", mount).forEach(function (b) {
      b.addEventListener("click", function () { setLevel(b.getAttribute("data-level")); });
    });
  }

  function renderObjectives(mod) {
    var mount = $("#objectives");
    if (!mount) return;
    var items = mod.objectives.map(function (o) {
      return '<li class="objective" data-objective="' + o.id + '">' +
        '<span class="check">' + ICONS.check + "</span>" +
        '<span class="txt">' + escapeHtml(o.label) + "<small>" + escapeHtml(o.detail) + "</small>" +
        '<span class="sr-only" data-state></span></span></li>';
    }).join("");
    mount.innerHTML =
      '<div class="panel-head"><h2>Objectives</h2>' +
      '<div class="progress-card" style="min-width:180px"><div class="progress-track"><div class="progress-fill" id="objectives-fill"></div></div>' +
      '<span class="progress-label" id="objectives-count" aria-live="polite"></span>' +
      '<button type="button" class="btn btn-ghost btn-sm" id="reset-objectives">Reset</button></div></div>' +
      '<div class="panel-body"><ul class="objectives">' + items + "</ul>" +
      (mod.hintsHtml || "") + "</div>";
    $("#reset-objectives").addEventListener("click", function () {
      progress.resetModule(mod);
      toast("Progress reset", mod.title + " objectives cleared.");
    });
    updateObjectives(mod);
  }

  function updateObjectives(mod) {
    if (!$("#objectives-fill")) return;
    var stats = progress.moduleStats(mod);
    $("#objectives-fill").style.width = (stats.done / stats.total * 100) + "%";
    $("#objectives-count").textContent = stats.done + " of " + stats.total;
    mod.objectives.forEach(function (o) {
      var li = $('[data-objective="' + o.id + '"]');
      if (!li) return;
      var done = progress.isDone(o.id);
      li.classList.toggle("done", done);
      $("[data-state]", li).textContent = done ? " (completed)" : " (not completed)";
    });
  }

  /**
   * Called by each lab script.
   * @param {object} opts { id, levels: {low, medium, high}, hints: html, onLevel(level) }
   */
  function initLab(opts) {
    var mod = getModule(opts.id);
    activeModule = mod;
    mod.levelText = opts.levels || {};
    mod.hintsHtml = opts.hints || "";
    renderLabHead(mod);
    renderLevelControl();
    renderObjectives(mod);
    renderSidebar(mod.id);
    progress.onChange(function () { updateObjectives(mod); renderSidebar(mod.id); });
    if (typeof opts.onLevel === "function") levelHandlers.push(opts.onLevel);
    applyLevel();
    return mod;
  }

  /* ------------------------------------------------------------------------
   * Tiny syntax highlighter for the server-side code samples
   * --------------------------------------------------------------------- */
  function highlightCode() {
    $$("pre code[data-lang]").forEach(function (el) {
      if (el.getAttribute("data-hl") === "1") return;
      var src = el.textContent;
      var html = escapeHtml(src);
      var rules = [
        { re: /(\/\/[^\n]*|(?:^|\s)#\s[^\n]*)/gm, cls: "tok-c" },
        { re: /(&#39;(?:[^&\n]|&(?!#39;))*?&#39;|&quot;(?:[^&\n]|&(?!quot;))*?&quot;|`[^`\n]*`)/g, cls: "tok-s" },
        { re: /\b(const|let|var|function|return|if|else|await|async|new|throw|import|from|require|def|for|in|of|try|catch|SELECT|FROM|WHERE|AND|OR|LIKE|UNION|INSERT|UPDATE|DELETE)\b/g, cls: "tok-k" }
      ];
      // Tokenise in a single pass to avoid highlighting inside earlier matches.
      var combined = new RegExp(rules.map(function (r) { return r.re.source; }).join("|"), "gm");
      html = html.replace(combined, function (m) {
        for (var i = 0; i < rules.length; i++) {
          var r = new RegExp("^(?:" + rules[i].re.source + ")$", "m");
          if (r.test(m)) return '<span class="' + rules[i].cls + '">' + m + "</span>";
        }
        return m;
      });
      // Markers: [[bad]]...[[/bad]] and [[good]]...[[/good]] in the source.
      html = html
        .replace(/\[\[bad\]\]/g, '<span class="tok-bad">').replace(/\[\[\/bad\]\]/g, "</span>")
        .replace(/\[\[good\]\]/g, '<span class="tok-good">').replace(/\[\[\/good\]\]/g, "</span>");
      el.innerHTML = html;
      el.setAttribute("data-hl", "1");
    });
  }

  /* ------------------------------------------------------------------------
   * Boot
   * --------------------------------------------------------------------- */
  function boot() {
    renderHeader();
    renderFooter();
    highlightCode();
  }

  window.MVWA = {
    REPO_URL: REPO_URL,
    MODULES: MODULES,
    LEVELS: LEVELS,
    store: store,
    progress: progress,
    toast: toast,
    escapeHtml: escapeHtml,
    getModule: getModule,
    severityClass: severityClass,
    initLab: initLab,
    getLevel: getLevel,
    complete: progress.complete,
    $: $,
    $$: $$
  };

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
})();
