/* Lab 04 — Insecure Direct Object Reference */
(function () {
  "use strict";
  var M = window.MVWA, $ = M.$, esc = M.escapeHtml;

  var ME = 1042;
  var ADMIN_KEY = "lk_live_9f2c7e41b8d03a56e0c4";

  var USERS = {
    1001: { id: 1001, username: "dwhitfield", name: "Dana Whitfield", email: "dana@ledgerly.test", role: "admin", api_key: ADMIN_KEY, mfa_enabled: true },
    1042: { id: 1042, username: "jdoe", name: "Jamie Doe", email: "jamie.doe@mail.test", role: "customer", api_key: "lk_live_3b81aa0f72d4c9e15b60", mfa_enabled: false },
    1043: { id: 1043, username: "acme-finance", name: "Acme Corp (Finance)", email: "ap@acme.test", role: "customer", api_key: "lk_live_c07d5e9b1f3a28e44d17", mfa_enabled: true },
    1057: { id: 1057, username: "rnakamura", name: "Rin Nakamura", email: "rin.n@mail.test", role: "customer", api_key: "lk_live_e6a2f94d0b7c135a88c2", mfa_enabled: false }
  };

  var INVOICES = {
    5001: { id: 5001, owner_id: 1043, date: "2026-09-02", total: 18450.00, items: ["Enterprise plan (annual)"], billing_address: "1 Market St, San Francisco, CA", card_last4: "4417" },
    5002: { id: 5002, owner_id: 1042, date: "2026-09-14", total: 29.00, items: ["Starter plan (monthly)"], billing_address: "22 Elm Rd, Portland, OR", card_last4: "0331" },
    5003: { id: 5003, owner_id: 1057, date: "2026-09-21", total: 99.00, items: ["Pro plan (monthly)", "Extra seat x2"], billing_address: "8-3 Shibuya, Tokyo", card_last4: "9120" },
    5004: { id: 5004, owner_id: 1042, date: "2026-10-14", total: 29.00, items: ["Starter plan (monthly)"], billing_address: "22 Elm Rd, Portland, OR", card_last4: "0331" },
    5005: { id: 5005, owner_id: 1001, date: "2026-10-15", total: 0.00, items: ["Internal test invoice"], billing_address: "Ledgerly HQ", card_last4: "0000", note: "Staff tooling: see /api/users/1001" },
    5006: { id: 5006, owner_id: 1043, date: "2026-10-30", total: 1720.00, items: ["Overage: 86k API calls"], billing_address: "1 Market St, San Francisco, CA", card_last4: "4417" }
  };

  /* ---------------- references (Medium uses base64) ---------------- */
  function encodeRef(type, id) { return btoa(type + ":" + id); }
  function decodeRef(ref) {
    try { return atob(decodeURIComponent(ref)).split(":"); } catch (e) { return null; }
  }
  function refFor(type, id) { return M.getLevel() === "medium" ? encodeRef(type, id) : String(id); }

  /* ---------------- the API server ---------------- */
  function api(path) {
    var level = M.getLevel();
    var m = /^\/api\/(invoices|users)\/([^\/?#]+)\/?$/.exec(path.trim());
    if (!m) return { status: 404, body: { error: "Not found" } };
    var kind = m[1], raw = m[2], id;

    if (level === "medium") {
      var parts = decodeRef(raw);
      var expected = kind === "invoices" ? "invoice" : "user";
      if (!parts || parts[0] !== expected || !/^\d+$/.test(parts[1] || "")) return { status: 400, body: { error: "Invalid reference" } };
      id = Number(parts[1]);
    } else {
      if (!/^\d+$/.test(raw)) return { status: 400, body: { error: "Invalid id" } };
      id = Number(raw);
    }

    if (kind === "invoices") {
      var inv = INVOICES[id];
      if (level === "high") {
        if (!inv || inv.owner_id !== ME) return { status: 404, body: { error: "Not found" } };
        return { status: 200, body: { id: inv.id, date: inv.date, total: inv.total, items: inv.items, card_last4: inv.card_last4 } };
      }
      if (!inv) return { status: 404, body: { error: "Not found" } };
      return { status: 200, body: inv, meta: { kind: "invoice", owner: inv.owner_id } };
    }

    var user = USERS[id];
    if (level === "high") {
      if (!user || id !== ME) return { status: 404, body: { error: "Not found" } };
      return { status: 200, body: { id: user.id, username: user.username, name: user.name, email: user.email, role: user.role, api_key_last4: user.api_key.slice(-4) } };
    }
    if (!user) return { status: 404, body: { error: "Not found" } };
    return { status: 200, body: user, meta: { kind: "user", owner: user.id } };
  }

  /* ---------------- console ---------------- */
  function send(path) {
    var level = M.getLevel();
    var res = api(path);
    var statusText = { 200: "OK", 400: "Bad Request", 403: "Forbidden", 404: "Not Found" }[res.status] || "";
    var cls = res.status < 400 ? "s2" : "s4";
    $("#api-response").innerHTML =
      '<span class="meth">GET</span> ' + esc(path) + " HTTP/1.1\n" +
      '<span class="hdr">Host: app.ledgerly.test\nAuthorization: Bearer eyJ1aWQiOjEwNDJ9.… (jdoe)</span>\n\n' +
      '<span class="' + cls + '">HTTP/1.1 ' + res.status + " " + statusText + "</span>\n" +
      '<span class="hdr">Content-Type: application/json</span>\n\n' +
      esc(JSON.stringify(res.body, null, 2));

    if (res.status === 200 && res.meta && res.meta.owner !== ME) {
      if (res.meta.kind === "invoice") M.complete("idor-invoice");
      if (res.body.api_key === ADMIN_KEY) M.complete("idor-admin");
      if (res.meta.kind === "user" && res.body.api_key !== ADMIN_KEY) M.complete("idor-invoice");
      if (level === "medium") M.complete("idor-medium");
    }
  }

  function renderMyInvoices() {
    var rows = Object.keys(INVOICES).map(Number).filter(function (id) { return INVOICES[id].owner_id === ME; });
    $("#my-invoices").innerHTML = rows.map(function (id) {
      var inv = INVOICES[id];
      return '<tr><td class="mono">INV-' + id + "</td><td>" + esc(inv.date) + '</td><td class="num">$' + inv.total.toFixed(2) +
        '</td><td style="text-align:right"><button type="button" class="btn btn-ghost btn-sm" data-view="' + id + '">View</button></td></tr>';
    }).join("");
  }

  $("#my-invoices").addEventListener("click", function (e) {
    var b = e.target.closest("[data-view]");
    if (!b) return;
    var path = "/api/invoices/" + refFor("invoice", b.getAttribute("data-view"));
    $("#api-path").value = path;
    send(path);
  });
  $("#my-profile").addEventListener("click", function () {
    var path = "/api/users/" + refFor("user", ME);
    $("#api-path").value = path;
    send(path);
  });
  $("#api-form").addEventListener("submit", function (e) {
    e.preventDefault();
    send($("#api-path").value);
  });

  renderMyInvoices();

  M.initLab({
    id: "idor",
    levels: {
      low: "Objects are fetched by sequential numeric ID with no ownership check, and full records (including API keys) are returned.",
      medium: "IDs are replaced by base64-encoded “opaque” references such as aW52b2ljZTo1MDAy. There is still no ownership check.",
      high: "Every query is scoped to the signed-in user, foreign objects return 404 and responses use DTOs without secrets."
    },
    hints: [
      '<details class="hint"><summary>Hint: other customers\' invoices</summary><div><p>Your invoices are 5002 and 5004. What about <code>/api/invoices/5001</code> or <code>5003</code>?</p></div></details>',
      '<details class="hint"><summary>Hint: the admin\'s API key</summary><div><p>One of the invoices you shouldn\'t be able to read leaves a note about staff tooling. User IDs start at 1001.</p></div></details>',
      '<details class="hint"><summary>Hint: "opaque" references</summary><div><p>Decode a reference in your browser console with <code>atob("aW52b2ljZTo1MDAy")</code>, change the number, and encode it again with <code>btoa("invoice:5001")</code>.</p></div></details>'
    ].join(""),
    onLevel: function () {
      var cur = $("#api-path").value;
      if (/^\/api\/(invoices|users)\/[^\/]*$/.test(cur)) $("#api-path").value = cur.replace(/[^\/]*$/, "");
    }
  });
})();
