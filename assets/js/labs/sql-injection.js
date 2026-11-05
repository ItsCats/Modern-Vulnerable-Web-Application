/* Lab 01 — SQL Injection (real SQLite via sql.js / WebAssembly) */
(function () {
  "use strict";
  var M = window.MVWA, $ = M.$, esc = M.escapeHtml;
  var SQLJS_CDN = "https://cdnjs.cloudflare.com/ajax/libs/sql.js/1.10.3/";

  var ADMIN_PASSWORD = "Xk9#vQ2m!Lp7";
  var FLAG = "FLAG{un10n_b4s3d_sql1_m4st3r}";
  var SEED = [
    "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, password TEXT NOT NULL, email TEXT, role TEXT);",
    "INSERT INTO users VALUES",
    " (1, 'admin',  '" + ADMIN_PASSWORD + "', 'admin@acme.test',   'administrator'),",
    " (2, 'jsmith', 'Summer2026!',           'j.smith@acme.test', 'staff'),",
    " (3, 'mlee',   'correct-horse-battery', 'm.lee@acme.test',   'staff'),",
    " (4, 'kpatel', 'Pa55w0rd!',             'k.patel@acme.test', 'support');",
    "CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, category TEXT, price REAL, released INTEGER);",
    "INSERT INTO products VALUES",
    " (1, 'Mechanical Keyboard',  'Peripherals', 129.00, 1),",
    " (2, 'Wireless Mouse',       'Peripherals',  49.00, 1),",
    " (3, '27\" 4K Monitor',       'Displays',    399.00, 1),",
    " (4, 'USB-C Dock',           'Accessories', 189.00, 1),",
    " (5, 'Noise-Cancelling Headset', 'Audio',   229.00, 1),",
    " (6, 'Laptop Stand',         'Accessories',  59.00, 1),",
    " (7, 'Prototype AR Glasses', 'Wearables',  1499.00, 0);",
    "CREATE TABLE internal_secrets (id INTEGER PRIMARY KEY, note TEXT, value TEXT);",
    "INSERT INTO internal_secrets VALUES (1, 'Penetration test canary', '" + FLAG + "');"
  ].join("\n");

  var SEARCH_PREFIX = "SELECT id, name, category, price FROM products WHERE released = 1 AND name LIKE '%";
  var SEARCH_SUFFIX = "%'";
  var LOGIN_A = "SELECT id, username, role FROM users WHERE username = '";
  var LOGIN_B = "' AND password = '";
  var LOGIN_C = "'";

  var SQL = null, db = null;

  /* ---------------- database ---------------- */
  function resetDb() {
    if (!SQL) return;
    if (db) db.close();
    db = new SQL.Database();
    db.run(SEED);
  }

  function setReady(ok, text) {
    var badge = $("#db-status");
    badge.className = "badge mono " + (ok ? "badge-ok" : "badge-danger");
    badge.innerHTML = '<span class="dot"></span>' + esc(text);
    M.$$("#search-form button, #login-form button").forEach(function (b) { b.disabled = !ok; });
  }

  function loadEngine() {
    if (typeof window.initSqlJs !== "function") {
      setReady(false, "sql.js failed to load");
      return;
    }
    window.initSqlJs({ locateFile: function (f) { return SQLJS_CDN + f; } })
      .then(function (S) {
        SQL = S;
        resetDb();
        var v = db.exec("SELECT sqlite_version()")[0].values[0][0];
        setReady(true, "SQLite " + v + " · WASM");
      })
      .catch(function (e) {
        console.error(e);
        setReady(false, "Database failed to start");
      });
  }

  /* ---------------- query execution per level ---------------- */
  function sanitizeMedium(input) {
    return input.replace(/OR|UNION|SELECT|--/g, "");
  }

  // Runs a query and returns { columns, rows, error }.
  function runQuery(level, parts, params) {
    try {
      if (level === "high") {
        var stmt = db.prepare(parts.sql);
        stmt.bind(params);
        var rows = [];
        while (stmt.step()) rows.push(stmt.get());
        var cols = stmt.getColumnNames();
        stmt.free();
        return { columns: cols, rows: rows };
      }
      if (level === "low") {
        // Stacked statements allowed (like mysql's multipleStatements: true).
        var results = db.exec(parts.sql);
        var first = results[0];
        return first ? { columns: first.columns, rows: first.values } : { columns: [], rows: [] };
      }
      // medium: only the first statement is compiled and executed.
      var s = db.prepare(parts.sql);
      var out = [];
      while (s.step()) out.push(s.get());
      var c = s.getColumnNames();
      s.free();
      return { columns: c, rows: out };
    } catch (e) {
      return { error: e.message || String(e), columns: [], rows: [] };
    }
  }

  /* ---------------- query inspector ---------------- */
  function logQuery(label, htmlSql, extra) {
    var el = $("#query-log");
    var time = new Date().toLocaleTimeString();
    el.innerHTML = '<span class="dim">-- ' + esc(label) + " · " + esc(time) + "</span>\n" + htmlSql + (extra ? "\n" + extra : "");
  }

  function inj(text) { return '<span class="inj">' + esc(text) + "</span>"; }

  /* ---------------- rendering ---------------- */
  function renderTable(res) {
    if (!res.rows.length) return '<p class="muted" style="margin:0">No rows returned.</p>';
    var html = '<div class="table-wrap"><table class="data"><thead><tr>';
    res.columns.forEach(function (c) { html += "<th>" + esc(c) + "</th>"; });
    html += "</tr></thead><tbody>";
    res.rows.forEach(function (r) {
      html += "<tr>";
      r.forEach(function (v) { html += '<td class="mono">' + esc(v === null ? "NULL" : v) + "</td>"; });
      html += "</tr>";
    });
    return html + "</tbody></table></div>";
  }

  function errorBox(level, message) {
    if (level === "high") return '<div class="alert alert-info"><p>Something went wrong. Please try again.</p></div>';
    return '<div class="alert alert-danger"><p><strong>500 Internal Server Error</strong><br><span class="mono">' + esc(message) + "</span></p></div>";
  }

  /* ---------------- objective detection ---------------- */
  function flatten(res) {
    var cells = [];
    res.rows.forEach(function (r) { r.forEach(function (v) { cells.push(String(v)); }); });
    return cells;
  }

  function checkLoot(res, level) {
    var cells = flatten(res);
    var got = false;
    var others = ["Summer2026!", "correct-horse-battery", "Pa55w0rd!"];
    if (cells.indexOf(ADMIN_PASSWORD) !== -1 && others.some(function (p) { return cells.indexOf(p) !== -1; })) {
      M.complete("sqli-union"); got = true;
    }
    if (cells.some(function (c) { return c.indexOf(FLAG) !== -1; })) { M.complete("sqli-flag"); got = true; }
    if (got && level === "medium") M.complete("sqli-medium");
  }

  /* ---------------- product search ---------------- */
  function doSearch(q) {
    var level = M.getLevel();
    var shown = level === "medium" ? sanitizeMedium(q) : q;
    var parts, res, logged;
    $("#search-url").textContent = encodeURIComponent(q);

    if (level === "high") {
      parts = { sql: "SELECT id, name, category, price FROM products WHERE released = 1 AND name LIKE ?" };
      res = runQuery(level, parts, ["%" + q + "%"]);
      logged = esc(parts.sql) + ';\n<span class="dim">-- bound parameters:</span> [' + inj(JSON.stringify("%" + q + "%")) + "]";
    } else {
      parts = { sql: SEARCH_PREFIX + shown + SEARCH_SUFFIX };
      res = runQuery(level, parts);
      logged = esc(SEARCH_PREFIX) + inj(shown) + esc(SEARCH_SUFFIX) + ";";
      if (level === "medium" && shown !== q) logged += '\n<span class="dim">-- input after sanitize(): </span>' + inj(shown);
    }
    logQuery("GET /products", logged, res.error ? '<span class="err">!! ' + esc(res.error) + "</span>" : '<span class="ok">' + res.rows.length + " row(s)</span>");

    var out = $("#search-results");
    if (res.error) { out.innerHTML = errorBox(level, res.error); return; }
    out.innerHTML = renderTable(res);
    checkLoot(res, level);
  }

  /* ---------------- staff login ---------------- */
  function doLogin(u, p) {
    var level = M.getLevel();
    var su = level === "medium" ? sanitizeMedium(u) : u;
    var sp = level === "medium" ? sanitizeMedium(p) : p;
    var res, logged;

    if (level === "high") {
      var sql = "SELECT id, username, role, password FROM users WHERE username = ?";
      res = runQuery(level, { sql: sql }, [u]);
      logged = esc(sql) + ';\n<span class="dim">-- bound parameters:</span> [' + inj(JSON.stringify(u)) + "]" +
        '\n<span class="dim">-- password compared in application code with a constant-time hash check</span>';
      // Password verified in application code (stands in for argon2.verify()).
      if (res.rows.length && res.rows[0][3] !== p) res.rows = [];
      res.rows = res.rows.map(function (r) { return r.slice(0, 3); });
      res.columns = ["id", "username", "role"];
    } else {
      res = runQuery(level, { sql: LOGIN_A + su + LOGIN_B + sp + LOGIN_C });
      logged = esc(LOGIN_A) + inj(su) + esc(LOGIN_B) + inj(sp) + esc(LOGIN_C) + ";";
    }
    logQuery("POST /staff/login", logged, res.error ? '<span class="err">!! ' + esc(res.error) + "</span>" : '<span class="ok">' + res.rows.length + " row(s)</span>");

    var out = $("#login-results");
    if (res.error) { out.innerHTML = errorBox(level, res.error); return; }
    if (!res.rows.length) {
      out.innerHTML = '<div class="alert alert-danger"><p><strong>401 Unauthorized</strong> · Invalid username or password.</p></div>';
      return;
    }
    var row = res.rows[0];
    out.innerHTML = '<div class="alert alert-ok"><p><strong>Welcome back, ' + esc(row[1]) + '.</strong> Signed in with role <span class="mono">' + esc(row[2]) + "</span>.</p></div>";

    if (level !== "high" && String(row[1]) === "admin" && p !== ADMIN_PASSWORD) {
      M.complete("sqli-login");
      if (level === "medium") M.complete("sqli-medium");
    }
    checkLoot(res, level);
  }

  /* ---------------- wiring ---------------- */
  $("#search-form").addEventListener("submit", function (e) {
    e.preventDefault();
    if (db) doSearch($("#search-q").value);
  });
  $("#login-form").addEventListener("submit", function (e) {
    e.preventDefault();
    if (db) doLogin($("#login-user").value, $("#login-pass").value);
  });
  $("#reset-db").addEventListener("click", function () {
    if (!SQL) return;
    resetDb();
    $("#search-results").innerHTML = "";
    $("#login-results").innerHTML = "";
    $("#query-log").innerHTML = '<span class="dim">-- Database restored to its original state.</span>';
    M.toast("Database reset", "All tables have been restored.");
  });

  M.initLab({
    id: "sql-injection",
    levels: {
      low: "Queries are built by string concatenation, stacked statements are allowed and raw database errors are shown to the user.",
      medium: "A case-sensitive blocklist strips OR, UNION, SELECT and -- from input, and only the first statement is executed. Queries are still concatenated.",
      high: "Every query is a prepared statement with bound parameters. Errors are generic. Your payloads are treated as plain data."
    },
    hints: [
      '<details class="hint"><summary>Hint: authentication bypass</summary><div><p>The login query compares <code>username = \'…\'</code>. Close the quote and comment out the rest of the statement, e.g. <code>admin\'--</code>.</p></div></details>',
      '<details class="hint"><summary>Hint: UNION-based extraction</summary><div><p>The search query returns 4 columns. A UNION must return the same number: <code>\' UNION SELECT id, username, password, role FROM users--</code></p></div></details>',
      '<details class="hint"><summary>Hint: finding the hidden table</summary><div><p>SQLite stores its schema in <code>sqlite_master</code>. Try <code>\' UNION SELECT 1, name, sql, 4 FROM sqlite_master--</code>, then query the table you find.</p></div></details>',
      '<details class="hint"><summary>Hint: bypassing the blocklist</summary><div><p>The filter is case-sensitive and SQLite keywords are not. Use lowercase keywords and replace <code>--</code> with an unterminated <code>/*</code> comment.</p></div></details>'
    ].join("")
  });

  loadEngine();
})();
