/* Lab 05 — Path Traversal */
(function () {
  "use strict";
  var M = window.MVWA, $ = M.$, esc = M.escapeHtml, fs = M.vfs;
  var BASE = "/var/www/docs/files";

  // Express-style query decoding: '+' is a space, then percent-decoding once.
  function frameworkDecode(raw) {
    try { return decodeURIComponent(raw.replace(/\+/g, " ")); } catch (e) { return null; }
  }

  function server(rawParam) {
    var level = M.getLevel();
    var file = frameworkDecode(rawParam);
    if (file === null) return { status: 400, body: "URIError: URI malformed", path: null };

    var target;
    if (level === "low") {
      target = fs.join(BASE, file);
    } else if (level === "medium") {
      var cleaned = file.split("../").join("");
      var name;
      try { name = decodeURIComponent(cleaned); } catch (e) { return { status: 400, body: "URIError: URI malformed", path: null }; }
      target = fs.join(BASE, name);
    } else {
      if (file.indexOf("\0") !== -1) return { status: 400, body: "Bad Request", path: null };
      target = fs.resolve(BASE, file);
      if (target.indexOf(BASE + "/") !== 0) return { status: 404, body: "Not Found", path: target, blocked: true };
    }

    var st = fs.stat(target);
    var verbose = level !== "high";
    if (!st) return { status: 404, body: verbose ? "ENOENT: no such file or directory, open '" + target + "'" : "Not Found", path: target };
    if (st.type === "dir") return { status: verbose ? 500 : 404, body: verbose ? "EISDIR: illegal operation on a directory, read" : "Not Found", path: target };
    if (!st.readable) return { status: verbose ? 500 : 404, body: verbose ? "EACCES: permission denied, open '" + target + "'" : "Not Found", path: target };
    return { status: 200, body: fs.read(target), path: target, ok: true };
  }

  function fetchFile(rawParam) {
    var level = M.getLevel();
    var res = server(rawParam);
    var statusText = { 200: "OK", 400: "Bad Request", 404: "Not Found", 500: "Internal Server Error" }[res.status];
    var cls = res.status < 400 ? "s2" : "s4";

    var shownPath = res.path || "—";
    $("#resolved-path").innerHTML = res.path
      ? (res.path.indexOf(BASE + "/") === 0 ? esc(shownPath) : '<span style="color:var(--danger);font-weight:600">' + esc(shownPath) + "</span>" + (res.blocked ? " (blocked)" : ""))
      : "—";

    $("#dl-response").innerHTML =
      '<span class="meth">GET</span> /download?file=' + esc(rawParam) + " HTTP/1.1\n" +
      '<span class="hdr">Host: docs.contoso.test</span>\n\n' +
      '<span class="' + cls + '">HTTP/1.1 ' + res.status + " " + statusText + "</span>\n" +
      '<span class="hdr">Content-Type: text/plain; charset=utf-8</span>\n\n' + esc(res.body);

    if (res.ok && res.path.indexOf(BASE + "/") !== 0) {
      if (res.path === "/etc/passwd") M.complete("pt-passwd");
      if (res.path === "/var/www/docs/.env") M.complete("pt-env");
      if (level === "medium") M.complete("pt-medium");
      M.toast("File outside the web root", res.path, "danger");
    }
  }

  function renderFiles() {
    $("#file-list").innerHTML = fs.list(BASE).map(function (f) {
      var kb = (fs.size(f.path) / 1024).toFixed(1) + " KB";
      return '<tr><td class="mono">' + esc(f.name) + '</td><td class="num">' + kb +
        '</td><td style="text-align:right"><button type="button" class="btn btn-ghost btn-sm" data-file="' + esc(f.name) + '">Download</button></td></tr>';
    }).join("");
  }

  $("#file-list").addEventListener("click", function (e) {
    var b = e.target.closest("[data-file]");
    if (!b) return;
    var name = encodeURIComponent(b.getAttribute("data-file"));
    $("#dl-file").value = name;
    fetchFile(name);
  });
  $("#dl-form").addEventListener("submit", function (e) {
    e.preventDefault();
    fetchFile($("#dl-file").value);
  });

  renderFiles();

  M.initLab({
    id: "path-traversal",
    levels: {
      low: "The file name is joined onto the base directory with path.join and read directly. Errors expose absolute paths.",
      medium: "“../” is removed from the input in a single pass, and the result is URL-decoded a second time afterwards.",
      high: "The path is canonicalised with path.resolve and must stay inside the base directory. Errors are generic."
    },
    hints: [
      '<details class="hint"><summary>Hint: reading /etc/passwd</summary><div><p>The base directory is four levels deep. Each <code>../</code> climbs one level: <code>../../../../etc/passwd</code>. Extra <code>../</code> segments are harmless at the root.</p></div></details>',
      '<details class="hint"><summary>Hint: the secrets file</summary><div><p>Node apps usually keep configuration in a <code>.env</code> file in the project root, one directory above <code>files/</code>.</p></div></details>',
      '<details class="hint"><summary>Hint: beating the filter</summary><div><p>Removing <code>../</code> from <code>....//</code> leaves <code>../</code>. Or encode the dots and slash twice, <code>%252e%252e%252f</code>, so they survive the filter and are decoded by the second decode.</p></div></details>'
    ].join(""),
    onLevel: function () { $("#resolved-path").textContent = "—"; }
  });
})();
