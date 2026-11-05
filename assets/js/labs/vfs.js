/*
 * Simulated Linux server file system shared by the Path Traversal and
 * Command Injection labs. Paths use POSIX semantics; helpers mirror Node's
 * path.join / path.resolve closely enough for the vulnerabilities to behave
 * exactly as they would on a real server.
 */
(function () {
  "use strict";

  var FLAG_ENV = "FLAG{p4th_tr4v3rs4l_l34ks_s3cr3ts}";
  var FLAG_CI = "FLAG{sh3ll_m3t4ch4r4ct3rs_ftw}";

  var FILES = {
    "/etc/passwd": [
      "root:x:0:0:root:/root:/bin/bash",
      "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
      "bin:x:2:2:bin:/bin:/usr/sbin/nologin",
      "sys:x:3:3:sys:/dev:/usr/sbin/nologin",
      "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
      "postgres:x:113:120:PostgreSQL administrator:/var/lib/postgresql:/bin/bash",
      "deploy:x:1000:1000:Deploy User:/home/deploy:/bin/bash"
    ].join("\n") + "\n",
    "/etc/hostname": "web01\n",
    "/etc/hosts": "127.0.0.1\tlocalhost\n10.0.4.12\tweb01\n10.0.4.20\tdb01.internal\n",
    "/etc/os-release": 'PRETTY_NAME="Ubuntu 24.04.1 LTS"\nNAME="Ubuntu"\nVERSION_ID="24.04"\n',
    "/etc/shadow": null, // exists, but unreadable by www-data
    "/home/deploy/.ssh/id_ed25519": null,
    "/home/deploy/.bash_history": null,
    "/root/.bashrc": null,

    "/var/www/docs/server.js": "const express = require(\"express\");\nconst app = express();\nrequire(\"./routes/download\")(app);\napp.listen(8080);\n",
    "/var/www/docs/package.json": '{\n  "name": "contoso-docs",\n  "version": "2.3.1",\n  "dependencies": { "express": "^4.21.0" }\n}\n',
    "/var/www/docs/.env": [
      "NODE_ENV=production",
      "DATABASE_URL=postgres://docs_app:Wv8#rT2!qLm9@db01.internal:5432/docs",
      "JWT_SECRET=4e1f9a7c2b8d6e3f0a5c9b2d7e4f1a8c",
      "AWS_ACCESS_KEY_ID=AKIAEXAMPLE7Q2LMNOP",
      "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      "CANARY=" + FLAG_ENV
    ].join("\n") + "\n",
    "/var/www/docs/files/Q3-financial-summary.txt":
      "CONTOSO LTD. Q3 FINANCIAL SUMMARY\n=================================\nRevenue:          $4.21M  (+12% QoQ)\nOperating costs:  $3.02M\nNet margin:        28.3%\n\nPrepared by Finance. Approved for internal distribution.\n",
    "/var/www/docs/files/employee-handbook.txt":
      "EMPLOYEE HANDBOOK (v7)\n\n1. Working hours are flexible between 07:00 and 19:00.\n2. Report security incidents to security@contoso.test.\n3. Never share credentials, even with IT staff.\n",
    "/var/www/docs/files/release-notes.md":
      "# Contoso Docs 2.3.1\n\n- Faster PDF export\n- Fixed: download links for files with spaces\n- New: audit log retention set to 90 days\n",

    "/opt/app/app.py": "import subprocess\nfrom flask import Flask, request\napp = Flask(__name__)\n\n@app.post('/diagnostics/ping')\ndef ping():\n    host = request.form['host']\n    return subprocess.check_output('ping -c 2 ' + host, shell=True)\n",
    "/opt/app/requirements.txt": "flask==3.0.3\ngunicorn==23.0.0\n",
    "/opt/app/flag.txt": FLAG_CI + "\n",
    "/opt/app/config.yaml": "debug: false\nadmin_email: ops@netdiag.test\nallowed_targets: any\n"
  };

  var DIRS = {};
  Object.keys(FILES).forEach(function (f) {
    var parts = f.split("/").slice(1, -1), cur = "";
    DIRS["/"] = true;
    parts.forEach(function (p) { cur += "/" + p; DIRS[cur] = true; });
  });

  function normalize(p) {
    var out = [];
    String(p).split("/").forEach(function (seg) {
      if (!seg || seg === ".") return;
      if (seg === "..") { if (out.length) out.pop(); }
      else out.push(seg);
    });
    return "/" + out.join("/");
  }

  // Node's path.join: concatenates, then normalizes. An absolute 2nd arg stays relative.
  function join(base, p) { return normalize(base + "/" + p); }

  // Node's path.resolve: an absolute 2nd arg wins.
  function resolve(base, p) { return String(p).charAt(0) === "/" ? normalize(p) : normalize(base + "/" + p); }

  function stat(path) {
    var p = normalize(path);
    if (Object.prototype.hasOwnProperty.call(FILES, p)) return { type: "file", readable: FILES[p] !== null };
    if (DIRS[p]) return { type: "dir", readable: true };
    return null;
  }

  function read(path) { return FILES[normalize(path)]; }

  function list(dir) {
    var d = normalize(dir);
    var prefix = d === "/" ? "/" : d + "/";
    var names = {};
    Object.keys(FILES).concat(Object.keys(DIRS)).forEach(function (p) {
      if (p !== d && p.indexOf(prefix) === 0) {
        var rest = p.slice(prefix.length).split("/")[0];
        if (rest) names[rest] = DIRS[prefix + rest] ? "dir" : "file";
      }
    });
    return Object.keys(names).sort().map(function (n) { return { name: n, type: names[n], path: prefix + n }; });
  }

  function size(path) { var c = read(path); return c ? c.length : 4096; }

  window.MVWA = window.MVWA || {};
  window.MVWA.vfs = {
    FLAG_ENV: FLAG_ENV,
    FLAG_CI: FLAG_CI,
    normalize: normalize,
    join: join,
    resolve: resolve,
    stat: stat,
    read: read,
    list: list,
    size: size
  };
})();
