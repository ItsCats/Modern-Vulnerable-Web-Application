/* Lab 06 — OS Command Injection (with a small POSIX-ish shell interpreter) */
(function () {
  "use strict";
  var M = window.MVWA, $ = M.$, esc = M.escapeHtml, fs = M.vfs;
  var CWD = "/opt/app";

  var ENV = {
    PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    HOME: "/var/www",
    USER: "www-data",
    PWD: CWD,
    FLASK_ENV: "production",
    SENTRY_DSN: "https://3f9c1e@o12345.ingest.sentry.test/77",
    ADMIN_TOKEN: "ndg_adm_b7e14c0f9a"
  };

  var KNOWN_HOSTS = { "example.com": "93.184.215.14", "localhost": "127.0.0.1", "db01.internal": "10.0.4.20", "web01": "10.0.4.12", "gateway": "10.0.4.1" };

  /* ------------------------------------------------------------------
   * Commands. Each returns { out, code }.
   * ---------------------------------------------------------------- */
  var executed = [];   // names of commands that ran successfully (for objectives)

  function fakeIp(host) {
    var h = 0;
    for (var i = 0; i < host.length; i++) h = (h * 31 + host.charCodeAt(i)) >>> 0;
    return "172." + (16 + (h % 16)) + "." + ((h >> 8) % 255) + "." + (1 + ((h >> 16) % 254));
  }

  function ping(args) {
    var count = 4, hosts = [];
    for (var i = 0; i < args.length; i++) {
      if (args[i] === "-c") { count = Math.max(1, Math.min(5, parseInt(args[++i], 10) || 4)); continue; }
      if (args[i].charAt(0) === "-") continue;
      hosts.push(args[i]);
    }
    if (!hosts.length) return { out: "ping: usage error: Destination address required\n", code: 1 };
    var host = hosts[hosts.length - 1];
    var isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
    var isName = /^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/.test(host);
    if (!isIp && !isName) return { out: "ping: " + host + ": Name or service not known\n", code: 2 };
    if (isName && !KNOWN_HOSTS[host] && host.indexOf(".") === -1) return { out: "ping: " + host + ": Name or service not known\n", code: 2 };
    var ip = isIp ? host : (KNOWN_HOSTS[host] || fakeIp(host));
    var lines = ["PING " + host + " (" + ip + ") 56(84) bytes of data."];
    var total = 0;
    for (var n = 1; n <= count; n++) {
      var t = (8 + ((n * 7 + host.length * 3) % 13) + n * 0.37).toFixed(1);
      total += Number(t);
      lines.push("64 bytes from " + ip + ": icmp_seq=" + n + " ttl=56 time=" + t + " ms");
    }
    lines.push("", "--- " + host + " ping statistics ---",
      count + " packets transmitted, " + count + " received, 0% packet loss, time " + (count * 1001 - 1000) + "ms",
      "rtt min/avg/max/mdev = 8.4/" + (total / count).toFixed(3) + "/21.9/3.120 ms");
    return { out: lines.join("\n") + "\n", code: 0 };
  }

  function ls(args) {
    var long = false, all = false, targets = [];
    args.forEach(function (a) {
      if (a.charAt(0) === "-") { long = long || a.indexOf("l") !== -1; all = all || a.indexOf("a") !== -1; }
      else targets.push(a);
    });
    if (!targets.length) targets = ["."];
    var out = "", code = 0;
    targets.forEach(function (t) {
      var p = fs.resolve(CWD, t), st = fs.stat(p);
      if (!st) { out += "ls: cannot access '" + t + "': No such file or directory\n"; code = 2; return; }
      if (targets.length > 1) out += t + ":\n";
      var entries = st.type === "dir" ? fs.list(p) : [{ name: t, type: "file", path: p }];
      entries = entries.filter(function (e) { return all || e.name.charAt(0) !== "."; });
      if (long) {
        out += "total " + entries.length * 4 + "\n";
        entries.forEach(function (e) {
          var s = fs.stat(e.path);
          var mode = e.type === "dir" ? "drwxr-xr-x" : s.readable ? "-rw-r--r--" : "-rw-------";
          var owner = s.readable ? "www-data www-data" : "root     root    ";
          out += mode + " 1 " + owner + " " + String(fs.size(e.path)).padStart(5) + " Oct 30 09:12 " + e.name + "\n";
        });
      } else {
        out += entries.map(function (e) { return e.name; }).join("  ") + (entries.length ? "\n" : "");
      }
    });
    return { out: out, code: code };
  }

  function cat(args, stdin) {
    if (!args.length) return { out: stdin || "", code: 0 };
    var out = "", code = 0;
    args.forEach(function (a) {
      var p = fs.resolve(CWD, a), st = fs.stat(p);
      if (!st) { out += "cat: " + a + ": No such file or directory\n"; code = 1; }
      else if (st.type === "dir") { out += "cat: " + a + ": Is a directory\n"; code = 1; }
      else if (!st.readable) { out += "cat: " + a + ": Permission denied\n"; code = 1; }
      else out += fs.read(p);
    });
    return { out: out, code: code };
  }

  var COMMANDS = {
    ping: ping,
    ls: ls,
    cat: cat,
    whoami: function () { return { out: "www-data\n", code: 0 }; },
    id: function () { return { out: "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n", code: 0 }; },
    hostname: function () { return { out: "web01\n", code: 0 }; },
    pwd: function () { return { out: CWD + "\n", code: 0 }; },
    uname: function (a) { return { out: (a.indexOf("-a") !== -1 ? "Linux web01 6.8.0-45-generic #45-Ubuntu SMP PREEMPT_DYNAMIC x86_64 GNU/Linux" : "Linux") + "\n", code: 0 }; },
    echo: function (a) { return { out: a.join(" ") + "\n", code: 0 }; },
    env: function () { return { out: Object.keys(ENV).map(function (k) { return k + "=" + ENV[k]; }).join("\n") + "\n", code: 0 }; },
    printenv: function (a) { return a.length ? { out: (ENV[a[0]] || "") + "\n", code: ENV[a[0]] ? 0 : 1 } : COMMANDS.env(a); },
    ps: function () {
      return { out: "  PID TTY          TIME CMD\n    1 ?        00:00:03 gunicorn\n   14 ?        00:01:12 gunicorn\n  211 ?        00:00:00 sh\n  212 ?        00:00:00 ps\n", code: 0 };
    },
    head: function (a, stdin) {
      var n = 10, files = [];
      for (var i = 0; i < a.length; i++) { if (a[i] === "-n") n = parseInt(a[++i], 10) || 10; else if (/^-\d+$/.test(a[i])) n = -parseInt(a[i], 10); else files.push(a[i]); }
      var src = files.length ? cat(files) : { out: stdin || "", code: 0 };
      return { out: src.out.split("\n").slice(0, n).join("\n") + "\n", code: src.code };
    },
    grep: function (a, stdin) {
      var pat = a[0];
      if (pat === undefined) return { out: "Usage: grep PATTERN [FILE]...\n", code: 2 };
      var src = a.length > 1 ? cat(a.slice(1)) : { out: stdin || "" };
      var hits = src.out.split("\n").filter(function (l) { return l.indexOf(pat) !== -1; });
      return { out: hits.length ? hits.join("\n") + "\n" : "", code: hits.length ? 0 : 1 };
    },
    wc: function (a, stdin) {
      var src = a.filter(function (x) { return x.charAt(0) !== "-"; });
      var text = src.length ? cat(src).out : stdin || "";
      var lines = (text.match(/\n/g) || []).length;
      return { out: (a.indexOf("-l") !== -1 ? String(lines) : lines + " " + text.split(/\s+/).filter(Boolean).length + " " + text.length) + "\n", code: 0 };
    },
    base64: function (a, stdin) { try { return { out: btoa(stdin || "") + "\n", code: 0 }; } catch (e) { return { out: "base64: invalid input\n", code: 1 }; } },
    sleep: function () { return { out: "", code: 0 }; },
    true: function () { return { out: "", code: 0 }; },
    false: function () { return { out: "", code: 1 }; },
    rm: function (a) { return { out: "rm: cannot remove '" + (a.filter(function (x) { return x.charAt(0) !== "-"; })[0] || "") + "': Permission denied\n", code: 1 }; },
    curl: function () { return { out: "curl: (7) Failed to connect: outbound traffic is disabled in this lab\n", code: 7 }; },
    wget: function () { return { out: "wget: unable to resolve host address: outbound traffic is disabled in this lab\n", code: 4 }; },
    nc: function () { return { out: "sh: 1: nc: not found\n", code: 127 }; },
    bash: function () { return { out: "", code: 0 }; },
    sh: function () { return { out: "", code: 0 }; }
  };
  COMMANDS["/bin/ping"] = ping;

  /* ------------------------------------------------------------------
   * Shell: quoting, $VAR / ${VAR}, $(...) and `...` substitution (with
   * field splitting, never re-parsed as syntax), ; && || & |, and
   * redirections (> >> < 2>&1). stdout and stderr are kept separate.
   * ---------------------------------------------------------------- */
  var VARS = { IFS: " \t\n" };
  Object.keys(ENV).forEach(function (k) { VARS[k] = ENV[k]; });
  var subErr = "";   // stderr produced inside command substitutions

  function substitute(inner, depth) {
    if (depth > 5) return "";
    var r = runScript(inner, depth + 1);
    subErr += r.err;
    return r.out.replace(/\n+$/, "");
  }

  function parse(src, depth) {
    var tokens = [], word = "", inWord = false, quote = null;
    function push() { if (inWord) tokens.push({ w: word }); word = ""; inWord = false; }
    function expansion(text) {
      if (quote === '"') { word += text; inWord = true; return; }
      text.split(/[ \t\n]+/).forEach(function (part, idx) {   // field splitting
        if (idx > 0) push();
        if (part) { word += part; inWord = true; }
      });
    }
    function matchParen(from) {
      var d = 1, q = null;
      for (var j = from; j < src.length; j++) {
        var ch = src[j];
        if (q) { if (ch === q) q = null; continue; }
        if (ch === "'" || ch === '"') { q = ch; continue; }
        if (ch === "(") d++;
        else if (ch === ")" && --d === 0) return j;
      }
      return -1;
    }
    for (var i = 0; i < src.length; i++) {
      var c = src[i], n = src[i + 1];
      if (quote === "'") { if (c === "'") quote = null; else word += c; continue; }
      if (c === "\\" && quote === '"' && /[$`"\\]/.test(n || "")) { word += n; i++; continue; }
      if (c === "$" && n === "(") {
        var close = matchParen(i + 2);
        if (close === -1) return { error: 'sh: 1: Syntax error: end of file unexpected (expecting ")")' };
        expansion(substitute(src.slice(i + 2, close), depth));
        i = close; continue;
      }
      if (c === "`") {
        var endB = src.indexOf("`", i + 1);
        if (endB === -1) return { error: "sh: 1: Syntax error: EOF in backquote substitution" };
        expansion(substitute(src.slice(i + 1, endB), depth));
        i = endB; continue;
      }
      if (c === "$" && n === "{") {
        var endV = src.indexOf("}", i + 2);
        if (endV === -1) return { error: "sh: 1: Syntax error: Missing '}'" };
        expansion(VARS[src.slice(i + 2, endV)] || "");
        i = endV; continue;
      }
      if (c === "$" && /[A-Za-z_]/.test(n || "")) {
        var name = /^[A-Za-z_][A-Za-z0-9_]*/.exec(src.slice(i + 1))[0];
        expansion(VARS[name] || "");
        i += name.length; continue;
      }
      if (quote === '"') { if (c === '"') quote = null; else word += c; continue; }
      if (c === "'" || c === '"') { quote = c; inWord = true; continue; }
      if (c === "\\" && n !== undefined) { word += n; inWord = true; i++; continue; }
      if (c === " " || c === "\t") { push(); continue; }
      if (c === "\n" || c === ";") { push(); tokens.push({ op: ";" }); continue; }
      if (c === "&" && n === "&") { push(); tokens.push({ op: "&&" }); i++; continue; }
      if (c === "|" && n === "|") { push(); tokens.push({ op: "||" }); i++; continue; }
      if (c === "&") { push(); tokens.push({ op: ";" }); continue; }        // background: run sequentially
      if (c === "|") { push(); tokens.push({ op: "|" }); continue; }
      if (c === ">" || c === "<") {
        var fd = c === "<" ? 0 : 1;
        if (inWord && /^\d$/.test(word)) { fd = Number(word); word = ""; inWord = false; } else push();
        if (c === ">" && n === ">") i++;
        var dup = /^&(\d)/.exec(src.slice(i + 1));
        if (dup) { tokens.push({ op: "dup", fd: fd, to: Number(dup[1]) }); i += 2; continue; }
        tokens.push({ op: "redir", fd: fd });
        continue;
      }
      if (c === "#" && !inWord) { while (i + 1 < src.length && src[i + 1] !== "\n") i++; continue; }
      word += c; inWord = true;
    }
    if (quote) return { error: "sh: 1: Syntax error: Unterminated quoted string" };
    push();
    return { tokens: tokens };
  }

  function build(tokens) {
    var list = [], pipeline = [], cmd = { words: [], redirs: [] }, pending = null;
    for (var i = 0; i < tokens.length; i++) {
      var t = tokens[i];
      if (t.w !== undefined) {
        if (pending) { pending.target = t.w; cmd.redirs.push(pending); pending = null; }
        else cmd.words.push(t.w);
        continue;
      }
      if (pending) return { error: "sh: 1: Syntax error: redirection unexpected" };
      if (t.op === "redir") { pending = { fd: t.fd }; continue; }
      if (t.op === "dup") { cmd.redirs.push({ fd: t.fd, dup: t.to }); continue; }
      pipeline.push(cmd);
      cmd = { words: [], redirs: [] };
      if (t.op === "|") continue;
      list.push({ pipeline: pipeline, op: t.op });
      pipeline = [];
    }
    if (pending) return { error: "sh: 1: Syntax error: newline unexpected" };
    pipeline.push(cmd);
    list.push({ pipeline: pipeline, op: null });
    return { list: list };
  }

  function runCommand(words, stdin) {
    var name = words[0];
    var fn = Object.prototype.hasOwnProperty.call(COMMANDS, name) ? COMMANDS[name] : null;
    if (!fn) return { out: "", err: "sh: 1: " + name + ": not found\n", code: 127 };
    var r = fn(words.slice(1), stdin);
    if (r.code === 0) executed.push(name);
    // Commands report failures as a single message: route it to stderr.
    return r.code === 0 ? { out: r.out, err: "", code: 0 } : { out: "", err: r.out, code: r.code };
  }

  function execSimple(cmd, stdin) {
    var table = { 1: "out", 2: "err" };
    for (var i = 0; i < cmd.redirs.length; i++) {
      var rd = cmd.redirs[i];
      if (rd.dup !== undefined) { table[rd.fd] = table[rd.dup] || "out"; continue; }
      var target = fs.resolve(CWD, rd.target);
      if (rd.fd === 0) {
        var st = fs.stat(target);
        if (!st || st.type !== "file" || !st.readable) return { out: "", err: "sh: 1: cannot open " + rd.target + ": " + (st ? "Permission denied" : "No such file") + "\n", code: 2 };
        stdin = fs.read(target);
        continue;
      }
      if (target !== "/dev/null" && target.indexOf("/tmp/") !== 0) return { out: "", err: "sh: 1: cannot create " + rd.target + ": Permission denied\n", code: 2 };
      table[rd.fd] = "null";
    }
    if (!cmd.words.length) return { out: "", err: "", code: 0 };
    var r = runCommand(cmd.words, stdin);
    var res = { out: "", err: "", code: r.code };
    if (table[1] !== "null") res[table[1]] += r.out;
    if (table[2] !== "null") res[table[2]] += r.err;
    return res;
  }

  // Returns { out (stdout), err, display (what a terminal shows), code }.
  function runScript(src, depth) {
    depth = depth || 0;
    var p = parse(src, depth);
    if (p.error) return { out: "", err: p.error + "\n", display: p.error + "\n", code: 2 };
    var b = build(p.tokens);
    if (b.error) return { out: "", err: b.error + "\n", display: b.error + "\n", code: 2 };

    var out = "", err = "", display = "", last = 0, prevOp = null;
    for (var i = 0; i < b.list.length; i++) {
      var entry = b.list[i];
      var empty = entry.pipeline.length === 1 && !entry.pipeline[0].words.length && !entry.pipeline[0].redirs.length;
      if (empty) {
        if (entry.op && entry.op !== ";") {
          var se = 'sh: 1: Syntax error: "' + entry.op + '" unexpected\n';
          return { out: out, err: err + se, display: display + se, code: 2 };
        }
        prevOp = entry.op; continue;
      }
      if ((prevOp === "&&" && last !== 0) || (prevOp === "||" && last === 0)) { prevOp = entry.op; continue; }
      var stdin = "", res = null;
      for (var j = 0; j < entry.pipeline.length; j++) {
        var cmd = entry.pipeline[j];
        if (!cmd.words.length && !cmd.redirs.length) {
          var pe = 'sh: 1: Syntax error: "|" unexpected\n';
          return { out: out, err: err + pe, display: display + pe, code: 2 };
        }
        res = execSimple(cmd, stdin);
        err += res.err; display += res.err;
        stdin = res.out;
      }
      out += res.out; display += res.out;
      last = res.code;
      prevOp = entry.op;
    }
    return { out: out, err: err, display: display, code: last };
  }

  /* ------------------------------------------------------------------
   * The diagnostics endpoint for each level
   * ---------------------------------------------------------------- */
  var BLOCKLIST = [";", "&&", "|"];
  var HOST_RE = /^(?=.{1,253}$)[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?$/;

  function endpoint(host) {
    var level = M.getLevel();
    executed = [];
    subErr = "";
    if (level === "medium") {
      for (var i = 0; i < BLOCKLIST.length; i++) {
        if (host.indexOf(BLOCKLIST[i]) !== -1) return { status: 400, cmd: null, out: "Invalid characters in host: \"" + BLOCKLIST[i] + "\"\n", code: 1 };
      }
    }
    if (level === "high") {
      if (!HOST_RE.test(host)) return { status: 400, cmd: null, out: "Invalid host. Enter a hostname or IPv4 address.\n", code: 1 };
      var r = ping(["-c", "2", "--", host]);
      return { status: r.code === 0 ? 200 : 502, cmd: ["ping", "-c", "2", "--", host], out: r.out, code: r.code, argv: true };
    }
    var cmd = "ping -c 2 " + host;
    var res = runScript(cmd);
    return { status: 200, cmd: cmd, out: subErr + res.display, code: res.code };
  }

  function submit(host) {
    var level = M.getLevel();
    var res = endpoint(host);
    var term = $("#ci-term");
    var head;
    if (res.argv) {
      head = '<span class="dim"># subprocess.run(' + esc(JSON.stringify(res.cmd).replace(/,/g, ", ")) + ")  (no shell)</span>\n";
    } else if (res.cmd) {
      head = '<span class="prompt">www-data@web01:/opt/app$</span> ping -c 2 <span class="inj">' + esc(host) + "</span>\n";
    } else {
      head = '<span class="err">HTTP 400</span> <span class="dim">request rejected before execution</span>\n';
    }
    term.innerHTML = head + esc(res.out) + (res.cmd && !res.argv ? '<span class="dim">[exit ' + res.code + "]</span>" : "");

    var injected = executed.filter(function (n) { return n !== "ping" && n !== "/bin/ping" && n !== "true" && n !== "false" && n !== "sleep"; });
    if (level !== "high" && injected.length) {
      M.complete("ci-exec");
      if (level === "medium") M.complete("ci-medium");
    }
    if (level !== "high" && res.out.indexOf(fs.FLAG_CI) !== -1) M.complete("ci-flag");
  }

  $("#ci-form").addEventListener("submit", function (e) {
    e.preventDefault();
    submit($("#ci-host").value);
  });

  M.initLab({
    id: "command-injection",
    levels: {
      low: "The host is appended to a shell command string and run with shell=True, so every shell metacharacter works.",
      medium: "Requests containing ;, && or | are rejected. Other shell syntax is not checked.",
      high: "The host must match a strict hostname/IPv4 pattern and ping is run with an argument array, so no shell is involved."
    },
    hints: [
      '<details class="hint"><summary>Hint: running your own command</summary><div><p>A shell runs commands separated by <code>;</code> one after the other. Try <code>example.com; whoami</code>.</p></div></details>',
      '<details class="hint"><summary>Hint: finding the flag</summary><div><p>Look around with <code>; ls -la</code>, then <code>; cat flag.txt</code>. The app runs from <code>/opt/app</code>.</p></div></details>',
      '<details class="hint"><summary>Hint: beating the blocklist</summary><div><p>Command substitution is still allowed: <code>$(whoami)</code> or backticks run first, and their output appears in ping\'s error message. A single <code>&amp;</code> also separates commands.</p></div></details>'
    ].join("")
  });
})();
