/* URL Guard core: regex rules + DFAs + scoring. Runs in browser and Node. */
(function (root) {
  'use strict';

  // ---- 1. Generic table-driven DFA: delta[state][symbol]; 'other' = fallback ----
  function runDFA(d, input, map) {
    let s = d.start;
    for (const ch of input) {
      const row = d.delta[s];
      if (!row) return false;
      const sym = map ? map(ch) : ch;
      s = sym in row ? row[sym] : ('other' in row ? row.other : d.dead);
      if (s === d.dead) return false;
    }
    return d.accept.has(s);
  }

  // ---- 2. Counting DFA: accepts hosts containing 4+ dots (states 0..4, 4 absorbing) ----
  const dotDFA = { start: 0, dead: -1, accept: new Set([4]), delta: {} };
  for (let i = 0; i <= 4; i++) dotDFA.delta[i] = { '.': Math.min(i + 1, 4), other: i };

  // ---- 3. URL structure DFA: scheme "://" host [":" port] [path|query|fragment] ----
  const cls = c => 'htps'.includes(c) ? c : /[a-z]/.test(c) ? 'a' : /\d/.test(c) ? 'd'
    : /[.\-:\/?#@%_=&+~,;!*()$'|\[\]]/.test(c) ? c : 'bad';
  const HOST = { h: 'HOST', t: 'HOST', p: 'HOST', s: 'HOST', a: 'HOST', d: 'HOST', '-': 'HOST', '.': 'HOST',
                 ':': 'PORT', '/': 'PATH', '?': 'PATH', '#': 'PATH' };
  const urlDFA = {
    start: 'S0', dead: 'DEAD', accept: new Set(['HOST', 'PORT', 'PATH']),
    delta: {
      S0: { h: 'S1' }, S1: { t: 'S2' }, S2: { t: 'S3' }, S3: { p: 'S4' },
      S4: { s: 'S5', ':': 'S6' }, S5: { ':': 'S6' }, S6: { '/': 'S7' }, S7: { '/': 'S8' },
      S8: { h: 'HOST', t: 'HOST', p: 'HOST', s: 'HOST', a: 'HOST', d: 'HOST' },
      HOST: HOST,
      PORT: { d: 'PORT', '/': 'PATH', '?': 'PATH', '#': 'PATH' },
      PATH: { other: 'PATH', bad: 'DEAD' }
    }
  };

  // ---- 4. Aho-Corasick: all keywords matched in one pass (a DFA built from a word set) ----
  function buildAC(words) {
    const go = [{}], fail = [0], out = [[]];
    for (const w of words) {
      let s = 0;
      for (const c of w) {
        if (!go[s][c]) { go.push({}); fail.push(0); out.push([]); go[s][c] = go.length - 1; }
        s = go[s][c];
      }
      out[s].push(w);
    }
    const q = Object.values(go[0]);
    while (q.length) {
      const r = q.shift();
      for (const c in go[r]) {
        const s = go[r][c]; q.push(s);
        let f = fail[r];
        while (f && !(c in go[f])) f = fail[f];
        fail[s] = c in go[f] ? go[f][c] : 0;
        out[s] = out[s].concat(out[fail[s]]);
      }
    }
    return text => {
      let s = 0; const found = new Set();
      for (const c of text) {
        while (s && !(c in go[s])) s = fail[s];
        s = c in go[s] ? go[s][c] : 0;
        out[s].forEach(w => found.add(w));
      }
      return [...found];
    };
  }
  const findKeywords = buildAC(['login', 'signin', 'verify', 'secure', 'update', 'account', 'banking',
    'confirm', 'password', 'wallet', 'otp', 'kyc', 'suspend', 'unlock']);

  // ---- 5. Regex rules (each regex is a regular language, i.e. a DFA in disguise) ----
  const RULES = [
    { label: 'IP address used as host',     weight: 3, test: c => /^https?:\/\/(\d{1,3}\.){3}\d{1,3}(?!\d)/.test(c.href) },
    { label: '@ hides the real host',       weight: 3, test: c => /^[a-z]+:\/\/[^\/?#]*@/.test(c.href) },
    { label: 'Punycode (lookalike) domain', weight: 2, test: c => /(^|\.)xn--/.test(c.host) },
    { label: 'Connection is not HTTPS',     weight: 1, test: c => /^http:\/\//.test(c.href) },
    { label: 'Risky top-level domain',      weight: 2, test: c => /\.(zip|tk|top|xyz|click|gq|ml|cf)$/.test(c.host) },
    { label: 'Many hyphens in host',        weight: 1, test: c => /(-[^.]*){3,}/.test(c.host) },
    { label: 'Very long URL',               weight: 1, test: c => c.href.length > 75 },
    { label: 'Heavy %-encoding',            weight: 1, test: c => /(%[0-9a-f]{2}){5,}/.test(c.href) },
    { label: 'URL shortener',               weight: 1, test: c => /^(bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|cutt\.ly|rb\.gy)$/.test(c.host) },
    { label: '4+ dots in host (DFA)',       weight: 2, test: c => runDFA(dotDFA, c.host) },
    { label: 'Malformed structure (DFA)',   weight: 2, test: c => !runDFA(urlDFA, c.href, cls) }
  ];

  const BRANDS = ['paypal', 'google', 'amazon', 'apple', 'microsoft', 'facebook', 'instagram',
    'netflix', 'paytm', 'hdfcbank', 'icicibank'];
  const brandMisuse = h => BRANDS.find(b => h.split(/[.\-]/).includes(b) &&
    !new RegExp('(^|\\.)' + b + '\\.(com|co\\.in|in|net|org)$').test(h));

  // ---- 6. Scoring ----
  function analyze(input) {
    input = String(input).trim();
    let u;
    try { u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(input) ? input : 'https://' + input); }
    catch (e) { return { url: input, score: 3, verdict: 'Suspicious', hits: [{ label: 'Not a valid URL', weight: 3 }] }; }
    const c = { href: u.href.toLowerCase(), host: u.hostname.toLowerCase() };
    const hits = RULES.filter(r => r.test(c)).map(r => ({ label: r.label, weight: r.weight }));
    const kw = findKeywords(c.href.replace(/^[a-z]+:\/\//, ''));
    if (kw.length) hits.push({ label: 'Phishing words: ' + kw.join(', '), weight: Math.min(kw.length, 2) });
    const b = brandMisuse(c.host);
    if (b) hits.push({ label: 'Brand "' + b + '" on an unofficial domain', weight: 3 });
    const score = hits.reduce((n, h) => n + h.weight, 0);
    return { url: u.href, score, hits, verdict: score >= 5 ? 'Dangerous' : score >= 3 ? 'Suspicious' : 'Safe' };
  }

  const api = { analyze, runDFA, dotDFA, urlDFA, buildAC };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.URLGuard = api;
})(typeof self !== 'undefined' ? self : this);
