// Run: node tests/test.js   (optional tests/urls.csv with lines "bad,<url>" or "good,<url>")
const fs = require('fs');
const { analyze } = require('../core/detector.js');
const S = [
  ['bad', 'http://paypal.com@evil.tk/login'],
  ['bad', 'http://paypal.com.secure-verify.xyz/login'],
  ['bad', 'https://xn--pypal-4ve.com/account/verify'],
  ['bad', 'http://login-update-secure-account.tk/otp'],
  ['bad', 'https://hdfcbank.verify-kyc-now.top/update'],
  ['bad', 'http://192.168.1.5/verify/account'],
  ['good', 'https://www.google.com/search?q=dfa'],
  ['good', 'https://github.com/anthropics'],
  ['good', 'https://en.wikipedia.org/wiki/Deterministic_finite_automaton'],
  ['good', 'https://www.amazon.in/gp/cart'],
  ['good', 'https://accounts.google.com/signin'],
  ['good', 'http://example.com/']
];
const csv = __dirname + '/urls.csv';
if (fs.existsSync(csv)) fs.readFileSync(csv, 'utf8').split('\n').forEach(l => {
  const [a, ...b] = l.trim().split(','); if (a && b.length) S.push([a, b.join(',')]);
});
let tp = 0, tn = 0, fp = 0, fn = 0;
for (const [label, url] of S) {
  const r = analyze(url), flagged = r.verdict !== 'Safe';
  if (label === 'bad') { if (flagged) tp++; else { fn++; console.log('MISSED     ', url, r.score); } }
  else { if (flagged) { fp++; console.log('FALSE ALARM', url, r.score); } else tn++; }
}
console.log({ total: S.length, tp, tn, fp, fn, accuracy: ((tp + tn) / S.length * 100).toFixed(1) + '%' });
