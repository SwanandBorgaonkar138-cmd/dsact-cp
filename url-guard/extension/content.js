// Outlines risky links on every page and explains why in a tooltip.
const COLORS = { Suspicious: '#B96A00', Dangerous: '#B3261E' };
function scan() {
  document.querySelectorAll('a[href]').forEach(a => {
    if (a.dataset.ug || !/^https?:/i.test(a.href)) return;
    a.dataset.ug = '1';
    const r = URLGuard.analyze(a.href);
    if (r.verdict === 'Safe') return;
    a.style.outline = '2px solid ' + COLORS[r.verdict];
    a.title = 'URL Guard: ' + r.verdict + ' (' + r.hits.map(h => h.label).join(', ') + ')';
  });
}
scan();
let timer;
new MutationObserver(() => { clearTimeout(timer); timer = setTimeout(scan, 500); })
  .observe(document.body, { childList: true, subtree: true });
