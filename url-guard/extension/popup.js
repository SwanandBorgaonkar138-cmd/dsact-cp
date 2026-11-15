const colors = { Safe: '#1F7A4D', Suspicious: '#B96A00', Dangerous: '#B3261E' };
chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
  const v = document.getElementById('v'), m = document.getElementById('m'), l = document.getElementById('l');
  if (!tab || !/^https?:/.test(tab.url || '')) { v.textContent = 'Open a web page'; return; }
  const r = URLGuard.analyze(tab.url);
  v.textContent = r.verdict; v.style.color = colors[r.verdict];
  m.textContent = 'Risk score ' + r.score + ' for ' + r.url;
  (r.hits.length ? r.hits : [{ label: 'No warning signs found', weight: 0 }]).forEach(h => {
    const li = document.createElement('li'), s = document.createElement('span'), b = document.createElement('b');
    s.textContent = h.label; b.textContent = '+' + h.weight; li.append(s, b); l.appendChild(li);
  });
});
