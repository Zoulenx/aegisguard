// AegisGuard Content Script — Real-time search box guard & social feed trigger cleaner.
(function () {
  const LEET = { '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '@': 'a', '$': 's' };
  const TERMS = [
    'porno', 'porn', 'pornhub', 'xvideos', 'xnxx', 'xhamster', 'onlyfans', 'fansly',
    'hentai', 'rule34', 'nsfw', 'xxx', 'nudes', 'desnuda', 'desnudas', 'desnudo',
    'tetas', 'boobs', 'pussy', 'verga', 'polla', 'mamada', 'blowjob', 'milf',
    'erome', 'redgifs', 'fapello', 'sin censura', 'cachonda', 'follando', 'cogiendo'
  ];

  function normalize(str) {
    let s = (str || '').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
    s = s.replace(/[\u200B-\u200D\uFEFF]/g, '');
    s = Array.from(s).map(c => LEET[c] || c).join('');
    s = s.replace(/[^a-z0-9]+/g, ' ').replace(/([a-z])\1{2,}/g, '$1').trim();
    return s;
  }

  function detectExplicit(val) {
    const norm = normalize(val);
    if (!norm) return null;
    const padded = ' ' + norm + ' ';
    const compact = norm.replace(/\s+/g, '');
    for (const t of TERMS) {
      if (padded.includes(' ' + t + ' ') || (t.length >= 5 && compact.includes(t))) {
        return t;
      }
    }
    return null;
  }

  function blockNow(reason) {
    window.stop();
    window.location.replace(
      chrome.runtime.getURL('blocked.html') + '?reason=' + encodeURIComponent(reason)
    );
  }

  // Intercept typing inside search inputs across all social media web apps
  document.addEventListener('input', (e) => {
    const el = e.target;
    if (!el) return;
    const value = el.value !== undefined ? el.value : el.innerText;
    if (!value || value.length < 3) return;
    const hit = detectExplicit(value);
    if (hit) {
      if (el.value !== undefined) el.value = '';
      else el.innerText = '';
      blockNow('Búsqueda explícita interceptada en tiempo real (' + hit + ')');
    }
  }, true);

  // Intercept form submissions
  document.addEventListener('submit', (e) => {
    const inputs = e.target.querySelectorAll('input, textarea');
    for (const inp of inputs) {
      const hit = detectExplicit(inp.value || '');
      if (hit) {
        e.preventDefault();
        e.stopPropagation();
        inp.value = '';
        blockNow('Envío de búsqueda explícita bloqueado (' + hit + ')');
        return;
      }
    }
  }, true);
})();
