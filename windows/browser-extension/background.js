// AegisGuard Browser Extension - Background Service Worker
// Intercepts navigation to explicit URLs, search queries, and social trigger tabs (Reels/Explore/Shorts).

const LEET_MAP = {
  '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's',
  '7': 't', '8': 'b', '@': 'a', '$': 's', '!': 'i'
};

const HIGH_RISK = [
  'porno', 'porn', 'pornhub', 'xvideos', 'xnxx', 'xhamster', 'redtube', 'youporn',
  'spankbang', 'onlyfans', 'fansly', 'chaturbate', 'stripchat', 'hentai', 'rule34',
  'nsfw', 'xxx', 'pornografia', 'nudes', 'desnuda', 'desnudas', 'desnudo', 'tetas',
  'boobs', 'tits', 'pussy', 'verga', 'polla', 'cock', 'mamada', 'blowjob', 'cumshot',
  'creampie', 'milf', 'bdsm', 'fetish', 'erotico', 'erotica', 'camgirl', 'escort',
  'follando', 'cogiendo', 'cojiendo', 'cachonda', 'masturbacion', 'erome', 'redgifs',
  'fapello', 'coomer', 'sin censura', 'uncensored', 'bikini try on', 'transparent haul'
];

const SAFE_CONTEXTS = [
  'educacion sexual', 'salud sexual', 'biologia', 'anatomia', 'medicina',
  'analisis', 'computadora', 'hot dog', 'hotspot', 'pack de iconos', 'ford escort'
];

const TRIGGER_PATHS = [
  { host: 'instagram.com', paths: ['/explore', '/reels'] },
  { host: 'youtube.com', paths: ['/shorts'] },
  { host: 'tiktok.com', paths: ['/foryou', '/live', '/explore'] },
  { host: 'x.com', paths: ['/explore'] },
  { host: 'twitter.com', paths: ['/explore'] },
  { host: 'facebook.com', paths: ['/reel', '/reels'] },
  { host: 'reddit.com', paths: ['/r/popular', '/r/all'] }
];

function normalizeText(input) {
  let s = (input || '').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
  s = s.replace(/[\u200B-\u200D\uFEFF]/g, '');
  s = Array.from(s).map(ch => LEET_MAP[ch] || ch).join('');
  s = s.replace(/[^a-z0-9]+/g, ' ').trim();
  // Collapse triple+ letter repeats
  s = s.replace(/([a-z])\1{2,}/g, '$1');
  // Join single-letter runs ("p o r n o" -> "porno")
  const tokens = s.split(/\s+/);
  const out = [];
  let run = [];
  const flush = () => {
    if (run.length >= 3) out.push(run.join(''));
    else out.push(...run);
    run = [];
  };
  for (const t of tokens) {
    if (t.length === 1) run.push(t);
    else { flush(); out.push(t); }
  }
  flush();
  return out.join(' ');
}

function isExplicitText(raw) {
  let norm = normalizeText(raw);
  if (!norm) return null;
  for (const safe of SAFE_CONTEXTS) {
    norm = norm.replaceAll(safe, ' ');
  }
  const padded = ' ' + norm + ' ';
  const compact = norm.replace(/\s+/g, '');
  for (const term of HIGH_RISK) {
    if (padded.includes(' ' + term + ' ') || (term.length >= 5 && compact.includes(term))) {
      return term;
    }
  }
  return null;
}

function checkUrl(urlStr) {
  try {
    const u = new URL(urlStr);
    if (u.protocol === 'chrome-extension:' || u.hostname === '127.0.0.1' || u.hostname === 'localhost') {
      return null;
    }
    const host = u.hostname.toLowerCase();
    const path = u.pathname.toLowerCase();

    // 1. Trigger tabs in social media
    for (const rule of TRIGGER_PATHS) {
      if (host === rule.host || host.endsWith('.' + rule.host)) {
        for (const p of rule.paths) {
          if (path.startsWith(p)) {
            return `Pestaña disparadora bloqueada (${rule.host}${p})`;
          }
        }
      }
    }

    // 2. Explicit terms in URL path or query parameters (Google, Bing, Reddit, X, TikTok, Instagram, YouTube)
    const decoded = decodeURIComponent(u.hostname + ' ' + u.pathname + ' ' + u.search);
    const hit = isExplicitText(decoded);
    if (hit) {
      return `Búsqueda o URL explícita bloqueada (${hit})`;
    }
  } catch (_) {}
  return null;
}

function redirectToBlocked(tabId, reason) {
  const blockedUrl = chrome.runtime.getURL('blocked.html') + '?reason=' + encodeURIComponent(reason);
  chrome.tabs.update(tabId, { url: blockedUrl });
}

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return;
  const reason = checkUrl(details.url);
  if (reason) redirectToBlocked(details.tabId, reason);
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  const url = changeInfo.url || (tab && tab.url);
  if (!url) return;
  const reason = checkUrl(url);
  if (reason) redirectToBlocked(tabId, reason);
});
