// ============================================================
//  api.js — Toutes les intégrations API externes
//  NVD API v2 · CISA KEV · RSS via CORS proxy
// ============================================================

const NVD_BASE  = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const CISA_KEV  = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const CORS      = url => `https://api.allorigins.win/get?url=${encodeURIComponent(url)}`;
const CORS2     = url => `https://corsproxy.io/?${encodeURIComponent(url)}`;

// ── Clé API NVD (depuis les Paramètres → localStorage) ──────
function getNvdApiKey() {
  try {
    const prefs = JSON.parse(localStorage.getItem('cyberintel_prefs') || '{}');
    return prefs.nvdApiKey || '';
  } catch { return ''; }
}

// ── Headers NVD (injecte la clé si disponible) ───────────────
function nvdHeaders() {
  const key = getNvdApiKey();
  return key ? { 'apiKey': key } : {};
}

// ── cache simple pour éviter les re-fetch inutiles ──────────
const _cache = new Map();
function fromCache(key, ttlMs = 60_000) {
  const hit = _cache.get(key);
  if (hit && Date.now() - hit.ts < ttlMs) return hit.data;
  return null;
}
function toCache(key, data) { _cache.set(key, { data, ts: Date.now() }); }

// ── utilitaire fetch avec timeout ───────────────────────────
async function fetchWithTimeout(url, opts = {}, timeout = 12_000) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeout);
  try {
    const res = await fetch(url, { ...opts, signal: ctrl.signal });
    clearTimeout(timer);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res;
  } catch (e) {
    clearTimeout(timer);
    throw e;
  }
}

// ═══════════════════════════════════════════════════════════
//  NVD API
// ═══════════════════════════════════════════════════════════

/**
 * Recherche CVEs par mot-clé, sévérité ou ID exact
 * Essaie l'API NVD directe, puis deux proxies CORS en fallback.
 * @param {object} params
 * @param {string}  params.keyword   - mot-clé de recherche
 * @param {string}  params.cveId     - ID exact (CVE-XXXX-XXXXX)
 * @param {string}  params.severity  - CRITICAL|HIGH|MEDIUM|LOW
 * @param {number}  params.limit     - nombre max de résultats (défaut 20)
 * @param {number}  params.startIndex
 * @returns {Promise<{cves: Array, total: number}>}
 */
export async function searchCVEs({ keyword = '', cveId = '', severity = '', limit = 20, startIndex = 0 } = {}) {
  const qs = new URLSearchParams({ resultsPerPage: String(limit), startIndex: String(startIndex) });
  if (cveId)    qs.set('cveId', cveId);
  if (keyword)  qs.set('keywordSearch', keyword);
  if (severity) qs.set('cvssV3Severity', severity);

  const url  = `${NVD_BASE}?${qs}`;
  const ckey = `nvd:search:${url}`;

  const cached = fromCache(ckey, 120_000);
  if (cached) return cached;

  // Stratégie: appel direct (avec clé API si dispo) → proxy allorigins → proxy corsproxy.io
  const hdrs = nvdHeaders();
  const attempts = [
    () => fetchWithTimeout(url, { headers: hdrs }, 14_000).then(r => r.json()),
    () => fetchWithTimeout(CORS(url),  {}, 16_000).then(r => r.json()).then(d => JSON.parse(d.contents)),
    () => fetchWithTimeout(CORS2(url), {}, 16_000).then(r => r.json()),
  ];

  let json = null;
  let lastErr = null;
  for (const attempt of attempts) {
    try {
      const data = await attempt();
      // Vérifier que c'est bien une réponse NVD valide
      if (data && (data.totalResults !== undefined || data.vulnerabilities !== undefined)) {
        json = data;
        break;
      }
    } catch (e) {
      lastErr = e;
      // Continuer avec le prochain
    }
  }

  if (!json) {
    throw new Error(lastErr?.message || 'API NVD inaccessible — vérifiez votre connexion');
  }

  const result = {
    total: json.totalResults ?? 0,
    cves: (json.vulnerabilities ?? []).map(parseCVE),
  };
  toCache(ckey, result);
  return result;
}

/** Récupère les CVEs récentes (dernières 24h) pour le dashboard */
export async function getRecentCVEs(limit = 50) {
  const now   = new Date();
  const ago   = new Date(now - 24 * 3600 * 1000);
  const fmt   = d => d.toISOString().split('.')[0] + '%2B00%3A00';

  const url   = `${NVD_BASE}?resultsPerPage=${limit}&pubStartDate=${fmt(ago)}&pubEndDate=${fmt(now)}`;
  const ckey  = `nvd:recent:${limit}`;
  const cached = fromCache(ckey, 300_000);
  if (cached) return cached;

  try {
    const res  = await fetchWithTimeout(url, { headers: nvdHeaders() });
    const json = await res.json();
    const result = (json.vulnerabilities ?? []).map(parseCVE);
    toCache(ckey, result);
    return result;
  } catch {
    return [];
  }
}

/** Parse un item vulnerability NVD → objet normalisé */
function parseCVE(vuln) {
  const cve  = vuln.cve;
  const id   = cve.id;
  const desc = (cve.descriptions ?? []).find(d => d.lang === 'en')?.value ?? 'No description.';
  const pub  = cve.published ?? '';
  const mod  = cve.lastModified ?? '';

  // CVSS v3 en priorité, sinon v2
  let cvss = null, vector = '', severity = 'NONE';
  const m3 = cve.metrics?.cvssMetricV31?.[0] ?? cve.metrics?.cvssMetricV30?.[0];
  const m2 = cve.metrics?.cvssMetricV2?.[0];
  if (m3) {
    cvss     = m3.cvssData.baseScore;
    vector   = m3.cvssData.vectorString ?? '';
    severity = m3.cvssData.baseSeverity ?? cvssToSeverity(cvss);
  } else if (m2) {
    cvss     = m2.cvssData.baseScore;
    vector   = m2.cvssData.vectorString ?? '';
    severity = cvssToSeverity(cvss);
  }

  const refs = (cve.references ?? []).map(r => ({ url: r.url, tags: r.tags ?? [] }));
  const cpes = [];
  (cve.configurations ?? []).forEach(cfg => {
    (cfg.nodes ?? []).forEach(node => {
      (node.cpeMatch ?? []).forEach(c => { if (c.vulnerable) cpes.push(c.criteria); });
    });
  });

  const weaknesses = (cve.weaknesses ?? []).flatMap(w => w.description.map(d => d.value));

  return { id, description: desc, published: pub, modified: mod, cvss, severity, vector, refs, cpes, weaknesses };
}

function cvssToSeverity(score) {
  if (!score) return 'NONE';
  if (score >= 9.0) return 'CRITICAL';
  if (score >= 7.0) return 'HIGH';
  if (score >= 4.0) return 'MEDIUM';
  return 'LOW';
}

// ═══════════════════════════════════════════════════════════
//  CISA KEV (Known Exploited Vulnerabilities)
// ═══════════════════════════════════════════════════════════

let _kevSet = null;
let _kevList = null;

export async function getKEVData() {
  if (_kevList) return { list: _kevList, set: _kevSet };

  // Try direct, then allorigins proxy, then corsproxy.io
  const attempts = [
    () => fetchWithTimeout(CISA_KEV, {}, 10_000).then(r => r.json()),
    () => fetchWithTimeout(CORS(CISA_KEV), {}, 12_000).then(r => r.json()).then(d => JSON.parse(d.contents)),
    () => fetchWithTimeout(CORS2(CISA_KEV), {}, 12_000).then(r => r.json()),
  ];

  for (const attempt of attempts) {
    try {
      const json = await attempt();
      _kevList = json.vulnerabilities ?? [];
      _kevSet  = new Set(_kevList.map(v => v.cveID));
      return { list: _kevList, set: _kevSet };
    } catch { /* try next */ }
  }

  _kevSet  = new Set();
  _kevList = [];
  return { list: [], set: new Set() };
}

export function isKEV(cveId) {
  return _kevSet?.has(cveId) ?? false;
}

// ═══════════════════════════════════════════════════════════
//  CVE Stats pour le dashboard
// ═══════════════════════════════════════════════════════════

export async function getCVEStats() {
  const ckey = 'stats:dashboard';
  const cached = fromCache(ckey, 600_000);
  if (cached) return cached;

  try {
    // Parallèle: comptes par sévérité
    const [crit, high, med, low, kev] = await Promise.allSettled([
      fetchCount('CRITICAL'),
      fetchCount('HIGH'),
      fetchCount('MEDIUM'),
      fetchCount('LOW'),
      getKEVData(),
    ]);

    const stats = {
      critical : crit.status === 'fulfilled' ? crit.value : 0,
      high     : high.status === 'fulfilled' ? high.value : 0,
      medium   : med.status  === 'fulfilled' ? med.value  : 0,
      low      : low.status  === 'fulfilled' ? low.value  : 0,
      kev      : kev.status  === 'fulfilled' ? kev.value.list.length : 0,
    };
    stats.total = stats.critical + stats.high + stats.medium + stats.low;
    toCache(ckey, stats);
    return stats;
  } catch {
    return { critical: 0, high: 0, medium: 0, low: 0, kev: 0, total: 0 };
  }
}

async function fetchCount(severity) {
  const url = `${NVD_BASE}?resultsPerPage=1&cvssV3Severity=${severity}`;
  const res = await fetchWithTimeout(url, { headers: nvdHeaders() }, 8000);
  const j   = await res.json();
  return j.totalResults ?? 0;
}

// ═══════════════════════════════════════════════════════════
//  RSS News Feeds (via proxy CORS)
// ═══════════════════════════════════════════════════════════

export const NEWS_SOURCES = [
  { id: 'hn',    name: 'The Hacker News',  url: 'https://feeds.feedburner.com/TheHackersNews',              color: '#ff3366' },
  { id: 'bc',    name: 'BleepingComputer', url: 'https://www.bleepingcomputer.com/feed/',                   color: '#00d4ff' },
  { id: 'cisa',  name: 'CISA Alerts',      url: 'https://www.cisa.gov/news-network/feeds/alerts',           color: '#a855f7' },
  { id: 'sw',    name: 'SecurityWeek',     url: 'https://feeds.feedblitz.com/securityweek',                 color: '#00e676' },
  { id: 'krebs', name: 'Krebs Security',   url: 'https://krebsonsecurity.com/feed/',                        color: '#ff6b1a' },
  { id: 'naked', name: 'Naked Security',   url: 'https://nakedsecurity.sophos.com/feed/',                   color: '#ffc107' },
];

export async function fetchNewsAll() {
  const results = await Promise.allSettled(
    NEWS_SOURCES.map(src => fetchRSS(src))
  );

  const articles = [];
  results.forEach((r, i) => {
    if (r.status === 'fulfilled') articles.push(...r.value);
    else console.warn(`RSS failed: ${NEWS_SOURCES[i].name}`);
  });

  // Tri par date décroissante
  articles.sort((a, b) => new Date(b.date) - new Date(a.date));
  return articles;
}

async function fetchRSS(source) {
  const ckey = `rss:${source.id}`;
  const cached = fromCache(ckey, 300_000); // 5 min
  if (cached) return cached;

  // Essayer allorigins d'abord, puis corsproxy
  let raw = null;
  for (const proxy of [CORS, CORS2]) {
    try {
      const res = await fetchWithTimeout(proxy(source.url), {}, 8000);
      const j   = await res.json();
      raw = j.contents ?? j;
      if (raw && typeof raw === 'string') break;
    } catch { /* essayer le proxy suivant */ }
  }
  if (!raw) return [];

  const articles = parseRSS(raw, source);
  toCache(ckey, articles);
  return articles;
}

function parseRSS(xml, source) {
  try {
    const parser = new DOMParser();
    const doc    = parser.parseFromString(xml, 'text/xml');
    const items  = [...doc.querySelectorAll('item, entry')];

    return items.slice(0, 15).map(item => {
      const getText = (...sels) => {
        for (const s of sels) {
          const el = item.querySelector(s);
          if (el) return el.textContent.trim();
        }
        return '';
      };

      const title   = getText('title');
      const link    = getText('link') || item.querySelector('link')?.getAttribute('href') || '#';
      const date    = getText('pubDate', 'published', 'updated', 'dc\\:date');
      const desc    = getText('description', 'summary', 'content');
      const excerpt = stripHtml(desc).slice(0, 220);
      const tags    = autoTag(title + ' ' + excerpt);

      return {
        id      : `${source.id}-${hashStr(title)}`,
        source  : source.name,
        sourceId: source.id,
        color   : source.color,
        title,
        link,
        date    : parseDate(date),
        excerpt,
        tags,
      };
    }).filter(a => a.title);
  } catch (e) {
    console.error('RSS parse error', e);
    return [];
  }
}

function stripHtml(html) {
  const tmp = document.createElement('div');
  tmp.innerHTML = html;
  return tmp.textContent || tmp.innerText || '';
}

function parseDate(str) {
  if (!str) return new Date().toISOString();
  const d = new Date(str);
  return isNaN(d) ? new Date().toISOString() : d.toISOString();
}

function hashStr(s) {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (Math.imul(31, h) + s.charCodeAt(i)) | 0;
  return Math.abs(h).toString(36);
}

const TAG_MAP = [
  [/ransomware/i,         'Ransomware'],
  [/phishing/i,           'Phishing'],
  [/zero.?day/i,          'Zero-Day'],
  [/patch|update|fix/i,   'Patch'],
  [/critical|severe/i,    'Critical'],
  [/apt|nation.state/i,   'APT'],
  [/data.?breach|leak/i,  'Data Breach'],
  [/malware|trojan|rat\b/i,'Malware'],
  [/vuln|cve-/i,          'Vulnerability'],
  [/ddos/i,               'DDoS'],
  [/supply.?chain/i,      'Supply Chain'],
  [/ai|artificial/i,      'AI'],
];

function autoTag(text) {
  return TAG_MAP.filter(([rx]) => rx.test(text)).map(([, t]) => t).slice(0, 3);
}

// ═══════════════════════════════════════════════════════════
//  Utilitaires exportés
// ═══════════════════════════════════════════════════════════

export function formatDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleDateString('fr-FR', { day: '2-digit', month: 'short', year: 'numeric' });
}

export function formatDateTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleString('fr-FR', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}

export function timeAgo(iso) {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60_000);
  if (mins < 1)   return 'À l\'instant';
  if (mins < 60)  return `il y a ${mins} min`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24)   return `il y a ${hrs}h`;
  const days = Math.floor(hrs / 24);
  return `il y a ${days}j`;
}

export function severityColor(sev) {
  switch ((sev || '').toUpperCase()) {
    case 'CRITICAL': return 'var(--sev-critical)';
    case 'HIGH':     return 'var(--sev-high)';
    case 'MEDIUM':   return 'var(--sev-medium)';
    case 'LOW':      return 'var(--sev-low)';
    default:         return 'var(--sev-none)';
  }
}

export function cvssColor(score) {
  if (!score) return 'var(--sev-none)';
  if (score >= 9)  return 'var(--sev-critical)';
  if (score >= 7)  return 'var(--sev-high)';
  if (score >= 4)  return 'var(--sev-medium)';
  return 'var(--sev-low)';
}
