// ============================================================
//  app.js — Routeur principal Cyberlens
// ============================================================
// v=10 sur chaque import pour invalider le cache ES module du navigateur
import * as Dashboard  from './modules/dashboard.js?v=15';
import * as CVE        from './modules/cve.js?v=15';
import * as Exploit    from './modules/exploit.js?v=15';
import * as News       from './modules/news.js?v=15';
import * as RedTeam    from './modules/redteam.js?v=15';
import * as BlueTeam   from './modules/blueteam.js?v=15';
import * as Simulator  from './modules/simulator.js?v=15';

// ── Vues enregistrées ────────────────────────────────────────
const VIEWS = {
  dashboard  : { module: Dashboard,  label: 'Dashboard',     icon: '⬛' },
  cve        : { module: CVE,        label: 'CVE Search',    icon: '🔍' },
  exploit    : { module: Exploit,    label: 'Exploit Lab',   icon: '🧪' },
  news       : { module: News,       label: 'Threat News',   icon: '📰' },
  simulator  : { module: Simulator,  label: 'Simulator',     icon: '💻' },
  redteam    : { module: RedTeam,    label: 'Red Team',      icon: '⚔️'  },
  blueteam   : { module: BlueTeam,   label: 'Blue Team',     icon: '🛡️' },
  'threat-map': { render: renderThreatMap, label: 'Threat Map', icon: '🗺️' },
  settings   : { render: renderSettings,  label: 'Paramètres',  icon: '⚙️' },
};

let _currentView = '';

// ── App init ─────────────────────────────────────────────────
async function init() {
  setupClock();
  setupSidebar();
  setupTopbar();
  setupNavigation();
  setupRefreshBtn();
  startTicker();

  // Naviguer vers la vue initiale
  const hash = location.hash.replace('#','') || 'dashboard';
  await navigate(hash in VIEWS ? hash : 'dashboard');

  // Exposer navigate globalement pour les modules
  window.__app = { navigate, showToast };
}

// ── Navigation ───────────────────────────────────────────────
async function navigate(viewId, params = {}) {
  if (viewId === _currentView && !params) return;
  _currentView = viewId;

  const view    = VIEWS[viewId];
  const content = document.getElementById('content');
  const bcCurrent = document.getElementById('breadcrumb-current');

  if (!view || !content) return;

  // Mettre à jour l'URL
  location.hash = viewId;

  // Breadcrumb
  if (bcCurrent) bcCurrent.textContent = view.label;

  // Nav active
  document.querySelectorAll('.nav-item').forEach(item => {
    item.classList.toggle('active', item.dataset.view === viewId);
  });

  // Afficher loading si vue asynchrone
  const overlay = document.getElementById('loading-overlay');

  content.innerHTML = '';
  content.className = 'content';

  try {
    if (view.module?.render) {
      overlay?.classList.remove('hidden');
      await view.module.render(content, params);
      overlay?.classList.add('hidden');
    } else if (view.render) {
      view.render(content, params);
    }
  } catch (e) {
    overlay?.classList.add('hidden');
    content.innerHTML = renderError(e, viewId);
    console.error(`View error [${viewId}]:`, e);
  }
}

// ── Sidebar toggle ───────────────────────────────────────────
function setupSidebar() {
  const sidebar = document.getElementById('sidebar');
  const toggleBtn = document.getElementById('sidebar-toggle');
  const mobileBtn = document.getElementById('mobile-menu-btn');

  toggleBtn?.addEventListener('click', () => {
    sidebar?.classList.toggle('collapsed');
  });

  mobileBtn?.addEventListener('click', () => {
    sidebar?.classList.toggle('mobile-open');
  });

  // Fermer sidebar mobile en cliquant en dehors
  document.addEventListener('click', e => {
    if (sidebar?.classList.contains('mobile-open') &&
        !sidebar.contains(e.target) &&
        !mobileBtn?.contains(e.target)) {
      sidebar.classList.remove('mobile-open');
    }
  });
}

// ── Navigation links ─────────────────────────────────────────
function setupNavigation() {
  document.querySelectorAll('.nav-item[data-view]').forEach(link => {
    link.addEventListener('click', e => {
      e.preventDefault();
      const viewId = link.dataset.view;
      if (viewId) navigate(viewId);
      // Fermer sidebar mobile
      document.getElementById('sidebar')?.classList.remove('mobile-open');
    });
  });

  // Hash change
  window.addEventListener('hashchange', () => {
    const hash = location.hash.replace('#','');
    if (hash && hash in VIEWS && hash !== _currentView) navigate(hash);
  });
}

// ── Topbar setup ─────────────────────────────────────────────
function setupTopbar() {
  // API status check
  checkAPIStatus();
  setInterval(checkAPIStatus, 30_000);
}

async function checkAPIStatus() {
  const dot = document.querySelector('.api-dot');
  const badge = document.getElementById('api-status');
  try {
    const ctrl = new AbortController();
    setTimeout(() => ctrl.abort(), 5000);
    await fetch('https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1', { signal: ctrl.signal });
    if (dot) { dot.style.background = 'var(--green)'; dot.style.boxShadow = '0 0 6px var(--green)'; }
    if (badge) badge.title = 'NVD API: En ligne';
  } catch {
    if (dot) { dot.style.background = 'var(--red)'; dot.style.boxShadow = '0 0 6px var(--red)'; }
    if (badge) badge.title = 'NVD API: Hors ligne';
  }
}

// ── Refresh button ───────────────────────────────────────────
function setupRefreshBtn() {
  document.getElementById('refresh-btn')?.addEventListener('click', () => {
    const btn = document.getElementById('refresh-btn');
    btn?.classList.add('spinning');
    navigate(_currentView).finally(() => btn?.classList.remove('spinning'));
  });
}

// ── Clock ─────────────────────────────────────────────────────
function setupClock() {
  const clockEl = document.getElementById('clock');
  if (!clockEl) return;

  function tick() {
    const now = new Date();
    clockEl.textContent = now.toLocaleTimeString('fr-FR', { hour:'2-digit', minute:'2-digit', second:'2-digit' });
  }
  tick();
  setInterval(tick, 1000);
}

// ── Session timer + event counter + session ID ────────────────
(function setupSessionHUD() {
  // Session ID aléatoire
  const sid = Array.from({length:6}, () => Math.floor(Math.random()*16).toString(16).toUpperCase()).join('');
  const sidEl = document.getElementById('session-id');
  if (sidEl) sidEl.textContent = `SID:${sid}`;

  // Timer de session
  const t0 = Date.now();
  const timerEl = document.getElementById('session-time');
  function tickTimer() {
    if (!timerEl) return;
    const s = Math.floor((Date.now() - t0) / 1000);
    const h = String(Math.floor(s / 3600)).padStart(2, '0');
    const m = String(Math.floor((s % 3600) / 60)).padStart(2, '0');
    const sc = String(s % 60).padStart(2, '0');
    timerEl.textContent = `${h}:${m}:${sc}`;
  }
  tickTimer();
  setInterval(tickTimer, 1000);

  // Compteur d'événements (incrémentation pseudo-aléatoire)
  const counterEl = document.getElementById('event-counter');
  let evCount = Math.floor(Math.random() * 200) + 80;
  if (counterEl) counterEl.textContent = evCount.toLocaleString('fr');
  setInterval(() => {
    if (!counterEl) return;
    evCount += Math.floor(Math.random() * 4) + 1;
    counterEl.textContent = evCount.toLocaleString('fr');
  }, 3200);
})();

// ── Ticker ────────────────────────────────────────────────────
function startTicker() {
  const alerts = [
    '[CRITICAL] CVE-2024-3400 · Palo Alto PAN-OS · RCE CVSS 10.0 · Patch NOW',
    '[HIGH]     CVE-2024-21762 · Fortinet FortiOS · Auth Bypass · KEV listed',
    '[CRITICAL] CVE-2024-27198 · JetBrains TeamCity · Pre-Auth RCE · CVSS 9.8',
    '[HIGH]     CVE-2023-23397 · Microsoft Outlook · NTLM Theft · APT28 active',
    '[CRITICAL] CVE-2021-44228 · Log4Shell · Still exploited by 42% threat actors',
    '[IOC]      185.220.101.x/24 · Tor exit nodes · Brute-force campaign detected',
    '[TTP]      T1566.001 Spearphishing · LockBit 3.0 · DACH region targeting',
    '[FEED]     CISA KEV +7 entries today · Immediate patch guidance issued',
    '[APT]      APT29 · Midnight Blizzard · OAuth token theft · M365 tenants',
    '[VULN]     NVD backlog cleared · 2 341 CVEs published last 7 days',
  ];

  const track = document.getElementById('ticker-track');
  if (!track) return;

  const inner = document.createElement('div');
  inner.className = 'ticker-inner';
  inner.innerHTML = alerts.map(a => `<span class="ticker-item">${a}</span>`).join('');
  track.appendChild(inner);
}

// ── Toast notifications ───────────────────────────────────────
function showToast(msg, type = 'info', duration = 4000) {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const icons = { success: '✅', error: '❌', warning: '⚠️', info: 'ℹ️' };
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `<span class="toast-icon">${icons[type] || 'ℹ️'}</span><span class="toast-msg">${msg}</span>`;

  container.appendChild(toast);
  setTimeout(() => { toast.style.opacity = '0'; toast.style.transform = 'translateX(20px)'; setTimeout(() => toast.remove(), 300); }, duration);
}

// ── Threat Map ───────────────────────────────────────────────
function renderThreatMap(container) {
  container.innerHTML = `
    <div class="page-header">
      <div>
        <div class="page-title">🗺️ Threat Map</div>
        <div class="page-subtitle">Visualisation des attaques globales en temps réel</div>
      </div>
    </div>
    <div class="card" style="padding:20px;text-align:center">
      <p style="color:var(--text-2);margin-bottom:14px">
        La carte des menaces en temps réel nécessite une connexion à des sources de données spécialisées.
      </p>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px;margin:20px 0;text-align:left">
        ${[
          { name:'Kaspersky Cyber Map', url:'https://cybermap.kaspersky.com/', icon:'🔴' },
          { name:'Fortinet Threat Map', url:'https://threatmap.fortiguard.com/', icon:'🟠' },
          { name:'CheckPoint Live Map', url:'https://threatmap.checkpoint.com/', icon:'🟡' },
          { name:'Radware Live Map', url:'https://livethreatmap.radware.com/', icon:'🟢' },
        ].map(m => `
          <a href="${m.url}" target="_blank" class="card" style="display:flex;gap:10px;align-items:center;text-decoration:none;padding:14px">
            <span style="font-size:20px">${m.icon}</span>
            <span style="font-size:13px;color:var(--text-1)">${m.name}</span>
          </a>
        `).join('')}
      </div>
      <p style="font-size:11px;color:var(--text-3)">Ces services tiers offrent des visualisations de menaces mondiales.</p>
    </div>

    <!-- Simulated attack stats -->
    <div class="stats-grid" style="margin-top:14px">
      ${[
        { label:'Attaques/sec (mondial)', value:'1,847', color:'var(--red)' },
        { label:'Pays sources actifs', value:'142', color:'var(--orange)' },
        { label:'Campagnes APT actives', value:'38', color:'var(--purple)' },
        { label:'Malwares uniques (24h)', value:'94K', color:'var(--yellow)' },
      ].map(s => `
        <div class="stat-card" style="--accent:${s.color}">
          <div class="stat-label">${s.label}</div>
          <div class="stat-value" style="color:${s.color}">${s.value}</div>
          <div class="stat-meta">Estimation temps réel</div>
        </div>
      `).join('')}
    </div>
  `;
}

// ── Settings ─────────────────────────────────────────────────
function renderSettings(container) {
  const prefs = loadPrefs();

  container.innerHTML = `
    <div class="page-header">
      <div>
        <div class="page-title">⚙️ Paramètres</div>
        <div class="page-subtitle">Configuration de Cyberlens</div>
      </div>
    </div>

    <div class="grid-2">
      <!-- API Settings -->
      <div class="card">
        <div class="card-header"><div class="card-title">🔑 Configuration API</div></div>
        <div style="display:flex;flex-direction:column;gap:12px">
          <div>
            <label style="font-size:12px;color:var(--text-2);display:block;margin-bottom:6px">Clé API NVD (optionnel — lève les limites)</label>
            <div style="display:flex;gap:8px">
              <input type="password" id="nvd-api-key" class="search-input" style="flex:1"
                placeholder="NVD API Key (pour augmenter le rate limit)"
                value="${prefs.nvdApiKey || ''}">
              <button class="btn btn-primary" id="save-api-key">Sauvegarder</button>
            </div>
            <p style="font-size:10px;color:var(--text-3);margin-top:4px">
              Obtenir une clé gratuite: <a href="https://nvd.nist.gov/developers/request-an-api-key" target="_blank" class="external">nvd.nist.gov</a>
            </p>
          </div>
        </div>
      </div>

      <!-- Display Settings -->
      <div class="card">
        <div class="card-header"><div class="card-title">🎨 Affichage</div></div>
        <div style="display:flex;flex-direction:column;gap:10px">
          ${[
            { id:'auto-refresh', label:'Actualisation automatique', desc:'Rafraîchir les données toutes les 5 minutes', val: prefs.autoRefresh },
            { id:'notifications', label:'Notifications toast', desc:'Afficher les notifications dans l\'application', val: prefs.notifications },
            { id:'compact-mode', label:'Mode compact', desc:'Réduire l\'espacement pour afficher plus de contenu', val: prefs.compact },
          ].map(s => `
            <div class="setting-row">
              <div class="setting-info">
                <div class="setting-label">${s.label}</div>
                <div class="setting-desc">${s.desc}</div>
              </div>
              <div class="toggle ${s.val ? 'on' : ''}" id="toggle-${s.id}" data-pref="${s.id}"></div>
            </div>
          `).join('')}
        </div>
      </div>

      <!-- About -->
      <div class="card">
        <div class="card-header"><div class="card-title">ℹ️ À propos</div></div>
        <div style="font-size:12px;color:var(--text-2);line-height:1.8">
          <div><b style="color:var(--cyan)">Cyberlens</b> v1.0.0</div>
          <div>Plateforme de veille et analyse de vulnérabilités</div>
          <hr style="border-color:var(--border);margin:10px 0">
          <div>Sources: NVD API v2 · CISA KEV · RSS Cybersec</div>
          <div>Données: <a href="https://nvd.nist.gov" target="_blank" class="external">NIST NVD</a> · <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" class="external">CISA KEV</a></div>
          <div style="margin-top:8px;padding:8px;background:var(--red-glow);border-radius:6px;color:var(--red);font-size:10px">
            ⚠️ Cette plateforme est destinée à un usage éducatif et de recherche uniquement.
          </div>
        </div>
      </div>

      <!-- Keyboard Shortcuts -->
      <div class="card">
        <div class="card-header"><div class="card-title">⌨️ Raccourcis clavier</div></div>
        <div style="display:flex;flex-direction:column;gap:6px">
          ${[
            ['Alt + D', 'Dashboard'],
            ['Alt + C', 'CVE Search'],
            ['Alt + E', 'Exploit Lab'],
            ['Alt + N', 'Threat News'],
            ['Alt + R', 'Red Team'],
            ['Alt + B', 'Blue Team'],
            ['F5', 'Rafraîchir la vue'],
          ].map(([key, action]) => `
            <div style="display:flex;align-items:center;justify-content:space-between;padding:5px 0;border-bottom:1px solid var(--border)">
              <span style="font-size:12px;color:var(--text-2)">${action}</span>
              <kbd style="font-family:var(--text-mono);font-size:11px;background:var(--bg-2);border:1px solid var(--border);padding:2px 8px;border-radius:4px;color:var(--cyan)">${key}</kbd>
            </div>
          `).join('')}
        </div>
      </div>
    </div>
  `;

  // Toggles
  container.querySelectorAll('.toggle').forEach(toggle => {
    toggle.addEventListener('click', () => {
      toggle.classList.toggle('on');
      const pref = toggle.dataset.pref;
      const prefs = loadPrefs();
      prefs[pref] = toggle.classList.contains('on');
      savePrefs(prefs);
      showToast(`${pref}: ${prefs[pref] ? 'activé' : 'désactivé'}`, 'success');
    });
  });

  // Sauvegarder clé API
  document.getElementById('save-api-key')?.addEventListener('click', () => {
    const key = document.getElementById('nvd-api-key')?.value.trim();
    const prefs = loadPrefs();
    prefs.nvdApiKey = key;
    savePrefs(prefs);
    showToast('Clé API sauvegardée', 'success');
  });
}

// ── Error page ───────────────────────────────────────────────
function renderError(e, viewId) {
  return `
    <div class="empty-state" style="padding:80px 20px">
      <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="var(--red)" stroke-width="1">
        <circle cx="12" cy="12" r="10"/>
        <line x1="12" y1="8" x2="12" y2="12"/>
        <line x1="12" y1="16" x2="12.01" y2="16"/>
      </svg>
      <div style="font-size:16px;font-weight:600;color:var(--red)">Erreur lors du chargement</div>
      <p style="max-width:400px">${e?.message || 'Une erreur inattendue s\'est produite.'}</p>
      <button class="btn btn-ghost" onclick="window.__app?.navigate('${viewId}')">
        ↺ Réessayer
      </button>
    </div>
  `;
}

// ── Preferences ──────────────────────────────────────────────
function loadPrefs() {
  try { return JSON.parse(localStorage.getItem('cyberintel_prefs') || '{}'); }
  catch { return {}; }
}

function savePrefs(prefs) {
  try { localStorage.setItem('cyberintel_prefs', JSON.stringify(prefs)); }
  catch {}
}

// ── Keyboard shortcuts ────────────────────────────────────────
document.addEventListener('keydown', e => {
  if (e.altKey) {
    const map = { d:'dashboard', c:'cve', e:'exploit', n:'news', r:'redteam', b:'blueteam' };
    const view = map[e.key.toLowerCase()];
    if (view) { e.preventDefault(); navigate(view); }
  }
  if (e.key === 'F5') {
    e.preventDefault();
    navigate(_currentView);
  }
});

// ── Auto-refresh ──────────────────────────────────────────────
setInterval(() => {
  const prefs = loadPrefs();
  if (prefs.autoRefresh && _currentView === 'dashboard') navigate('dashboard');
}, 5 * 60_000);

// ── Start ─────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', init);
