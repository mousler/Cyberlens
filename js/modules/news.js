// ============================================================
//  news.js — Threat News Feed (RSS via CORS proxy)
// ============================================================
import { fetchNewsAll, NEWS_SOURCES, timeAgo } from '../api.js?v=10';

let _allArticles = [];
let _filter = 'all';

export async function render(container) {
  container.innerHTML = '';
  container.className = 'content fade-in';

  container.innerHTML = `
    <div class="page-header">
      <div>
        <div class="page-title">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
            <path d="M4 22h16a2 2 0 0 0 2-2V4a2 2 0 0 0-2-2H8a2 2 0 0 0-2 2v16a2 2 0 0 1-2 2Zm0 0a2 2 0 0 1-2-2v-9c0-1.1.9-2 2-2h2"/>
            <path d="M18 14h-8"/><path d="M15 18h-5"/><path d="M10 6h8v4h-8V6Z"/>
          </svg>
          Threat News
        </div>
        <div class="page-subtitle">Actualité cybersécurité en temps réel — agrégation multi-sources</div>
      </div>
      <button class="btn btn-ghost btn-sm" id="news-refresh">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
          <path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/>
        </svg>
        Actualiser
      </button>
    </div>

    <!-- Source filters -->
    <div class="filter-bar" id="source-filter">
      <div class="filter-chip active" data-filter="all">🌐 Toutes les sources</div>
      ${NEWS_SOURCES.map(s => `
        <div class="filter-chip" data-filter="${s.id}" style="--chip-color:${s.color}">
          <span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${s.color};margin-right:4px"></span>
          ${s.name}
        </div>
      `).join('')}
    </div>

    <!-- Tag filters -->
    <div class="filter-bar" id="tag-filter" style="margin-bottom:20px">
      <span style="font-size:11px;color:var(--text-3);align-self:center;margin-right:4px">Tags:</span>
      ${['Ransomware','Phishing','Zero-Day','Patch','Critical','APT','Data Breach','Malware','Vulnerability','DDoS','Supply Chain'].map(t => `
        <div class="filter-chip" data-tag="${t}" style="font-size:10px;padding:3px 10px">${t}</div>
      `).join('')}
    </div>

    <!-- News grid -->
    <div id="news-container">
      <div class="news-grid" id="news-grid">
        ${Array(12).fill(0).map(() => skeletonCard()).join('')}
      </div>
    </div>
  `;

  // Source filter
  document.getElementById('source-filter')?.addEventListener('click', e => {
    const chip = e.target.closest('[data-filter]');
    if (!chip) return;
    document.querySelectorAll('#source-filter .filter-chip').forEach(c => c.classList.remove('active'));
    chip.classList.add('active');
    _filter = chip.dataset.filter;
    applyFilter();
  });

  // Tag filter (toggle)
  const activeTags = new Set();
  document.getElementById('tag-filter')?.addEventListener('click', e => {
    const chip = e.target.closest('[data-tag]');
    if (!chip) return;
    const tag = chip.dataset.tag;
    if (activeTags.has(tag)) { activeTags.delete(tag); chip.classList.remove('active'); }
    else { activeTags.add(tag); chip.classList.add('active'); }
    applyFilter(activeTags);
  });

  document.getElementById('news-refresh')?.addEventListener('click', () => loadNews(true));

  await loadNews();
}

async function loadNews(force = false) {
  const btn = document.getElementById('news-refresh');
  if (btn) btn.classList.add('spinning');

  try {
    _allArticles = await fetchNewsAll();
    if (!_allArticles.length) {
      // Données de démonstration si les flux échouent
      _allArticles = getDemoArticles();
    }
    applyFilter();
    if (btn) { btn.classList.remove('spinning'); btn.textContent = '✓ Mis à jour'; setTimeout(() => { btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/></svg> Actualiser'; }, 2000); }
    updateTicker(_allArticles);
  } catch (e) {
    _allArticles = getDemoArticles();
    applyFilter();
    if (btn) btn.classList.remove('spinning');
  }
}

function applyFilter(activeTags = new Set()) {
  let filtered = _allArticles;

  // Filtre par source
  if (_filter !== 'all') {
    filtered = filtered.filter(a => a.sourceId === _filter);
  }

  // Filtre par tags
  if (activeTags.size > 0) {
    filtered = filtered.filter(a => a.tags?.some(t => activeTags.has(t)));
  }

  renderArticles(filtered);
}

function renderArticles(articles) {
  const grid = document.getElementById('news-grid');
  if (!grid) return;

  if (!articles.length) {
    grid.innerHTML = `
      <div style="grid-column:1/-1" class="empty-state">
        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1"><path d="M4 22h16a2 2 0 0 0 2-2V4a2 2 0 0 0-2-2H8a2 2 0 0 0-2 2v16a2 2 0 0 1-2 2Zm0 0a2 2 0 0 1-2-2v-9c0-1.1.9-2 2-2h2"/></svg>
        <p>Aucun article pour ces filtres</p>
      </div>`;
    return;
  }

  grid.innerHTML = articles.map(a => `
    <div class="news-card" style="--source-color:${a.color}" data-link="${escHtml(a.link)}">
      <div style="display:flex;align-items:center;justify-content:space-between">
        <span class="news-source">${escHtml(a.source)}</span>
        <span class="news-date">${timeAgo(a.date)}</span>
      </div>
      <div class="news-title">${escHtml(a.title)}</div>
      ${a.excerpt ? `<div class="news-excerpt">${escHtml(a.excerpt)}</div>` : ''}
      <div class="news-footer">
        <div class="news-tags">
          ${(a.tags || []).map(t => `<span class="news-tag">${t}</span>`).join('')}
        </div>
        <span style="font-size:11px;color:var(--text-3)">↗ Lire</span>
      </div>
    </div>
  `).join('');

  // Click → ouvrir l'article
  grid.querySelectorAll('.news-card').forEach(card => {
    card.addEventListener('click', () => {
      const url = card.dataset.link;
      if (url && url !== '#') window.open(url, '_blank', 'noopener');
    });
  });
}

// ── Ticker ───────────────────────────────────────────────────
function updateTicker(articles) {
  const track = document.getElementById('ticker-track');
  if (!track || !articles.length) return;

  const inner = document.createElement('div');
  inner.className = 'ticker-inner';
  inner.innerHTML = articles.slice(0, 20).map(a =>
    `<span class="ticker-item">
      <b style="color:${a.color}">[${a.source}]</b> ${escHtml(a.title)}
    </span>`
  ).join('');
  track.innerHTML = '';
  track.appendChild(inner);
}

// ── Demo articles (fallback si RSS indisponible) ─────────────
function getDemoArticles() {
  const now = new Date();
  return [
    { id:'d1', source:'The Hacker News', sourceId:'hn', color:'#ff3366', title:'Critical Zero-Day in Ivanti VPN Exploited by Chinese APT Groups', excerpt:'Security researchers have identified active exploitation of a critical zero-day vulnerability in Ivanti Connect Secure VPN appliances by multiple Chinese state-sponsored threat actors.', date: new Date(now - 3600000).toISOString(), tags:['Zero-Day','APT','VPN'], link:'https://thehackernews.com' },
    { id:'d2', source:'CISA Alerts', sourceId:'cisa', color:'#a855f7', title:'CISA Adds 3 Known Exploited Vulnerabilities to Catalog', excerpt:'CISA has added three new vulnerabilities to its Known Exploited Vulnerabilities Catalog, based on evidence of active exploitation in the wild.', date: new Date(now - 7200000).toISOString(), tags:['Vulnerability','Critical'], link:'https://www.cisa.gov/news-events/alerts' },
    { id:'d3', source:'BleepingComputer', sourceId:'bc', color:'#00d4ff', title:'LockBit Ransomware Gang Claims Attack on Major Hospital Chain', excerpt:'The LockBit ransomware group has claimed responsibility for a cyberattack on a major hospital chain, threatening to publish 200GB of stolen patient data.', date: new Date(now - 10800000).toISOString(), tags:['Ransomware','Data Breach'], link:'https://www.bleepingcomputer.com' },
    { id:'d4', source:'Krebs Security', sourceId:'krebs', color:'#ff6b1a', title:'Massive Phishing Campaign Targets Microsoft 365 Users Across Fortune 500', excerpt:'A sophisticated phishing-as-a-service platform called "DarkAngels" is being used to harvest Microsoft 365 credentials at unprecedented scale.', date: new Date(now - 14400000).toISOString(), tags:['Phishing','Microsoft'], link:'https://krebsonsecurity.com' },
    { id:'d5', source:'SecurityWeek', sourceId:'sw', color:'#00e676', title:'CISA Emergency Directive: Patch Palo Alto Networks Firewalls Immediately', excerpt:'CISA has issued an emergency directive ordering federal agencies to patch critical vulnerabilities in Palo Alto Networks PAN-OS within 48 hours.', date: new Date(now - 18000000).toISOString(), tags:['Critical','Patch','Firewall'], link:'https://www.securityweek.com' },
    { id:'d6', source:'Naked Security', sourceId:'naked', color:'#ffc107', title:'North Korean Hackers Targeting Crypto Exchanges via Supply Chain Attack', excerpt:'The Lazarus Group, linked to North Korea, has been observed conducting sophisticated supply chain attacks against cryptocurrency exchanges worldwide.', date: new Date(now - 21600000).toISOString(), tags:['APT','Supply Chain'], link:'https://nakedsecurity.sophos.com' },
    { id:'d7', source:'The Hacker News', sourceId:'hn', color:'#ff3366', title:'New AI-Powered Malware Can Evade All Major Antivirus Solutions', excerpt:'Security researchers have documented a new strain of malware that uses generative AI to polymorphically rewrite its code, successfully evading detection by 23 tested AV products.', date: new Date(now - 25200000).toISOString(), tags:['Malware','AI'], link:'https://thehackernews.com' },
    { id:'d8', source:'BleepingComputer', sourceId:'bc', color:'#00d4ff', title:'Critical SQL Injection in Popular CMS Plugin Affects 500,000 Sites', excerpt:'A critical SQL injection vulnerability has been discovered in a popular WordPress plugin with over 500,000 active installations, allowing unauthenticated attackers to read sensitive database content.', date: new Date(now - 28800000).toISOString(), tags:['Vulnerability','Zero-Day'], link:'https://www.bleepingcomputer.com' },
    { id:'d9', source:'CISA Alerts', sourceId:'cisa', color:'#a855f7', title:'Alert AA24-131A: Black Basta Ransomware Targeting Critical Infrastructure', excerpt:'CISA, FBI, and HHS have released a joint advisory warning of ongoing Black Basta ransomware attacks targeting healthcare and critical infrastructure organizations.', date: new Date(now - 32400000).toISOString(), tags:['Ransomware','Critical'], link:'https://www.cisa.gov/news-events/alerts' },
    { id:'d10', source:'SecurityWeek', sourceId:'sw', color:'#00e676', title:'Microsoft Patch Tuesday: 147 Vulnerabilities Fixed, 3 Actively Exploited', excerpt:'Microsoft\'s latest Patch Tuesday update addresses 147 security vulnerabilities across its product lineup, including three zero-days currently being exploited in the wild.', date: new Date(now - 36000000).toISOString(), tags:['Patch','Zero-Day','Microsoft'], link:'https://www.securityweek.com' },
    { id:'d11', source:'Krebs Security', sourceId:'krebs', color:'#ff6b1a', title:'$45 Million Stolen in Crypto Heist via Smart Contract Vulnerability', excerpt:'Hackers exploited a reentrancy vulnerability in a DeFi protocol\'s smart contract, draining $45 million in various cryptocurrencies before the attack was detected.', date: new Date(now - 39600000).toISOString(), tags:['Vulnerability','Data Breach'], link:'https://krebsonsecurity.com' },
    { id:'d12', source:'Naked Security', sourceId:'naked', color:'#ffc107', title:'Google Patches Two Chrome Zero-Days Exploited in Targeted Attacks', excerpt:'Google has released an emergency update for Chrome fixing two zero-day vulnerabilities that were being exploited in targeted attacks against journalists and human rights activists.', date: new Date(now - 43200000).toISOString(), tags:['Zero-Day','Patch'], link:'https://nakedsecurity.sophos.com' },
  ];
}

// ── Helpers ──────────────────────────────────────────────────
function skeletonCard() {
  return `
    <div class="news-card" style="cursor:default">
      <div class="skeleton skeleton-line short" style="height:10px;margin-bottom:10px"></div>
      <div class="skeleton skeleton-line full" style="height:14px;margin-bottom:6px"></div>
      <div class="skeleton skeleton-line medium" style="height:14px;margin-bottom:12px"></div>
      <div class="skeleton skeleton-line full" style="height:11px;margin-bottom:4px"></div>
      <div class="skeleton skeleton-line medium" style="height:11px;margin-bottom:4px"></div>
      <div class="skeleton skeleton-line short" style="height:11px"></div>
    </div>
  `;
}

function escHtml(str) {
  return (str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
