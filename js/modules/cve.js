// ============================================================
//  cve.js — Recherche CVE temps réel (NVD API v2)
// ============================================================
import { searchCVEs, getKEVData, formatDate, formatDateTime, cvssColor, severityColor, isKEV } from '../api.js?v=10';

let _currentCVE = null;
let _searchTimeout = null;
let _currentPage = 0;
const PAGE_SIZE = 20;

export async function render(container, params = {}) {
  container.innerHTML = '';
  container.className = 'content fade-in';

  await getKEVData(); // pré-charger KEV

  container.innerHTML = `
    <div class="page-header">
      <div>
        <div class="page-title">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
            <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
          </svg>
          CVE Search
        </div>
        <div class="page-subtitle">Recherche en temps réel sur la base NVD — 200 000+ vulnérabilités</div>
      </div>
    </div>

    <!-- Search bar -->
    <div class="search-wrapper">
      <svg class="search-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
      </svg>
      <input type="text" class="search-input" id="cve-search-input"
        placeholder="Rechercher: CVE-ID, produit, vendor (ex: apache, log4j, CVE-2021-44228)..."
        autocomplete="off" spellcheck="false">
    </div>

    <!-- Filters -->
    <div class="search-controls">
      <select class="filter-select" id="filter-severity">
        <option value="">Toutes sévérités</option>
        <option value="CRITICAL">🔴 Critique (9.0–10.0)</option>
        <option value="HIGH">🟠 Haute (7.0–8.9)</option>
        <option value="MEDIUM">🟡 Moyenne (4.0–6.9)</option>
        <option value="LOW">🟢 Basse (0.1–3.9)</option>
      </select>
      <select class="filter-select" id="filter-sort">
        <option value="new">Plus récentes</option>
        <option value="score">Score CVSS ↓</option>
      </select>
      <button class="btn btn-primary btn-sm" id="btn-search">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
          <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
        </svg>
        Rechercher
      </button>
      <button class="btn btn-ghost btn-sm" id="btn-clear">Effacer</button>
      <span class="mono text-muted" style="font-size:11px;margin-left:auto;align-self:center" id="search-count"></span>
    </div>

    <!-- Split layout: list + detail -->
    <div class="split-layout">
      <!-- Results list -->
      <div class="results-panel">
        <div class="results-header">
          <span class="card-title">Résultats</span>
          <span class="results-count" id="results-count">—</span>
        </div>
        <div class="results-list" id="results-list">
          <div class="empty-state">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1">
              <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
            </svg>
            <p>Entrez un terme de recherche ou sélectionnez une sévérité pour commencer</p>
          </div>
        </div>
        <div style="border-top:1px solid var(--border);padding:8px 12px;display:flex;gap:8px" id="pagination"></div>
      </div>

      <!-- Detail panel -->
      <div class="detail-panel" id="detail-panel">
        <div class="detail-empty">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
            <polyline points="14 2 14 8 20 8"/>
          </svg>
          <span>Sélectionnez une CVE pour voir les détails</span>
        </div>
      </div>
    </div>
  `;

  // Event listeners
  const input    = document.getElementById('cve-search-input');
  const btnSearch = document.getElementById('btn-search');
  const btnClear  = document.getElementById('btn-clear');
  const sevFilter = document.getElementById('filter-severity');

  const doSearch = () => { _currentPage = 0; performSearch(); };

  input?.addEventListener('keydown', e => {
    if (e.key === 'Enter') doSearch();
    else {
      clearTimeout(_searchTimeout);
      _searchTimeout = setTimeout(() => doSearch(), 600);
    }
  });

  btnSearch?.addEventListener('click', doSearch);
  btnClear?.addEventListener('click', () => {
    input.value = '';
    sevFilter.value = '';
    document.getElementById('results-list').innerHTML = `<div class="empty-state"><svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg><p>Entrez un terme de recherche</p></div>`;
    document.getElementById('results-count').textContent = '—';
  });

  sevFilter?.addEventListener('change', doSearch);

  // Auto-search si params
  if (params.search) {
    input.value = params.search;
    doSearch();
  } else {
    // Charger les CVEs critiques par défaut
    sevFilter.value = 'CRITICAL';
    doSearch();
  }
}

// ── Recherche ────────────────────────────────────────────────
async function performSearch() {
  const input    = document.getElementById('cve-search-input');
  const severity = document.getElementById('filter-severity')?.value;
  const sortBy   = document.getElementById('filter-sort')?.value;
  const list     = document.getElementById('results-list');
  const countEl  = document.getElementById('results-count');
  if (!list || !input) return;

  const keyword = input.value.trim();
  const isCveId = /^CVE-\d{4}-\d+$/i.test(keyword);

  // Afficher le loading
  list.innerHTML = skeletonList(8);
  if (countEl) countEl.textContent = '...';

  try {
    const params = {
      limit     : PAGE_SIZE,
      startIndex: _currentPage * PAGE_SIZE,
    };
    if (isCveId) params.cveId = keyword.toUpperCase();
    else if (keyword) params.keyword = keyword;
    if (severity) params.severity = severity;

    const { cves, total } = await searchCVEs(params);

    // Tri côté client si demandé
    let sorted = [...cves];
    if (sortBy === 'score') sorted.sort((a, b) => (b.cvss ?? 0) - (a.cvss ?? 0));

    if (countEl) countEl.textContent = `${total.toLocaleString('fr')} résultats`;
    renderResultsList(sorted, list);
    renderPagination(total, _currentPage);
  } catch (e) {
    list.innerHTML = `
      <div class="empty-state">
        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1">
          <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
        </svg>
        <p>Erreur lors de la recherche.<br><small style="font-size:10px">${e.message}</small></p>
      </div>`;
    if (countEl) countEl.textContent = '—';
  }
}

// ── Liste des résultats ──────────────────────────────────────
function renderResultsList(cves, container) {
  if (!cves.length) {
    container.innerHTML = `<div class="empty-state"><p>Aucune CVE trouvée pour ces critères.</p></div>`;
    return;
  }

  container.innerHTML = cves.map(cve => {
    const kev = isKEV(cve.id);
    const desc = cve.description.slice(0, 120) + (cve.description.length > 120 ? '...' : '');
    return `
      <div class="result-item" data-cve-id="${cve.id}">
        <div class="result-item-header">
          <span class="cve-id">${cve.id}</span>
          <div style="display:flex;gap:6px;align-items:center">
            ${kev ? '<span class="badge badge-kev">KEV</span>' : ''}
            <span class="badge badge-${(cve.severity||'none').toLowerCase()}">${cve.severity || 'N/A'}</span>
            <span class="cvss-score" style="color:${cvssColor(cve.cvss)};font-size:13px;font-weight:700">${cve.cvss ?? '—'}</span>
          </div>
        </div>
        <div class="result-item-desc">${escHtml(desc)}</div>
        <div style="margin-top:5px;font-size:10px;color:var(--text-3);font-family:var(--text-mono)">
          Pub: ${formatDate(cve.published)}
        </div>
      </div>
    `;
  }).join('');

  // Clic sur un item → afficher le détail
  container.querySelectorAll('.result-item').forEach(item => {
    item.addEventListener('click', () => {
      container.querySelectorAll('.result-item').forEach(i => i.classList.remove('active'));
      item.classList.add('active');
      const cve = cves.find(c => c.id === item.dataset.cveId);
      if (cve) renderDetail(cve);
    });
  });

  // Sélectionner automatiquement le premier
  const first = container.querySelector('.result-item');
  if (first) first.click();
}

// ── Pagination ───────────────────────────────────────────────
function renderPagination(total, currentPage) {
  const pag = document.getElementById('pagination');
  if (!pag) return;
  const totalPages = Math.ceil(total / PAGE_SIZE);
  if (totalPages <= 1) { pag.innerHTML = ''; return; }

  pag.innerHTML = `
    <button class="btn btn-ghost btn-sm" id="pag-prev" ${currentPage === 0 ? 'disabled' : ''}>← Préc</button>
    <span class="mono text-muted" style="font-size:11px;flex:1;text-align:center">
      Page ${currentPage + 1} / ${Math.min(totalPages, 50)}
    </span>
    <button class="btn btn-ghost btn-sm" id="pag-next" ${currentPage >= totalPages - 1 ? 'disabled' : ''}>Suiv →</button>
  `;

  document.getElementById('pag-prev')?.addEventListener('click', () => { _currentPage--; performSearch(); });
  document.getElementById('pag-next')?.addEventListener('click', () => { _currentPage++; performSearch(); });
}

// ── Panneau de détail ────────────────────────────────────────
function renderDetail(cve) {
  _currentCVE = cve;
  const panel = document.getElementById('detail-panel');
  if (!panel) return;

  const kev     = isKEV(cve.id);
  const cvssC   = cvssColor(cve.cvss);
  const sevClass = 'badge-' + (cve.severity || 'none').toLowerCase();

  // Analyser le vecteur CVSS
  const vectorParts = parseVector(cve.vector);

  panel.innerHTML = `
    <!-- CVE Header -->
    <div class="cve-detail-header">
      <div class="cve-detail-id">${cve.id}</div>
      <div class="cve-detail-title">${escHtml(cve.description.slice(0, 200))}${cve.description.length > 200 ? '...' : ''}</div>
      <div class="cve-meta-row">
        <div class="cvss-display">
          <div>
            <div class="cvss-label">CVSS v3</div>
            <div class="cvss-number" style="color:${cvssC}">${cve.cvss ?? 'N/A'}</div>
          </div>
          <span class="badge ${sevClass}">${cve.severity || 'NONE'}</span>
        </div>
        ${kev ? '<span class="badge badge-kev">🚨 CISA KEV</span>' : ''}
        <div style="margin-left:auto">
          <a class="btn btn-ghost btn-sm" href="https://nvd.nist.gov/vuln/detail/${cve.id}" target="_blank">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="12" height="12">
              <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>
              <polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>
            </svg>
            NVD
          </a>
        </div>
      </div>
    </div>

    <!-- Tabs -->
    <div class="tab-nav">
      <button class="tab-btn active" data-tab="overview">Vue d'ensemble</button>
      <button class="tab-btn" data-tab="redteam">Red Team</button>
      <button class="tab-btn" data-tab="blueteam">Blue Team</button>
      <button class="tab-btn" data-tab="refs">Références</button>
    </div>

    <!-- Tab Content -->
    <div class="scroll-section">
      <!-- Overview Tab -->
      <div class="tab-pane active" id="tab-overview">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px">
          <div class="card" style="padding:12px">
            <div class="card-title" style="margin-bottom:8px">📅 Dates</div>
            <div style="font-size:12px;color:var(--text-2)">
              <div style="margin-bottom:4px"><b style="color:var(--text-3)">Publiée:</b> ${formatDate(cve.published)}</div>
              <div><b style="color:var(--text-3)">Modifiée:</b> ${formatDate(cve.modified)}</div>
            </div>
          </div>
          <div class="card" style="padding:12px">
            <div class="card-title" style="margin-bottom:8px">🔖 Faiblesses (CWE)</div>
            <div>
              ${cve.weaknesses.length ? cve.weaknesses.map(w => `<span class="badge badge-info" style="margin:2px">${w}</span>`).join('') : '<span class="text-muted" style="font-size:11px">Non spécifié</span>'}
            </div>
          </div>
        </div>

        <!-- Description complète -->
        <div class="card" style="padding:14px;margin-bottom:12px">
          <div class="card-title" style="margin-bottom:8px">📄 Description</div>
          <p style="font-size:12px;color:var(--text-2);line-height:1.7">${escHtml(cve.description)}</p>
        </div>

        <!-- Vecteur CVSS -->
        ${cve.vector ? `
        <div class="card" style="padding:14px;margin-bottom:12px">
          <div class="card-title" style="margin-bottom:10px">📊 Vecteur CVSS</div>
          <div style="font-family:var(--text-mono);font-size:11px;color:var(--cyan);word-break:break-all;margin-bottom:10px">
            ${cve.vector}
          </div>
          <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:6px">
            ${vectorParts.map(p => `
              <div style="background:var(--bg-2);border:1px solid var(--border);border-radius:6px;padding:6px 10px">
                <div style="font-size:9px;color:var(--text-3);text-transform:uppercase;letter-spacing:0.5px">${p.label}</div>
                <div style="font-size:12px;font-weight:600;color:${p.color}">${p.value}</div>
              </div>
            `).join('')}
          </div>
        </div>` : ''}

        <!-- Produits affectés -->
        ${cve.cpes.length ? `
        <div class="card" style="padding:14px">
          <div class="card-title" style="margin-bottom:8px">💻 Produits affectés</div>
          <div style="max-height:120px;overflow-y:auto">
            ${cve.cpes.slice(0,12).map(cpe => `
              <div style="font-family:var(--text-mono);font-size:10px;color:var(--text-2);padding:3px 0;border-bottom:1px solid var(--border)">${cpe}</div>
            `).join('')}
            ${cve.cpes.length > 12 ? `<div style="font-size:11px;color:var(--text-3);padding-top:4px">... et ${cve.cpes.length - 12} autres</div>` : ''}
          </div>
        </div>` : ''}
      </div>

      <!-- Red Team Tab -->
      <div class="tab-pane" id="tab-redteam">
        <div class="card" style="padding:14px;margin-bottom:12px;border-color:var(--red-dim)">
          <div class="card-title" style="margin-bottom:8px;color:var(--red)">
            ⚔️ Perspective Attaquant
          </div>
          <div style="font-size:12px;color:var(--text-2);line-height:1.7">
            ${getRedTeamContent(cve)}
          </div>
        </div>
        <div class="card" style="padding:14px;margin-bottom:12px">
          <div class="card-title" style="margin-bottom:8px">🎯 Surface d'attaque</div>
          ${getAttackSurface(cve)}
        </div>
        <div class="card" style="padding:14px">
          <div class="card-title" style="margin-bottom:8px">🔧 Ressources exploitation</div>
          ${getExploitResources(cve)}
        </div>
      </div>

      <!-- Blue Team Tab -->
      <div class="tab-pane" id="tab-blueteam">
        <div class="card" style="padding:14px;margin-bottom:12px;border-color:var(--cyan-dim)">
          <div class="card-title" style="margin-bottom:8px;color:var(--cyan)">
            🛡️ Perspective Défenseur
          </div>
          ${getBlueTeamContent(cve)}
        </div>
        <div class="card" style="padding:14px;margin-bottom:12px">
          <div class="card-title" style="margin-bottom:8px">🔍 Indicateurs de détection</div>
          ${getDetectionContent(cve)}
        </div>
        <div class="card" style="padding:14px">
          <div class="card-title" style="margin-bottom:8px">✅ Remédiation</div>
          ${getRemediationContent(cve)}
        </div>
      </div>

      <!-- Références Tab -->
      <div class="tab-pane" id="tab-refs">
        <div style="display:flex;flex-direction:column;gap:8px">
          ${cve.refs.length ? cve.refs.map(ref => `
            <div class="card" style="padding:10px 14px">
              <div style="display:flex;align-items:center;justify-content:space-between;gap:10px">
                <div>
                  <div style="font-size:11px;color:var(--text-2);word-break:break-all">${escHtml(ref.url)}</div>
                  ${ref.tags.length ? `<div style="margin-top:4px">${ref.tags.map(t => `<span class="badge badge-info" style="margin:1px;font-size:9px">${t}</span>`).join('')}</div>` : ''}
                </div>
                <a href="${ref.url}" target="_blank" rel="noopener" class="btn btn-ghost btn-sm" style="flex-shrink:0">↗</a>
              </div>
            </div>
          `).join('') : '<div class="empty-state"><p>Aucune référence disponible</p></div>'}
        </div>
      </div>
    </div>
  `;

  // Tab switching
  panel.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      panel.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      panel.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      const pane = document.getElementById('tab-' + btn.dataset.tab);
      if (pane) pane.classList.add('active');
    });
  });
}

// ── Analyse vecteur CVSS ─────────────────────────────────────
function parseVector(vector) {
  if (!vector) return [];
  const parts = [];
  const map = {
    'AV': { label: 'Attack Vector',    N:'Network', A:'Adjacent', L:'Local', P:'Physical' },
    'AC': { label: 'Attack Complexity', L:'Low', H:'High' },
    'PR': { label: 'Privil. Required', N:'None', L:'Low', H:'High' },
    'UI': { label: 'User Interaction',  N:'None', R:'Required' },
    'S' : { label: 'Scope',            U:'Unchanged', C:'Changed' },
    'C' : { label: 'Confidentiality',  N:'None', L:'Low', H:'High' },
    'I' : { label: 'Integrity',        N:'None', L:'Low', H:'High' },
    'A' : { label: 'Availability',     N:'None', L:'Low', H:'High' },
  };
  const colorMap = { N:'var(--green)', L:'var(--yellow)', H:'var(--red)', Network:'var(--red)', Local:'var(--yellow)', Physical:'var(--green)', Adjacent:'var(--orange)', Changed:'var(--orange)', Unchanged:'var(--text-2)', Required:'var(--yellow)', None:'var(--green)' };
  vector.replace('CVSS:3.1/','').replace('CVSS:3.0/','').split('/').forEach(seg => {
    const [k, v] = seg.split(':');
    if (map[k]) {
      const val = map[k][v] || v;
      parts.push({ label: map[k].label, value: val, color: colorMap[val] || 'var(--text-2)' });
    }
  });
  return parts;
}

// ── Contenu Red Team ─────────────────────────────────────────
function getRedTeamContent(cve) {
  const sev = (cve.severity || '').toUpperCase();
  const vec = cve.vector || '';
  const isNetwork = vec.includes('AV:N');
  const noAuth    = vec.includes('PR:N');
  const noUI      = vec.includes('UI:N');

  return `
    <div style="display:grid;gap:6px">
      <div style="display:flex;gap:8px;align-items:center">
        <span style="font-size:16px">${isNetwork ? '🌐' : '💻'}</span>
        <span><b>Vecteur:</b> ${isNetwork ? 'Réseau (exploitable à distance)' : 'Local (accès physique/SSH requis)'}</span>
      </div>
      <div style="display:flex;gap:8px;align-items:center">
        <span style="font-size:16px">${noAuth ? '🔓' : '🔐'}</span>
        <span><b>Authentification:</b> ${noAuth ? 'Non requise — exploitation sans compte' : 'Compte requis pour exploiter'}</span>
      </div>
      <div style="display:flex;gap:8px;align-items:center">
        <span style="font-size:16px">${noUI ? '⚡' : '👆'}</span>
        <span><b>Interaction utilisateur:</b> ${noUI ? 'Aucune — exploitation automatique possible' : 'Interaction victime requise (phishing, etc.)'}</span>
      </div>
      ${sev === 'CRITICAL' ? '<div style="margin-top:8px;padding:8px;background:var(--red-glow);border:1px solid var(--red-dim);border-radius:6px;color:var(--red);font-size:11px">⚠️ Score CRITIQUE — Wormable possible, prioriser la remédiation immédiate</div>' : ''}
    </div>
  `;
}

function getAttackSurface(cve) {
  const types = [];
  const desc = cve.description.toLowerCase();
  if (desc.includes('sql')) types.push({ icon: '💉', name: 'SQL Injection', risk: 'HIGH' });
  if (desc.includes('buffer') || desc.includes('overflow')) types.push({ icon: '💥', name: 'Buffer Overflow', risk: 'CRITICAL' });
  if (desc.includes('xss') || desc.includes('cross-site')) types.push({ icon: '🕸️', name: 'Cross-Site Scripting', risk: 'MEDIUM' });
  if (desc.includes('rce') || desc.includes('remote code')) types.push({ icon: '🚀', name: 'Remote Code Execution', risk: 'CRITICAL' });
  if (desc.includes('path traversal') || desc.includes('directory')) types.push({ icon: '📁', name: 'Path Traversal', risk: 'HIGH' });
  if (desc.includes('authentication') || desc.includes('bypass')) types.push({ icon: '🔓', name: 'Auth Bypass', risk: 'HIGH' });
  if (desc.includes('privilege') || desc.includes('escalat')) types.push({ icon: '⬆️', name: 'Privilege Escalation', risk: 'HIGH' });
  if (desc.includes('ssrf')) types.push({ icon: '🔄', name: 'SSRF', risk: 'HIGH' });

  if (!types.length) types.push({ icon: '⚠️', name: 'Voir description NVD', risk: 'UNKNOWN' });

  return `<div style="display:flex;flex-direction:column;gap:6px">
    ${types.map(t => `
      <div style="display:flex;align-items:center;gap:10px;padding:7px 10px;background:var(--bg-2);border-radius:6px;border:1px solid var(--border)">
        <span style="font-size:16px">${t.icon}</span>
        <span style="font-size:12px;color:var(--text-1)">${t.name}</span>
        <span class="badge badge-${t.risk.toLowerCase()}" style="margin-left:auto">${t.risk}</span>
      </div>
    `).join('')}
  </div>`;
}

function getExploitResources(cve) {
  return `
    <div style="display:flex;flex-direction:column;gap:6px">
      <a href="https://www.exploit-db.com/search?cve=${cve.id}" target="_blank" class="btn btn-ghost btn-sm" style="justify-content:flex-start">
        🗃️ Exploit-DB — Rechercher des PoC
      </a>
      <a href="https://github.com/search?q=${cve.id}&type=repositories" target="_blank" class="btn btn-ghost btn-sm" style="justify-content:flex-start">
        🐙 GitHub — Dépôts liés à ${cve.id}
      </a>
      <a href="https://www.shodan.io/search?query=${encodeURIComponent(cve.id)}" target="_blank" class="btn btn-ghost btn-sm" style="justify-content:flex-start">
        🔭 Shodan — Systèmes exposés
      </a>
      <a href="https://vulners.com/search?query=${cve.id}" target="_blank" class="btn btn-ghost btn-sm" style="justify-content:flex-start">
        🔍 Vulners — Intelligence étendue
      </a>
    </div>
  `;
}

// ── Contenu Blue Team ────────────────────────────────────────
function getBlueTeamContent(cve) {
  const vec = cve.vector || '';
  const isNetwork = vec.includes('AV:N');
  const kev = isKEV(cve.id);

  return `
    <div style="display:grid;gap:8px;font-size:12px;color:var(--text-2)">
      <div style="display:flex;gap:8px;align-items:center">
        ${kev
          ? '<span style="color:var(--red);font-size:16px">🚨</span><span><b style="color:var(--red)">CISA KEV:</b> Exploitation active confirmée — patch OBLIGATOIRE</span>'
          : '<span style="color:var(--green);font-size:16px">✅</span><span>Non dans la liste KEV CISA (exploitation active non confirmée)</span>'}
      </div>
      ${isNetwork ? '<div style="display:flex;gap:8px"><span>🔥</span><span>Exposition réseau: Envisager le blocage firewall en attente de patch</span></div>' : ''}
      <div style="display:flex;gap:8px"><span>📋</span><span>Priorité de patch: ${cvssToAgePriority(cve.cvss)}</span></div>
    </div>
  `;
}

function cvssToAgePriority(score) {
  if (!score) return 'À évaluer';
  if (score >= 9.0) return '<b style="color:var(--red)">IMMÉDIAT (24-48h)</b>';
  if (score >= 7.0) return '<b style="color:var(--orange)">Urgent (7 jours)</b>';
  if (score >= 4.0) return '<b style="color:var(--yellow)">Normal (30 jours)</b>';
  return '<b style="color:var(--green)">Planifié (90 jours)</b>';
}

function getDetectionContent(cve) {
  return `
    <div style="display:flex;flex-direction:column;gap:6px;font-size:12px;color:var(--text-2)">
      <div style="padding:8px;background:var(--bg-2);border-radius:6px;border-left:3px solid var(--cyan)">
        <b style="color:var(--text-1)">Recherche dans SIEM:</b><br>
        <code style="font-family:var(--text-mono);font-size:10px;color:var(--cyan)">${cve.id}</code>
      </div>
      <div style="padding:8px;background:var(--bg-2);border-radius:6px;border-left:3px solid var(--green)">
        <b style="color:var(--text-1)">Règles de détection:</b><br>
        Vérifier <a href="https://github.com/SigmaHQ/sigma/search?q=${cve.id}" target="_blank" class="external">Sigma Rules</a>
        et <a href="https://github.com/Neo23x0/signature-base/search?q=${cve.id}" target="_blank" class="external">YARA (signature-base)</a>
      </div>
      <div style="padding:8px;background:var(--bg-2);border-radius:6px;border-left:3px solid var(--purple)">
        <b style="color:var(--text-1)">Threat Intelligence:</b><br>
        <a href="https://otx.alienvault.com/indicator/cve/${cve.id}" target="_blank" class="external">OTX AlienVault</a> ·
        <a href="https://ti.defender.microsoft.com/" target="_blank" class="external">Microsoft Defender TI</a>
      </div>
    </div>
  `;
}

function getRemediationContent(cve) {
  return `
    <div style="font-size:12px;color:var(--text-2);line-height:1.8">
      <div style="display:flex;flex-direction:column;gap:6px">
        <div>1. <b style="color:var(--text-1)">Identifier</b> les systèmes affectés via l'inventaire et les CPEs listés</div>
        <div>2. <b style="color:var(--text-1)">Consulter</b> les bulletins de sécurité officiels du vendor</div>
        <div>3. <b style="color:var(--text-1)">Appliquer</b> le patch dans les délais selon la sévérité CVSS</div>
        <div>4. <b style="color:var(--text-1)">Vérifier</b> l'absence de compromission (IoCs, logs)</div>
        <div>5. <b style="color:var(--text-1)">Documenter</b> dans le registre de risques</div>
      </div>
      <div style="margin-top:10px">
        <a href="https://nvd.nist.gov/vuln/detail/${cve.id}" target="_blank" class="btn btn-ghost btn-sm">📋 Voir sur NVD</a>
      </div>
    </div>
  `;
}

// ── Helpers ──────────────────────────────────────────────────
function skeletonList(n) {
  return Array(n).fill(0).map(() => `
    <div class="result-item">
      <div class="result-item-header">
        <div class="skeleton skeleton-line" style="width:140px;height:14px"></div>
        <div class="skeleton skeleton-line" style="width:60px;height:14px"></div>
      </div>
      <div class="skeleton skeleton-line medium" style="margin-top:6px"></div>
    </div>
  `).join('');
}

function escHtml(str) {
  return (str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
