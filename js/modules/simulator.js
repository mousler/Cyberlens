// ============================================================
//  simulator.js — CVE Simulator interactif
//  Terminal typewriter · SOC/SIEM en temps réel · Détection
// ============================================================
import { SIMULATIONS } from '../data/simulations.js?v=15';
import { searchCVEs }   from '../api.js?v=15';
import { autoGenSimulation } from './cve-auto.js?v=15';

// ── État ─────────────────────────────────────────────────────
let _sim        = null;
let _step       = -1;
let _playing    = false;
let _speed      = 1;
let _evCount    = 0;
let _detection  = 0;
let _autoTimer  = null;
let _typing     = false;
let _simLibrary = [];   // Simulations auto-générées persistantes

const sleep = ms => new Promise(r => setTimeout(r, ms));

// ── Point d'entrée ───────────────────────────────────────────
export function render(container) {
  container.innerHTML = buildShell();
  attachListeners();

  // Restaurer la dernière simulation active si elle existe
  if (_sim) {
    refreshSimLibraryUI();
    document.getElementById('sim-main').style.display = '';
    populateInfoBar(_sim);
    resetSim();
  }
}

// ── Squelette HTML ───────────────────────────────────────────
function buildShell() {
  const cards = SIMULATIONS.map(s => `
    <div class="simcard" data-id="${s.id}">
      <div class="simcard-top">
        <span class="sev-badge sev-${s.severity.toLowerCase()}">${s.severity}</span>
        <span class="simcard-cvss">CVSS ${s.cvss}</span>
        <span class="simcard-year">${s.year}</span>
      </div>
      <div class="simcard-cve">${s.cve}</div>
      <div class="simcard-name">${s.name}</div>
      <div class="simcard-sub">${s.subtitle}</div>
      <div class="simcard-target">🎯 ${s.target}</div>
      <div class="simcard-tags">
        ${s.tags.map(t => `<span class="simcard-tag">${t}</span>`).join('')}
      </div>
    </div>
  `).join('');

  return `
  <div class="sim-wrap">

    <!-- En-tête ──────────────────────────────── -->
    <div class="sim-topbar">
      <div>
        <h1 class="sim-title">💻 CVE Simulator</h1>
        <p class="sim-subtitle">Simulation interactive — comprenez comment les CVEs sont exploitées étape par étape</p>
      </div>
      <span class="usage-only-badge">⚠️ USAGE ÉDUCATIF UNIQUEMENT</span>
    </div>

    <!-- Recherche CVE NVD ───────────────────── -->
    <div class="sim-search-section">
      <div class="sim-search-title">🔍 Rechercher un CVE à simuler (NVD)</div>
      <div class="sim-search-row">
        <input class="sim-search-input" id="sim-search-input"
               placeholder="CVE-2024-XXXXX ou mot-clé (ex: apache, log4j...)" />
        <button class="sim-search-btn" id="sim-search-btn">Simuler →</button>
      </div>
      <div class="sim-search-results" id="sim-search-results"></div>
    </div>

    <!-- Sélecteur CVE ────────────────────────── -->
    <div class="simcard-grid" id="simcard-grid">${cards}</div>

    <!-- Zone principale (cachée jusqu'à sélection) ── -->
    <div class="sim-main" id="sim-main" style="display:none">

      <!-- Bandeau info CVE -->
      <div class="sim-infobar" id="sim-infobar"></div>

      <!-- Phases + Détection -->
      <div class="sim-meta-row">
        <div class="sim-phases" id="sim-phases"></div>
        <div class="sim-det" id="sim-det">
          <span class="sim-det-dot"></span>
          <span class="sim-det-label">NON DÉTECTÉ</span>
          <span class="sim-det-sub">Aucune activité suspecte</span>
        </div>
      </div>

      <!-- Split : Terminal | SIEM ──────────────── -->
      <div class="sim-split">

        <!-- Terminal attaquant -->
        <div class="sim-panel sim-term-panel">
          <div class="sim-panel-hdr">
            <div class="sim-tl">
              <span class="tl-r"></span><span class="tl-y"></span><span class="tl-g"></span>
            </div>
            <span class="sim-panel-title">🔴 ATTAQUANT — Terminal</span>
            <span class="sim-env-badge" id="sim-env-atk"></span>
          </div>
          <div class="sim-terminal" id="sim-terminal">
            <div class="term-idle">
              <span class="term-prompt">attacker@kali:~$</span>
              <span class="term-cursor">█</span>
            </div>
          </div>
        </div>

        <!-- Panneau SOC/SIEM -->
        <div class="sim-panel sim-siem-panel">
          <div class="sim-panel-hdr">
            <span class="sim-panel-title">🔵 DÉFENSEUR — SOC / SIEM</span>
            <span class="sim-ev-count" id="sim-ev-count">0 alertes</span>
          </div>
          <div class="sim-siem" id="sim-siem">
            <div class="siem-idle">
              <div class="siem-idle-icon">🛡️</div>
              <div>En attente d'activité...</div>
              <div class="siem-idle-sub">Les alertes SOC apparaîtront ici</div>
            </div>
          </div>
        </div>

      </div><!-- /sim-split -->

      <!-- Explication étape ────────────────────── -->
      <div class="sim-explain" id="sim-explain">
        <span class="sim-explain-icon">📖</span>
        <div class="sim-explain-text" id="sim-explain-text">
          Cliquez sur <strong>▶ Lancer</strong> pour démarrer la simulation...
        </div>
      </div>

      <!-- Contrôles ────────────────────────────── -->
      <div class="sim-controls">
        <button class="sim-btn" id="sim-prev" disabled>◀ Précédent</button>
        <button class="sim-btn sim-btn-play" id="sim-play">▶ Lancer</button>
        <button class="sim-btn" id="sim-next">Suivant ▶</button>

        <div class="sim-speed-wrap">
          <label class="sim-speed-label">Vitesse</label>
          <select class="sim-speed-sel" id="sim-speed-sel">
            <option value="2.5">0.4x</option>
            <option value="1.5">0.7x</option>
            <option value="1" selected>1x</option>
            <option value="0.5">2x</option>
            <option value="0.15">5x</option>
          </select>
        </div>

        <div class="sim-step-ctr" id="sim-step-ctr">Étape 0 / 0</div>

        <button class="sim-btn sim-btn-reset" id="sim-reset">↺ Reset</button>
      </div>

    </div><!-- /sim-main -->
  </div><!-- /sim-wrap -->
  `;
}

// ── Listeners ────────────────────────────────────────────────
function attachListeners() {
  document.querySelectorAll('.simcard').forEach(card => {
    card.addEventListener('click', () => {
      document.querySelectorAll('.simcard').forEach(c => c.classList.remove('active'));
      card.classList.add('active');
      loadSim(card.dataset.id);
    });
  });

  document.getElementById('sim-play').addEventListener('click', togglePlay);
  document.getElementById('sim-next').addEventListener('click', () => { if (!_typing) nextStep(); });
  document.getElementById('sim-prev').addEventListener('click', () => { if (!_typing) prevStep(); });
  document.getElementById('sim-reset').addEventListener('click', resetSim);
  document.getElementById('sim-speed-sel').addEventListener('change', e => {
    _speed = parseFloat(e.target.value);
  });

  // CVE search
  const searchBtn = document.getElementById('sim-search-btn');
  const searchInp = document.getElementById('sim-search-input');
  searchBtn.addEventListener('click', runSimSearch);
  searchInp.addEventListener('keydown', e => { if (e.key === 'Enter') runSimSearch(); });
}

// ── Fetch NVD (autonome, indépendant de api.js) ───────────────
async function nvdFetch(q) {
  const NVD = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

  // Clé API NVD depuis les paramètres
  let apiKey = '';
  try {
    apiKey = JSON.parse(localStorage.getItem('cyberintel_prefs') || '{}').nvdApiKey || '';
  } catch {}

  // Validation de la requête
  const q2 = q.trim();
  if (q2.length < 2) throw new Error('Recherche trop courte (minimum 2 caractères)');

  const isCveId = /^CVE-\d{4}-\d+$/i.test(q2);
  const qs = new URLSearchParams({ resultsPerPage: '8', startIndex: '0' });
  if (isCveId) qs.set('cveId', q2.toUpperCase());
  else         qs.set('keywordSearch', q2);

  const nvdUrl = `${NVD}?${qs}`;
  console.log(`[SimSearch] Query: "${q2}" | URL: ${nvdUrl}`);
  console.log(`[SimSearch] Clé API: ${apiKey ? '✓ configurée' : '✗ absente'}`);

  // ── Helper: valider la réponse NVD ──
  function isValidNvd(data) {
    return data && typeof data === 'object' && 'vulnerabilities' in data;
  }

  // ── Tentative 1: appel direct avec clé API ──────────────────
  try {
    const headers = apiKey ? { 'apiKey': apiKey } : {};
    const ctrl    = new AbortController();
    const timer   = setTimeout(() => ctrl.abort(), 12000);
    const r = await fetch(nvdUrl, { headers, signal: ctrl.signal });
    clearTimeout(timer);
    console.log(`[SimSearch] Direct → HTTP ${r.status}`);
    if (r.ok) {
      const data = await r.json();
      if (isValidNvd(data)) {
        console.log(`[SimSearch] ✓ Direct OK — ${data.totalResults} résultats`);
        return data;
      }
    }
    if (r.status === 429) console.warn('[SimSearch] Rate limit 429 → proxy');
    else if (!r.ok)       console.warn(`[SimSearch] HTTP ${r.status} → proxy`);
  } catch (e) {
    console.warn(`[SimSearch] Direct échoué (${e.message}) → proxy`);
  }

  // ── Tentative 2: proxy allorigins.win ───────────────────────
  try {
    const proxyUrl = `https://api.allorigins.win/get?url=${encodeURIComponent(nvdUrl)}`;
    const ctrl     = new AbortController();
    const timer    = setTimeout(() => ctrl.abort(), 15000);
    const r = await fetch(proxyUrl, { signal: ctrl.signal });
    clearTimeout(timer);
    const wrapper = await r.json();
    const data    = JSON.parse(wrapper.contents);
    if (isValidNvd(data)) {
      console.log(`[SimSearch] ✓ Proxy 1 OK — ${data.totalResults} résultats`);
      return data;
    }
  } catch (e) {
    console.warn(`[SimSearch] Proxy 1 échoué: ${e.message}`);
  }

  // ── Tentative 3: corsproxy.io ────────────────────────────────
  try {
    const proxyUrl = `https://corsproxy.io/?${encodeURIComponent(nvdUrl)}`;
    const ctrl     = new AbortController();
    const timer    = setTimeout(() => ctrl.abort(), 15000);
    const r = await fetch(proxyUrl, { signal: ctrl.signal });
    clearTimeout(timer);
    const data = await r.json();
    if (isValidNvd(data)) {
      console.log(`[SimSearch] ✓ Proxy 2 OK — ${data.totalResults} résultats`);
      return data;
    }
  } catch (e) {
    console.warn(`[SimSearch] Proxy 2 échoué: ${e.message}`);
  }

  // ── Aucune tentative n'a fonctionné ─────────────────────────
  console.error('[SimSearch] ✗ Toutes les tentatives ont échoué');
  throw new Error('Impossible de joindre NVD (direct + 2 proxies). Vérifiez votre connexion.');
}

// ── Conversion parsed CVE → format NVD brut pour autoGen ─────
function toRawNvd(p) {
  const vec = p.vector || '';
  return {
    id: p.id,
    descriptions: [{ lang: 'en', value: p.description || '' }],
    metrics: {
      cvssMetricV31: p.cvss ? [{
        cvssData: {
          baseScore:          p.cvss,
          baseSeverity:       p.severity || 'HIGH',
          attackVector:       vec.includes('AV:N') ? 'NETWORK' : 'LOCAL',
          attackComplexity:   vec.includes('AC:L') ? 'LOW'  : 'HIGH',
          privilegesRequired: vec.includes('PR:N') ? 'NONE' : 'LOW',
          userInteraction:    vec.includes('UI:N') ? 'NONE' : 'REQUIRED',
          scope:              vec.includes('S:C')  ? 'CHANGED' : 'UNCHANGED',
          confidentialityImpact: vec.includes('C:H') ? 'HIGH' : 'NONE',
          integrityImpact:       vec.includes('I:H') ? 'HIGH' : 'NONE',
          availabilityImpact:    vec.includes('A:H') ? 'HIGH' : 'NONE',
        }
      }] : [],
    },
    weaknesses:    (p.weaknesses || []).map(w => ({ description: [{ value: w }] })),
    configurations: [],
    published:     p.published || '',
  };
}

// ── Recherche CVE pour simulation ────────────────────────────
async function runSimSearch() {
  const inp   = document.getElementById('sim-search-input');
  const resEl = document.getElementById('sim-search-results');
  const btn   = document.getElementById('sim-search-btn');
  const q     = inp?.value.trim();
  if (!q) return;

  btn.disabled = true;
  btn.textContent = '…';
  resEl.innerHTML = `
    <div class="sim-search-loading">
      <span class="sim-search-spinner"></span>
      Connexion à NVD…
    </div>`;

  try {
    // nvdFetch est autonome — ne dépend pas du cache de api.js
    const json  = await nvdFetch(q);
    const items = (json.vulnerabilities || []).slice(0, 8);

    if (!items.length) {
      resEl.innerHTML = `
        <div class="sim-search-empty">
          Aucun CVE trouvé pour <b>"${escSim(q)}"</b><br>
          <span style="font-size:10px;opacity:.6">Essayez: apache, log4j, CVE-2021-44228…</span>
        </div>`;
      btn.disabled = false;
      btn.textContent = 'Simuler →';
      return;
    }

    resEl.innerHTML = '';
    items.forEach(vuln => {
      // NVD retourne { vulnerabilities: [{ cve: {...} }] }
      const cve  = vuln.cve || vuln;
      const id   = cve.id || '—';
      const desc = ((cve.descriptions || []).find(d => d.lang === 'en')?.value || '').slice(0, 70) + '…';
      const m    = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0] || cve.metrics?.cvssMetricV2?.[0];
      const cvss = m?.cvssData?.baseScore ?? '—';
      const sev  = (m?.cvssData?.baseSeverity || '').toUpperCase();
      const sevCls = { CRITICAL:'sev-critical', HIGH:'sev-high', MEDIUM:'sev-medium', LOW:'sev-low' }[sev] || '';

      const item = document.createElement('div');
      item.className = 'sim-search-item';
      item.innerHTML = `
        <div class="sim-search-item-id">
          ${escSim(id)}
          <span class="sim-auto-badge">AUTO</span>
          ${sev ? `<span class="sev-badge ${sevCls}" style="font-size:9px;padding:1px 5px">${sev}</span>` : ''}
        </div>
        <div class="sim-search-item-desc">${escSim(desc)}</div>
        <div class="sim-search-item-cvss">CVSS ${cvss}</div>
      `;
      item.addEventListener('click', () => {
        resEl.innerHTML = `<div class="sim-search-loading"><span class="sim-search-spinner"></span>Génération de la simulation…</div>`;
        btn.disabled = true;
        setTimeout(() => {
          try {
            addSimToLibrary(cve);
            resEl.innerHTML = '';
            if (inp) inp.value = '';
          } catch (e) {
            console.error('[SimSearch] Génération échouée:', e);
            resEl.innerHTML = `<div class="sim-search-empty">❌ Génération impossible: ${escSim(e.message)}<br><span style="font-size:10px;opacity:.6">F12 → Console pour le détail.</span></div>`;
          } finally {
            btn.disabled = false;
            btn.textContent = 'Simuler →';
          }
        }, 80);
      });
      resEl.appendChild(item);
    });

  } catch (err) {
    console.error('[SimSearch] Erreur finale:', err);
    resEl.innerHTML = `
      <div class="sim-search-empty">
        ❌ ${escSim(err.message)}<br>
        <span style="font-size:10px;opacity:.6">Ouvrez F12 → Console pour voir le détail de l'erreur.</span>
      </div>`;
  }

  btn.disabled = false;
  btn.textContent = 'Simuler →';
}

function escSim(s) {
  return (s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// ── Bibliothèque de simulations auto ─────────────────────────
// rawCve : objet NVD brut tel que retourné par nvdFetch (cve.*)
// autoGenSimulation attend ce format directement

function addSimToLibrary(rawCve) {
  const id = rawCve.id;
  const existing = _simLibrary.find(s => s.id === id);
  if (existing) {
    _sim = existing.sim;
    activateSimCard(id);
    resetSim();
    document.getElementById('sim-main').style.display = '';
    populateInfoBar(_sim);
    return;
  }

  console.log('[SimSearch] Génération simulation pour', id);
  const sim = autoGenSimulation(rawCve);
  console.log('[SimSearch] Simulation générée:', sim?.name, '— étapes:', sim?.steps?.length);

  _simLibrary.push({ id, rawCve, sim });
  refreshSimLibraryUI();

  _sim = sim;
  activateSimCard(id);
  resetSim();
  document.getElementById('sim-main').style.display = '';
  populateInfoBar(sim);
}

function refreshSimLibraryUI() {
  const grid = document.getElementById('simcard-grid');
  if (!grid) return;
  // Supprimer anciens auto-cards
  grid.querySelectorAll('.simcard-auto').forEach(c => c.remove());
  // Ajouter les nouveaux
  _simLibrary.forEach(({ id, rawCve, sim }) => {
    const card = document.createElement('div');
    card.className = 'simcard simcard-auto';
    card.dataset.autoId = id;
    const m    = rawCve.metrics?.cvssMetricV31?.[0] || rawCve.metrics?.cvssMetricV30?.[0];
    const cvss = m?.cvssData?.baseScore ?? sim.cvss ?? '?';
    const sev  = (sim.severity || 'HIGH').toUpperCase();
    card.innerHTML = `
      <div class="simcard-top">
        <span class="sev-badge sev-${sev.toLowerCase()}">${sev}</span>
        <span class="simcard-cvss">CVSS ${cvss}</span>
        <span class="simcard-year">${sim.year || ''}</span>
        <button class="sim-card-remove" title="Retirer">×</button>
      </div>
      <div class="simcard-cve">${sim.cve}</div>
      <div class="simcard-name">${sim.name}</div>
      <div class="simcard-sub">${sim.subtitle || ''}</div>
      <div class="simcard-target">🎯 ${sim.target}</div>
      <div class="simcard-tags">
        ${(sim.tags || []).map(t => `<span class="simcard-tag">${t}</span>`).join('')}
        <span class="simcard-tag simcard-tag-auto">AUTO</span>
      </div>`;
    card.addEventListener('click', e => {
      if (e.target.classList.contains('sim-card-remove')) {
        _simLibrary = _simLibrary.filter(s => s.id !== id);
        refreshSimLibraryUI();
        return;
      }
      activateSimCard(id);
      _sim = sim;
      resetSim();
      document.getElementById('sim-main').style.display = '';
      populateInfoBar(sim);
    });
    grid.appendChild(card);
  });
}

function activateSimCard(id) {
  document.querySelectorAll('.simcard').forEach(c => c.classList.remove('active'));
  const card = document.querySelector(`[data-auto-id="${id}"]`)
            || document.querySelector(`[data-id="${id}"]`);
  card?.classList.add('active');
}

function populateInfoBar(sim) {
  document.getElementById('sim-infobar').innerHTML = `
    <div class="infobar-left">
      <span class="sev-badge sev-${sim.severity.toLowerCase()}">${sim.severity}</span>
      <strong class="infobar-cve">${sim.cve}</strong>
      <span class="infobar-name">${sim.name}</span>
      <span class="infobar-sep">—</span>
      <span class="infobar-target">${sim.target}</span>
      ${sim._autoGen ? '<span class="sim-auto-badge" style="margin-left:8px">AUTO-GÉNÉRÉ</span>' : ''}
    </div>
    <div class="infobar-env">
      <span class="env-atk">🔴 ${sim.env.attacker.ip} <em>${sim.env.attacker.label}</em></span>
      <span class="env-arrow">⟶</span>
      <span class="env-vic">🟦 ${sim.env.victim.ip} <em>${sim.env.victim.label}</em></span>
    </div>
    <div class="infobar-desc">${sim.description}</div>
  `;
  document.getElementById('sim-env-atk').textContent = sim.env.attacker.ip;
  renderPhases();
  updateCounter();
}


// ── Chargement d'une simulation ───────────────────────────────
function loadSim(id) {
  _sim = SIMULATIONS.find(s => s.id === id);
  if (!_sim) return;
  resetSim();
  document.getElementById('sim-main').style.display = '';
  populateInfoBar(_sim);
}

// ── Phases ───────────────────────────────────────────────────
function renderPhases() {
  if (!_sim) return;
  const currentPhase = _step >= 0 ? (_sim.steps[_step]?.phase ?? -1) : -1;
  document.getElementById('sim-phases').innerHTML = _sim.phases.map((p, i) => `
    <div class="sim-phase ${i <= currentPhase ? 'sim-phase-done' : ''} ${i === currentPhase ? 'sim-phase-active' : ''}"
         style="--ph-col:${p.color}">
      <span class="sim-phase-icon">${p.icon}</span>
      <span class="sim-phase-name">${p.name}</span>
    </div>
  `).join('<div class="sim-phase-arrow">›</div>');
}

// ── Détection ────────────────────────────────────────────────
function setDetection(level) {
  if (level <= _detection) return;
  _detection = level;
  const configs = [
    { cls: '',            dot: '#00e676', label: 'NON DÉTECTÉ',  sub: 'Aucune activité suspecte' },
    { cls: 'det-suspect', dot: '#ffc107', label: 'SUSPECT',      sub: 'Activité anormale détectée — surveillance renforcée' },
    { cls: 'det-compromis',dot:'#ff3366', label: '🚨 COMPROMIS', sub: 'Incident confirmé — réponse immédiate requise' },
  ];
  const cfg = configs[level];
  const el = document.getElementById('sim-det');
  el.className = `sim-det ${cfg.cls}`;
  el.innerHTML = `
    <span class="sim-det-dot" style="background:${cfg.dot};box-shadow:0 0 8px ${cfg.dot}"></span>
    <span class="sim-det-label">${cfg.label}</span>
    <span class="sim-det-sub">${cfg.sub}</span>
  `;
}

// ── Compteur étapes ──────────────────────────────────────────
function updateCounter() {
  const el = document.getElementById('sim-step-ctr');
  if (!_sim) { el.textContent = 'Étape 0 / 0'; return; }
  el.textContent = `Étape ${Math.max(0, _step + 1)} / ${_sim.steps.length}`;
}

// ── Navigation ───────────────────────────────────────────────
async function nextStep(fromAuto = false) {
  if (!_sim || _typing) return;
  if (_step >= _sim.steps.length - 1) { stopPlay(); return; }

  _step++;
  await runStep(_step);
  renderPhases();
  updateCounter();
  document.getElementById('sim-prev').disabled = _step <= 0;
  document.getElementById('sim-next').disabled = _step >= _sim.steps.length - 1;
}

async function prevStep() {
  if (!_sim || _step <= 0) return;
  _step--;

  // Replay instantané jusqu'à l'étape précédente
  clearTerminal();
  clearSiem();
  _detection = -1;
  _evCount   = 0;
  document.getElementById('sim-ev-count').textContent = '0 alertes';
  document.getElementById('sim-ev-count').classList.remove('has-events');
  document.getElementById('sim-explain-text').innerHTML = '...';

  for (let i = 0; i <= _step; i++) await instantStep(i);

  renderPhases();
  updateCounter();
  document.getElementById('sim-prev').disabled = _step <= 0;
  document.getElementById('sim-next').disabled = _step >= _sim.steps.length - 1;
}

// ── Exécution d'une étape (animée) ───────────────────────────
async function runStep(idx) {
  const step = _sim.steps[idx];
  if (!step) return;
  _typing = true;

  // Ligne séparateur de titre
  addTermLine(`── ${step.title} ──`, 'term-sep', false);

  // Commande ou label serveur
  if (step.cmd) {
    await typeCmd(step.prompt, step.cmd);
  } else if (step.prompt) {
    addTermLine(step.prompt, 'term-server-hdr', false);
  }

  // Output ligne par ligne
  for (const out of step.output) {
    await sleep(35 * _speed);
    addTermLine(out.t, `term-out ${out.c}`, true);
    scrollTerm();
  }

  addTermLine('', 'term-spacer', false);

  // Alertes SIEM
  for (const ev of step.siem) {
    await sleep(180 * _speed);
    addSiemEvent(ev);
  }

  // Niveau de détection
  setDetection(step.detection);

  // Explication
  document.getElementById('sim-explain-text').innerHTML =
    `<span class="sim-step-title">${step.title}</span> — ${step.explain}`;

  _typing = false;

  // Auto-play
  if (_playing) {
    const pause = step.cmd ? 1400 : 900;
    _autoTimer = setTimeout(() => nextStep(true), pause * _speed);
  }
}

// ── Étape instantanée (pour replay "Précédent") ──────────────
async function instantStep(idx) {
  const step = _sim.steps[idx];
  if (!step) return;

  addTermLine(`── ${step.title} ──`, 'term-sep', false);

  if (step.cmd) {
    addTermLine(`${step.prompt} ${step.cmd}`, 'term-cmd', false);
  } else if (step.prompt) {
    addTermLine(step.prompt, 'term-server-hdr', false);
  }

  for (const out of step.output) addTermLine(out.t, `term-out ${out.c}`, false);
  addTermLine('', 'term-spacer', false);

  for (const ev of step.siem) addSiemInstant(ev);

  if (step.detection > _detection) {
    _detection = -1;
    setDetection(step.detection);
  }

  if (idx === _step) {
    document.getElementById('sim-explain-text').innerHTML =
      `<span class="sim-step-title">${step.title}</span> — ${step.explain}`;
  }

  scrollTerm();
}

// ── Typewriter commande ──────────────────────────────────────
async function typeCmd(prompt, cmd) {
  const term = document.getElementById('sim-terminal');
  removeIdle();

  const line = document.createElement('div');
  line.className = 'term-line term-cmd';

  const pEl  = document.createElement('span');
  pEl.className = 'term-prompt';
  pEl.textContent = prompt + ' ';

  const cEl  = document.createElement('span');
  cEl.className = 'term-cmdtxt';

  const cur  = document.createElement('span');
  cur.className = 'term-cursor';
  cur.textContent = '█';

  line.append(pEl, cEl, cur);
  term.appendChild(line);
  scrollTerm();

  const delay = 32 * _speed;
  for (const ch of cmd) {
    cEl.textContent += ch;
    scrollTerm();
    await sleep(delay);
  }

  cur.remove();
  await sleep(160 * _speed);
}

// ── Helpers terminal ─────────────────────────────────────────
function addTermLine(text, cls = '', animate = false) {
  const term = document.getElementById('sim-terminal');
  removeIdle();
  const div = document.createElement('div');
  div.className = `term-line ${cls}`;
  if (animate) div.style.animation = 'fadeIn 0.15s ease';
  div.textContent = text;
  term.appendChild(div);
}

function scrollTerm() {
  const t = document.getElementById('sim-terminal');
  if (t) t.scrollTop = t.scrollHeight;
}

function removeIdle() {
  document.querySelector('.term-idle')?.remove();
}

function clearTerminal() {
  document.getElementById('sim-terminal').innerHTML = `
    <div class="term-idle">
      <span class="term-prompt">attacker@kali:~$</span>
      <span class="term-cursor">█</span>
    </div>
  `;
}

// ── SIEM events ──────────────────────────────────────────────
function addSiemEvent(ev, instant = false) {
  const siem = document.getElementById('sim-siem');
  siem.querySelector('.siem-idle')?.remove();

  _evCount++;
  const now  = new Date();
  const ts   = [now.getHours(), now.getMinutes(), now.getSeconds()]
    .map(n => String(n).padStart(2, '0')).join(':');

  const el   = document.createElement('div');
  el.className = `siem-ev siev-${ev.sev.toLowerCase()}`;
  if (!instant) el.style.animation = 'slideInRight 0.3s ease';

  el.innerHTML = `
    <div class="siev-hdr">
      <span class="siev-sev siev-${ev.sev.toLowerCase()}">${ev.sev}</span>
      <span class="siev-src">${ev.src}</span>
      <span class="siev-ts">${ts}</span>
    </div>
    <div class="siev-msg">${ev.msg}</div>
  `;

  siem.insertBefore(el, siem.firstChild);
  const cntEl = document.getElementById('sim-ev-count');
  cntEl.textContent = `${_evCount} alerte${_evCount > 1 ? 's' : ''}`;
  cntEl.classList.add('has-events');
}

function addSiemInstant(ev) { addSiemEvent(ev, true); }

function clearSiem() {
  document.getElementById('sim-siem').innerHTML = `
    <div class="siem-idle">
      <div class="siem-idle-icon">🛡️</div>
      <div>En attente d'activité...</div>
      <div class="siem-idle-sub">Les alertes SOC apparaîtront ici</div>
    </div>
  `;
}

// ── Lecture auto ─────────────────────────────────────────────
function togglePlay() {
  _playing ? stopPlay() : startPlay();
}

function startPlay() {
  _playing = true;
  const btn = document.getElementById('sim-play');
  btn.textContent = '⏸ Pause';
  btn.classList.add('playing');
  nextStep(true);
}

function stopPlay() {
  _playing = false;
  clearTimeout(_autoTimer);
  const btn = document.getElementById('sim-play');
  btn.textContent = '▶ Lancer';
  btn.classList.remove('playing');
}

// ── Reset ────────────────────────────────────────────────────
function resetSim() {
  stopPlay();
  _step      = -1;
  _detection = -1;
  _evCount   = 0;
  _typing    = false;

  clearTerminal();
  clearSiem();

  // Reset détection badge
  const det = document.getElementById('sim-det');
  if (det) {
    det.className = 'sim-det';
    det.innerHTML = `
      <span class="sim-det-dot" style="background:#00e676;box-shadow:0 0 8px #00e676"></span>
      <span class="sim-det-label">NON DÉTECTÉ</span>
      <span class="sim-det-sub">Aucune activité suspecte</span>
    `;
  }
  _detection = 0;

  const cntEl = document.getElementById('sim-ev-count');
  if (cntEl) { cntEl.textContent = '0 alertes'; cntEl.classList.remove('has-events'); }

  const expEl = document.getElementById('sim-explain-text');
  if (expEl) expEl.innerHTML = 'Cliquez sur <strong>▶ Lancer</strong> pour démarrer la simulation...';

  const prevBtn = document.getElementById('sim-prev');
  const nextBtn = document.getElementById('sim-next');
  if (prevBtn) prevBtn.disabled = true;
  if (nextBtn) nextBtn.disabled = false;

  updateCounter();
  if (_sim) renderPhases();
}
