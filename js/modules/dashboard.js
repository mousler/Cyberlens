// ============================================================
//  dashboard.js — Vue principale avec stats, charts, KEV table
// ============================================================
import { getRecentCVEs, getCVEStats, getKEVData, formatDate, timeAgo, severityColor, cvssColor } from '../api.js?v=10';

let _charts = {};

export async function render(container) {
  container.innerHTML = '';
  container.className = 'content fade-in';

  // Squelette immédiat
  container.innerHTML = `
    <div class="page-header">
      <div>
        <div class="page-title">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
            <rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/>
            <rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>
          </svg>
          Dashboard
        </div>
        <div class="page-subtitle">Vue d'ensemble de la menace en temps réel — données NVD &amp; CISA KEV</div>
      </div>
      <div class="flex gap-2">
        <button class="btn btn-ghost btn-sm" id="dash-refresh">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
            <path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/>
            <path d="M21 3v5h-5"/>
          </svg>
          Actualiser
        </button>
      </div>
    </div>

    <!-- Stats Cards -->
    <div class="stats-grid" id="stats-grid">
      ${[0,1,2,3,4].map(() => `
        <div class="stat-card">
          <div class="stat-label"><div class="skeleton skeleton-line short"></div></div>
          <div class="stat-value"><div class="skeleton skeleton-line" style="height:30px;width:70px"></div></div>
          <div class="stat-meta"><div class="skeleton skeleton-line short"></div></div>
        </div>
      `).join('')}
    </div>

    <!-- Charts Row -->
    <div class="grid-2 mb-3" id="charts-row">
      <div class="card">
        <div class="card-header">
          <div class="card-title">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
            Distribution CVSS (7 derniers jours)
          </div>
        </div>
        <div class="chart-container"><canvas id="chart-cvss"></canvas></div>
      </div>
      <div class="card">
        <div class="card-header">
          <div class="card-title">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/></svg>
            Répartition par Sévérité
          </div>
        </div>
        <div class="chart-container"><canvas id="chart-severity"></canvas></div>
      </div>
    </div>

    <!-- Recent CVEs + KEV -->
    <div class="grid-2" id="tables-row">
      <div class="card">
        <div class="card-header">
          <div class="card-title">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 8v4l3 3"/><circle cx="12" cy="12" r="10"/></svg>
            CVEs Récentes (24h)
          </div>
          <span class="text-muted mono" style="font-size:11px" id="recent-count">...</span>
        </div>
        <div id="recent-cves-list">
          ${skeletonRows(6)}
        </div>
      </div>
      <div class="card">
        <div class="card-header">
          <div class="card-title">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
            CISA KEV — Exploitées Activement
          </div>
          <span class="badge badge-kev" id="kev-total">...</span>
        </div>
        <div id="kev-list">
          ${skeletonRows(6)}
        </div>
      </div>
    </div>
  `;

  // Charger les données en parallèle
  document.getElementById('dash-refresh')?.addEventListener('click', () => render(container));

  try {
    const [stats, recent, kevData] = await Promise.all([
      getCVEStats(),
      getRecentCVEs(30),
      getKEVData(),
    ]);

    renderStats(stats);
    renderCharts(stats, recent);
    renderRecentCVEs(recent);
    renderKEV(kevData.list.slice(0, 20), kevData.list.length);
  } catch (e) {
    console.error('Dashboard error:', e);
    showDashError(container);
  }
}

// ── Stats Cards ──────────────────────────────────────────────
function renderStats(stats) {
  const grid = document.getElementById('stats-grid');
  if (!grid) return;

  const cards = [
    {
      label: 'Total CVEs (base)',
      value: stats.total.toLocaleString('fr'),
      meta: 'Toutes sévérités confondues',
      color: 'var(--cyan)',
      icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/></svg>`,
    },
    {
      label: 'Critiques',
      value: stats.critical.toLocaleString('fr'),
      meta: 'CVSS ≥ 9.0',
      color: 'var(--sev-critical)',
      icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/></svg>`,
    },
    {
      label: 'Hautes',
      value: stats.high.toLocaleString('fr'),
      meta: 'CVSS 7.0–8.9',
      color: 'var(--sev-high)',
      icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="m21 15-9-9-9 9"/></svg>`,
    },
    {
      label: 'Moyennes',
      value: stats.medium.toLocaleString('fr'),
      meta: 'CVSS 4.0–6.9',
      color: 'var(--sev-medium)',
      icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M5 12h14"/></svg>`,
    },
    {
      label: 'KEV — Exploitées',
      value: stats.kev.toLocaleString('fr'),
      meta: 'CISA Known Exploited',
      color: 'var(--purple)',
      icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/></svg>`,
    },
  ];

  grid.innerHTML = cards.map(c => `
    <div class="stat-card" style="--accent:${c.color}">
      <div class="stat-label">${c.label}</div>
      <div class="stat-value" style="color:${c.color}">${c.value}</div>
      <div class="stat-meta">${c.meta}</div>
      <div class="stat-icon" style="color:${c.color}">${c.icon}</div>
    </div>
  `).join('');
}

// ── Charts ───────────────────────────────────────────────────
function renderCharts(stats, recent) {
  // Détruire les charts existants
  Object.values(_charts).forEach(c => c?.destroy());
  _charts = {};

  // Chart 1: Distribution CVSS (histogramme des CVEs récentes)
  const cvssCanvas = document.getElementById('chart-cvss');
  if (cvssCanvas) {
    const bins = Array(10).fill(0); // 0-1, 1-2, ..., 9-10
    recent.forEach(cve => {
      if (cve.cvss != null) {
        const bin = Math.min(Math.floor(cve.cvss), 9);
        bins[bin]++;
      }
    });

    const labels = ['0-1','1-2','2-3','3-4','4-5','5-6','6-7','7-8','8-9','9-10'];
    const colors = bins.map((_, i) => {
      const score = i + 0.5;
      if (score >= 9) return 'rgba(255,51,102,0.8)';
      if (score >= 7) return 'rgba(255,107,26,0.8)';
      if (score >= 4) return 'rgba(255,193,7,0.8)';
      return 'rgba(0,230,118,0.8)';
    });

    _charts.cvss = new Chart(cvssCanvas, {
      type: 'bar',
      data: {
        labels,
        datasets: [{
          label: 'CVEs',
          data: bins,
          backgroundColor: colors,
          borderColor: colors.map(c => c.replace('0.8','1')),
          borderWidth: 1,
          borderRadius: 4,
        }]
      },
      options: chartOptions('Score CVSS'),
    });
  }

  // Chart 2: Severity Donut
  const sevCanvas = document.getElementById('chart-severity');
  if (sevCanvas) {
    _charts.sev = new Chart(sevCanvas, {
      type: 'doughnut',
      data: {
        labels: ['Critique', 'Haute', 'Moyenne', 'Basse'],
        datasets: [{
          data: [stats.critical, stats.high, stats.medium, stats.low],
          backgroundColor: [
            'rgba(255,51,102,0.85)',
            'rgba(255,107,26,0.85)',
            'rgba(255,193,7,0.85)',
            'rgba(0,230,118,0.85)',
          ],
          borderColor: ['#ff3366','#ff6b1a','#ffc107','#00e676'],
          borderWidth: 2,
          hoverOffset: 6,
        }]
      },
      options: {
        ...chartOptions(),
        cutout: '65%',
        scales: {
          x: { display: false },
          y: { display: false },
        },
        plugins: {
          legend: {
            display: true,
            position: 'right',
            labels: {
              color: '#94a3b8',
              font: { size: 11, family: 'JetBrains Mono' },
              boxWidth: 12,
              padding: 14,
            }
          },
          tooltip: {
            callbacks: {
              label: ctx => ` ${ctx.label}: ${ctx.parsed.toLocaleString('fr')}`,
            },
            backgroundColor: '#111827',
            borderColor: '#1e2d5a',
            borderWidth: 1,
            titleColor: '#e2e8f0',
            bodyColor: '#94a3b8',
          }
        }
      }
    });
  }
}

function chartOptions(yLabel = '') {
  return {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: '#111827',
        borderColor: '#1e2d5a',
        borderWidth: 1,
        titleColor: '#e2e8f0',
        bodyColor: '#94a3b8',
        titleFont: { family: 'JetBrains Mono', size: 11 },
        bodyFont: { family: 'JetBrains Mono', size: 11 },
      }
    },
    scales: {
      x: {
        grid: { color: 'rgba(30,45,90,0.5)' },
        ticks: { color: '#475569', font: { family: 'JetBrains Mono', size: 10 } },
      },
      y: {
        grid: { color: 'rgba(30,45,90,0.5)' },
        ticks: { color: '#475569', font: { family: 'JetBrains Mono', size: 10 } },
        title: yLabel ? { display: true, text: yLabel, color: '#475569' } : undefined,
      }
    }
  };
}

// ── Recent CVEs ──────────────────────────────────────────────
function renderRecentCVEs(cves) {
  const list = document.getElementById('recent-cves-list');
  const count = document.getElementById('recent-count');
  if (!list) return;
  if (count) count.textContent = `${cves.length} trouvées`;

  if (!cves.length) {
    list.innerHTML = `<div class="empty-state"><p>Aucune CVE trouvée dans les dernières 24h<br>(limite API NVD)</p></div>`;
    return;
  }

  list.innerHTML = `
    <div class="table-wrapper">
      <table>
        <thead>
          <tr>
            <th>CVE ID</th>
            <th>CVSS</th>
            <th>Sévérité</th>
            <th>Publiée</th>
          </tr>
        </thead>
        <tbody>
          ${cves.slice(0, 15).map(cve => `
            <tr class="clickable" data-cve="${cve.id}" title="${escHtml(cve.description.slice(0, 120))}">
              <td><span class="cve-id">${cve.id}</span></td>
              <td>
                <span class="cvss-score" style="color:${cvssColor(cve.cvss)}">
                  ${cve.cvss ?? '—'}
                </span>
              </td>
              <td><span class="badge badge-${(cve.severity||'none').toLowerCase()}">${cve.severity || 'N/A'}</span></td>
              <td class="text-muted mono" style="font-size:11px">${formatDate(cve.published)}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  `;

  // Clic → naviguer vers CVE search
  list.querySelectorAll('tr[data-cve]').forEach(row => {
    row.addEventListener('click', () => {
      window.__app?.navigate('cve', { search: row.dataset.cve });
    });
  });
}

// ── KEV List ─────────────────────────────────────────────────
function renderKEV(kevList, total) {
  const list = document.getElementById('kev-list');
  const badge = document.getElementById('kev-total');
  if (!list) return;
  if (badge) badge.textContent = total.toLocaleString('fr');

  if (!kevList.length) {
    list.innerHTML = `<div class="empty-state"><p>Impossible de charger la liste KEV</p></div>`;
    return;
  }

  // Trier par date ajout desc
  const sorted = [...kevList].sort((a, b) =>
    new Date(b.dateAdded || 0) - new Date(a.dateAdded || 0)
  );

  list.innerHTML = `
    <div class="table-wrapper">
      <table>
        <thead>
          <tr>
            <th>CVE</th>
            <th>Produit</th>
            <th>Ajoutée</th>
            <th>Délai patch</th>
          </tr>
        </thead>
        <tbody>
          ${sorted.slice(0, 15).map(kev => `
            <tr>
              <td><span class="cve-id">${kev.cveID}</span></td>
              <td class="truncate" style="max-width:160px" title="${escHtml(kev.vendorProject + ' — ' + kev.product)}">
                <span style="font-size:11px;color:var(--text-2)">${escHtml(kev.vendorProject)}</span>
              </td>
              <td class="mono text-muted" style="font-size:11px">${kev.dateAdded ?? '—'}</td>
              <td class="mono" style="font-size:11px">
                ${kev.dueDate
                  ? `<span style="color:${new Date(kev.dueDate) < new Date() ? 'var(--red)' : 'var(--green)'}">${kev.dueDate}</span>`
                  : '—'}
              </td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  `;
}

// ── Helpers ──────────────────────────────────────────────────
function skeletonRows(n) {
  return Array(n).fill(0).map(() => `
    <div style="padding:10px 14px;border-bottom:1px solid var(--border)">
      <div class="skeleton skeleton-line medium" style="margin-bottom:4px"></div>
      <div class="skeleton skeleton-line short"></div>
    </div>
  `).join('');
}

function showDashError(container) {
  const grid = document.getElementById('stats-grid');
  if (grid) {
    grid.innerHTML = `
      <div style="grid-column:1/-1;padding:20px;color:var(--text-3);text-align:center">
        <p>Impossible de charger les données NVD. Vérifiez votre connexion.</p>
        <p style="font-size:11px;margin-top:6px">L'API NVD peut être temporairement indisponible ou le rate limit est atteint.</p>
      </div>`;
  }
}

function escHtml(str) {
  return (str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
