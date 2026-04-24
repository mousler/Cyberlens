// ============================================================
//  blueteam.js — Vue Blue Team : Détection, Défense, SOC
// ============================================================

const SIGMA_RULES = [
  {
    name: 'Mimikatz — LSASS Memory Access',
    type: 'sigma',
    desc: 'Détection d\'accès à la mémoire LSASS (dump de credentials)',
    severity: 'CRITICAL',
    code: `title: Mimikatz — LSASS Memory Access
status: stable
description: Detects processes accessing lsass.exe memory (credential dumping)
tags:
  - attack.credential_access
  - attack.t1003.001
logsource:
  category: process_access
  product: windows
detection:
  selection:
    TargetImage|endswith: '\\lsass.exe'
    GrantedAccess|contains:
      - '0x1010'
      - '0x1038'
      - '0x40'
      - '0x1400'
  filter_legitimate:
    SourceImage|startswith:
      - 'C:\\Windows\\System32\\'
      - 'C:\\Program Files\\Windows Defender\\'
  condition: selection and not filter_legitimate
falsepositives:
  - AV scanners, backup software
level: critical`,
  },
  {
    name: 'Kerberoasting — SPN Ticket Request',
    type: 'sigma',
    desc: 'Détection des requêtes Kerberoast via EventID 4769',
    severity: 'HIGH',
    code: `title: Kerberoasting — Service Ticket Request
status: stable
description: Detects Kerberoasting via abnormal Kerberos service ticket requests
tags:
  - attack.credential_access
  - attack.t1558.003
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    ServiceName|endswith: '$'
    TicketEncryptionType: '0x17'   # RC4 — indication de Kerberoasting
    Status: '0x0'
  filter_machine:
    AccountName|endswith: '$'
  condition: selection and not filter_machine
falsepositives:
  - Old applications using RC4
level: high`,
  },
  {
    name: 'PowerShell — Encoded Command Execution',
    type: 'sigma',
    desc: 'Détection d\'exécution PowerShell encodé en Base64 (technique courante d\'évasion)',
    severity: 'HIGH',
    code: `title: PowerShell Encoded Command Execution
status: stable
description: Detects PowerShell execution with Base64 encoded commands
tags:
  - attack.defense_evasion
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection_ps:
    Image|endswith:
      - '\\powershell.exe'
      - '\\pwsh.exe'
  selection_encoded:
    CommandLine|contains:
      - ' -EncodedCommand '
      - ' -enc '
      - ' -ec '
  selection_suspicious:
    CommandLine|contains:
      - 'JAB'     # Variable assignment en B64
      - 'SQEX'    # IEX (Invoke-Expression) en B64
      - 'SQBFAFgA'
  condition: selection_ps and (selection_encoded or selection_suspicious)
falsepositives:
  - Legitimate admin scripts using encoded commands
level: high`,
  },
  {
    name: 'YARA — Webshell Detection',
    type: 'yara',
    desc: 'Règle YARA pour détecter les webshells PHP/ASPX communs',
    severity: 'CRITICAL',
    code: `rule Webshell_Generic_Detection {
  meta:
    description = "Detects common webshell patterns"
    author = "Cyberlens Team"
    date = "2024-01-01"
    severity = "CRITICAL"

  strings:
    // PHP webshells
    $php1 = "eval(base64_decode" nocase
    $php2 = "eval(gzinflate" nocase
    $php3 = "assert($_" nocase
    $php4 = "system($_GET" nocase
    $php5 = "passthru($_REQUEST" nocase

    // ASP/ASPX webshells
    $asp1 = "<%@ Page Language=\"Jscript\"%>" nocase
    $asp2 = "Response.Write(eval(Request" nocase
    $asp3 = "cmd.exe /c" nocase

    // China Chopper (très répandu)
    $chopper = { 65 76 61 6C 28 52 65 71 75 65 73 74 }

    // Generic
    $generic1 = "cmd_shell"
    $generic2 = "shell_exec" nocase

  condition:
    (2 of ($php*)) or
    (1 of ($asp*)) or
    $chopper or
    (1 of ($generic*) and filesize < 100KB)
}`,
  },
  {
    name: 'Snort — EternalBlue SMB Detection',
    type: 'snort',
    desc: 'Règle Snort/Suricata pour détecter les tentatives EternalBlue',
    severity: 'CRITICAL',
    code: `# Suricata/Snort Rule — EternalBlue MS17-010
alert tcp any any -> $HOME_NET 445 (
  msg:"ET EXPLOIT EternalBlue MS17-010 Attempt";
  flow:to_server,established;
  content:"|ff|SMB|72|";
  content:"|00 00 00 00 00 00 00|";
  within:7;
  distance:13;
  threshold: type both, track by_src, count 3, seconds 60;
  sid:2024218;
  rev:3;
  classtype:attempted-admin;
  metadata:severity high;
)

alert tcp $HOME_NET any -> any 4444 (
  msg:"ET TROJAN Common Reverse Shell Port";
  flow:established,to_server;
  content:"|00 50 56|";
  threshold: type both, track by_src, count 2, seconds 30;
  sid:2099001;
  rev:1;
)`,
  },
  {
    name: 'KQL — Azure Sentinel — Suspicious Sign-ins',
    type: 'kql',
    desc: 'Requête Microsoft Sentinel pour détecter les connexions suspectes (impossible travel, spray)',
    severity: 'HIGH',
    code: `// Microsoft Sentinel — Suspicious Sign-in Detection
// Impossible travel + password spray detection

// 1. Impossible Travel
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == "0"  // Succès
| summarize Locations = make_set(Location),
            IPs = make_set(IPAddress),
            Countries = make_set(LocationDetails.countryOrRegion)
  by UserPrincipalName, bin(TimeGenerated, 10m)
| where array_length(Countries) > 1
| project TimeGenerated, UserPrincipalName, Locations, Countries, IPs
| order by TimeGenerated desc

// 2. Password Spray (même IP, multiples comptes)
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType in ("50126", "50056", "50053")  // Échecs auth
| summarize FailedAttempts = count(),
            UniqueAccounts = dcount(UserPrincipalName),
            Accounts = make_set(UserPrincipalName)
  by IPAddress, bin(TimeGenerated, 10m)
| where UniqueAccounts > 20
| order by FailedAttempts desc`,
  },
];

const IOC_FEEDS = [
  { name: 'CISA KEV', desc: 'Vulnérabilités exploitées activement (officiel)', url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', color: '#a855f7' },
  { name: 'Abuse.ch MalwareBazaar', desc: 'Hashes de malwares récents', url: 'https://bazaar.abuse.ch/export/json/recent/', color: '#ff3366' },
  { name: 'Threat Fox', desc: 'IOCs C2, URLs, IPs malveillantes', url: 'https://threatfox-api.abuse.ch/api/v1/', color: '#ff6b1a' },
  { name: 'OTX AlienVault', desc: 'Pulses de threat intelligence partagée', url: 'https://otx.alienvault.com/api/v1/pulses/subscribed', color: '#00e676' },
  { name: 'URLhaus', desc: 'URLs de distribution de malwares', url: 'https://urlhaus-api.abuse.ch/v1/urls/recent/', color: '#00d4ff' },
  { name: 'PhishTank', desc: 'Sites de phishing confirmés', url: 'https://data.phishtank.com/data/online-valid.json', color: '#ffd700' },
];

const HARDENING_CHECKS = [
  { category: 'Windows Active Directory', items: [
    { name: 'Désactiver LLMNR/NetBIOS', status: 'todo', risk: 'HIGH', cmd: 'Set-NetAdapterBinding -AllBindings -ComponentID ms_msclient -Enabled $false' },
    { name: 'Activer SMB Signing', status: 'todo', risk: 'HIGH', cmd: 'Set-SmbServerConfiguration -RequireSecuritySignature $true' },
    { name: 'Désactiver SMBv1', status: 'todo', risk: 'CRITICAL', cmd: 'Set-SmbServerConfiguration -EnableSMB1Protocol $false' },
    { name: 'Protected Users Security Group', status: 'todo', risk: 'HIGH', cmd: 'Add-ADGroupMember "Protected Users" -Members privileged_accounts' },
    { name: 'Activer LAPS', status: 'todo', risk: 'HIGH', cmd: '# Déployer Microsoft LAPS via GPO' },
    { name: 'Audit Policy avancée', status: 'todo', risk: 'MEDIUM', cmd: 'auditpol /set /category:* /success:enable /failure:enable' },
  ]},
  { category: 'Réseau & Firewall', items: [
    { name: 'Bloquer SMB sortant (445)', status: 'todo', risk: 'HIGH', cmd: 'New-NetFirewallRule -Direction Outbound -Protocol TCP -RemotePort 445 -Action Block' },
    { name: 'Segmentation réseau (VLANs)', status: 'todo', risk: 'HIGH', cmd: '# Configurer VLANs sur switches managés' },
    { name: 'Désactiver RDP si non requis', status: 'todo', risk: 'MEDIUM', cmd: 'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" -Name fDenyTSConnections -Value 1' },
    { name: 'NPS — Network Policy Server', status: 'todo', risk: 'MEDIUM', cmd: '# Configurer 802.1X pour l\'authentification réseau' },
  ]},
  { category: 'Endpoints & EDR', items: [
    { name: 'Déployer EDR (Defender for Endpoint / CrowdStrike)', status: 'todo', risk: 'CRITICAL', cmd: '# Via Intune / SCCM' },
    { name: 'Activer ASR Rules (Attack Surface Reduction)', status: 'todo', risk: 'HIGH', cmd: 'Set-MpPreference -AttackSurfaceReductionRules_Actions 1 -AttackSurfaceReductionRules_Ids <GUID>' },
    { name: 'Bloquer macros Office dans les emails', status: 'todo', risk: 'HIGH', cmd: '# Via GPO: User Config > Admin Templates > Microsoft Office' },
    { name: 'Activer PowerShell ScriptBlock Logging', status: 'todo', risk: 'MEDIUM', cmd: 'Set-ItemProperty HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging -Name EnableScriptBlockLogging -Value 1' },
    { name: 'Application Whitelisting (AppLocker/WDAC)', status: 'todo', risk: 'HIGH', cmd: '# Via GPO: Computer Config > Windows Settings > Security Settings > Application Control' },
  ]},
];

export function render(container) {
  container.innerHTML = '';
  container.className = 'content fade-in';

  container.innerHTML = `
    <div class="page-header">
      <div>
        <div class="page-title" style="color:var(--cyan)">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/>
            <path d="m9 12 2 2 4-4"/>
          </svg>
          Blue Team
        </div>
        <div class="page-subtitle">Détection · Réponse aux incidents · Durcissement · IOC Feeds</div>
      </div>
      <span class="badge badge-info" style="padding:6px 14px">🛡️ Defensive Security</span>
    </div>

    <!-- Tabs -->
    <div class="tab-nav" style="background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius-lg) var(--radius-lg) 0 0;padding:0 16px;margin-bottom:0">
      <button class="tab-btn active" data-tab="rules">Règles de détection</button>
      <button class="tab-btn" data-tab="hardening">Durcissement</button>
      <button class="tab-btn" data-tab="ioc">IOC Feeds</button>
      <button class="tab-btn" data-tab="ir">Réponse incident</button>
    </div>

    <div style="background:var(--bg-card);border:1px solid var(--border);border-top:none;border-radius:0 0 var(--radius-lg) var(--radius-lg);overflow-y:auto;max-height:calc(100vh - 220px)">

      <!-- Detection Rules -->
      <div class="tab-pane active" id="tab-rules" style="padding:16px">
        <div style="display:flex;gap:8px;margin-bottom:14px">
          ${['sigma','yara','snort','kql'].map(t => `
            <span class="rule-type ${t}" style="cursor:pointer;padding:4px 10px;border-radius:4px" data-rule-filter="${t}">${t.toUpperCase()}</span>
          `).join('')}
          <span style="cursor:pointer;padding:4px 10px;border-radius:4px;background:var(--bg-2);color:var(--text-3);font-size:10px" data-rule-filter="all">Tout afficher</span>
        </div>
        <div id="rules-list">
          ${SIGMA_RULES.map(rule => `
            <div class="rule-card" data-rule-type="${rule.type}">
              <div class="rule-header">
                <div style="display:flex;align-items:center;gap:10px">
                  <span class="rule-type ${rule.type}">${rule.type.toUpperCase()}</span>
                  <span style="font-size:13px;font-weight:600;color:var(--text-1)">${rule.name}</span>
                </div>
                <div style="display:flex;align-items:center;gap:8px">
                  <span class="badge badge-${rule.severity.toLowerCase()}">${rule.severity}</span>
                  <span style="color:var(--text-3);font-size:12px">▼</span>
                </div>
              </div>
              <div class="rule-body" style="display:none;padding:0 14px 14px">
                <p style="font-size:12px;color:var(--text-2);margin-bottom:10px">${rule.desc}</p>
                <div class="code-block">
                  <div class="code-header">
                    <span class="code-lang">${rule.type}</span>
                    <button class="code-copy">Copier</button>
                  </div>
                  <pre><code class="language-yaml">${escHtml(rule.code)}</code></pre>
                </div>
              </div>
            </div>
          `).join('')}
        </div>
      </div>

      <!-- Hardening -->
      <div class="tab-pane" id="tab-hardening" style="padding:16px">
        <div style="margin-bottom:14px;padding:12px 16px;background:var(--cyan-glow);border:1px solid var(--cyan-dim);border-radius:8px;font-size:12px;color:var(--cyan)">
          💡 Checklist de durcissement — Cochez les éléments implémentés dans votre environnement.
        </div>
        ${HARDENING_CHECKS.map(cat => `
          <div style="margin-bottom:18px">
            <div class="section-title">${cat.category}</div>
            <div style="display:flex;flex-direction:column;gap:6px">
              ${cat.items.map((item, i) => `
                <div class="card" style="padding:12px 14px">
                  <div style="display:flex;align-items:center;gap:10px">
                    <input type="checkbox" id="harden-${cat.category.replace(/\s/g,'')}-${i}"
                      style="width:16px;height:16px;accent-color:var(--cyan);cursor:pointer">
                    <div style="flex:1">
                      <label for="harden-${cat.category.replace(/\s/g,'')}-${i}"
                        style="font-size:13px;color:var(--text-1);cursor:pointer;font-weight:500">
                        ${item.name}
                      </label>
                      <div style="margin-top:3px">
                        <span class="badge badge-${item.risk.toLowerCase()}">${item.risk}</span>
                      </div>
                    </div>
                    <button class="btn btn-ghost btn-sm" onclick="
                      navigator.clipboard?.writeText(${JSON.stringify(item.cmd)});
                      this.textContent='✓';setTimeout(()=>this.textContent='Copier cmd',1500)
                    ">Copier cmd</button>
                  </div>
                  <div style="margin-top:8px;padding:6px 10px;background:var(--bg-2);border-radius:4px">
                    <code style="font-family:var(--text-mono);font-size:10px;color:var(--text-3)">${escHtml(item.cmd)}</code>
                  </div>
                </div>
              `).join('')}
            </div>
          </div>
        `).join('')}
      </div>

      <!-- IOC Feeds -->
      <div class="tab-pane" id="tab-ioc" style="padding:16px">
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:12px;margin-bottom:20px">
          ${IOC_FEEDS.map(feed => `
            <div class="card" style="border-left:3px solid ${feed.color}">
              <div style="display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:8px">
                <div>
                  <div style="font-size:14px;font-weight:700;color:${feed.color}">${feed.name}</div>
                  <div style="font-size:11px;color:var(--text-2);margin-top:3px">${feed.desc}</div>
                </div>
                <a href="${feed.url}" target="_blank" class="btn btn-ghost btn-sm" style="font-size:10px;padding:3px 8px;flex-shrink:0">Feed ↗</a>
              </div>
              <div style="font-family:var(--text-mono);font-size:9px;color:var(--text-3);word-break:break-all">${feed.url}</div>
            </div>
          `).join('')}
        </div>

        <!-- IOC Lookup -->
        <div class="card" style="padding:16px">
          <div class="card-title" style="margin-bottom:10px">🔍 Lookup IOC rapide</div>
          <div style="display:flex;gap:8px;margin-bottom:12px">
            <input type="text" id="ioc-input" class="search-input" style="flex:1"
              placeholder="IP, domaine, hash MD5/SHA256, URL...">
            <button class="btn btn-primary" id="ioc-lookup">Analyser</button>
          </div>
          <div id="ioc-links" style="display:none;display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:6px">
            ${getIOCLinks('').map(l => `
              <a href="${l.url}" target="_blank" class="btn btn-ghost btn-sm" style="font-size:11px" data-ioc-link data-template="${l.template}">
                ${l.icon} ${l.name}
              </a>
            `).join('')}
          </div>
        </div>
      </div>

      <!-- Incident Response -->
      <div class="tab-pane" id="tab-ir" style="padding:16px">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">
          ${getIRPlaybooks().map(pb => `
            <div class="card">
              <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px">
                <span style="font-size:20px">${pb.icon}</span>
                <div>
                  <div style="font-size:13px;font-weight:700;color:var(--text-1)">${pb.name}</div>
                  <span class="badge badge-${pb.severity.toLowerCase()}">${pb.severity}</span>
                </div>
              </div>
              <div style="display:flex;flex-direction:column;gap:4px">
                ${pb.steps.map((step, i) => `
                  <div style="display:flex;gap:8px;padding:6px 8px;background:var(--bg-2);border-radius:5px;align-items:flex-start">
                    <span style="font-family:var(--text-mono);font-size:10px;color:var(--cyan);font-weight:700;width:18px;flex-shrink:0">${i + 1}.</span>
                    <div>
                      <div style="font-size:11px;font-weight:600;color:var(--text-1)">${step.action}</div>
                      ${step.cmd ? `<code style="font-size:9px;color:var(--text-3);font-family:var(--text-mono)">${escHtml(step.cmd)}</code>` : ''}
                    </div>
                  </div>
                `).join('')}
              </div>
            </div>
          `).join('')}
        </div>
      </div>
    </div>
  `;

  // Tabs
  container.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      container.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      container.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById('tab-' + btn.dataset.tab)?.classList.add('active');
    });
  });

  // Rule accordion
  container.querySelectorAll('.rule-header').forEach(header => {
    header.addEventListener('click', () => {
      const body   = header.nextElementSibling;
      const arrow  = header.querySelector('span:last-child');
      const isOpen = body.style.display !== 'none';
      body.style.display = isOpen ? 'none' : 'block';
      if (arrow) arrow.textContent = isOpen ? '▼' : '▲';
      if (!isOpen) {
        body.querySelectorAll('pre code').forEach(el => { if (window.hljs) window.hljs.highlightElement(el); });
      }
    });
  });

  // Rule type filters
  container.querySelectorAll('[data-rule-filter]').forEach(chip => {
    chip.addEventListener('click', () => {
      const f = chip.dataset.ruleFilter;
      container.querySelectorAll('.rule-card').forEach(card => {
        card.style.display = (f === 'all' || card.dataset.ruleType === f) ? '' : 'none';
      });
    });
  });

  // IOC lookup
  document.getElementById('ioc-lookup')?.addEventListener('click', () => {
    const val = document.getElementById('ioc-input')?.value.trim();
    if (!val) return;
    const linksDiv = document.getElementById('ioc-links');
    if (linksDiv) {
      linksDiv.style.display = 'grid';
      linksDiv.querySelectorAll('[data-ioc-link]').forEach(a => {
        const url = a.dataset.template?.replace('{IOC}', encodeURIComponent(val));
        a.href = url || '#';
      });
    }
  });

  // Code copy
  setTimeout(() => {
    container.querySelectorAll('.code-copy').forEach(btn => {
      btn.addEventListener('click', () => {
        const code = btn.closest('.code-block')?.querySelector('code')?.textContent || '';
        navigator.clipboard?.writeText(code).then(() => { btn.textContent = '✓'; setTimeout(() => btn.textContent = 'Copier', 1500); });
      });
    });
  }, 50);
}

function getIOCLinks(ioc) {
  return [
    { name: 'VirusTotal',  icon: '🔬', template: `https://www.virustotal.com/gui/search/{IOC}` },
    { name: 'Shodan',      icon: '🔭', template: `https://www.shodan.io/host/{IOC}` },
    { name: 'OTX',         icon: '📡', template: `https://otx.alienvault.com/indicator/ip/{IOC}` },
    { name: 'AbuseIPDB',   icon: '🚫', template: `https://www.abuseipdb.com/check/{IOC}` },
    { name: 'Talos Intel', icon: '🛡️', template: `https://talosintelligence.com/reputation_center/lookup?search={IOC}` },
    { name: 'URLScan.io',  icon: '🌐', template: `https://urlscan.io/search/#page.domain:{IOC}` },
    { name: 'Censys',      icon: '📊', template: `https://search.censys.io/hosts/{IOC}` },
    { name: 'ThreatBook',  icon: '📖', template: `https://threatbook.io/ip/{IOC}` },
  ];
}

function getIRPlaybooks() {
  return [
    {
      name: 'Ransomware — Réponse immédiate',
      icon: '💀', severity: 'CRITICAL',
      steps: [
        { action: 'Isoler les systèmes affectés du réseau', cmd: 'netsh interface set interface "LAN" admin=disabled' },
        { action: 'Identifier le patient zéro et la timeline', cmd: '' },
        { action: 'Sauvegarder les logs systèmes et réseau', cmd: 'wevtutil epl System C:\\IR\\system.evtx' },
        { action: 'Vérifier l\'intégrité des sauvegardes (hors ligne)', cmd: '' },
        { action: 'Notifier CIRT/CERT-FR + direction', cmd: '' },
        { action: 'Identifier le ransomware (ID Ransomware)', cmd: '' },
        { action: 'Analyser les IOCs et chercher la persistance', cmd: 'Get-ScheduledTask | Where Status -eq "Ready"' },
        { action: 'Décision: payer vs restauration', cmd: '' },
      ],
    },
    {
      name: 'Compromission Active Directory',
      icon: '🏰', severity: 'CRITICAL',
      steps: [
        { action: 'Réinitialiser le compte krbtgt (deux fois)', cmd: 'Set-ADAccountPassword -Identity krbtgt -Reset' },
        { action: 'Identifier les comptes compromis', cmd: 'Get-ADUser -Filter * | Where {$_.PasswordLastSet -gt (Get-Date).AddDays(-1)}' },
        { action: 'Révoquer tous les tickets Kerberos', cmd: 'Invoke-Command -ScriptBlock { klist purge }' },
        { action: 'Analyser BloodHound pour les chemins exploités', cmd: '' },
        { action: 'Vérifier les GPOs modifiées récemment', cmd: 'Get-GPO -All | Sort-Object ModificationTime -Desc | Select -First 10' },
        { action: 'Vérifier les nouveaux comptes admin', cmd: 'Get-ADGroupMember "Domain Admins"' },
        { action: 'Chercher les backdoors (compte admin cachés)', cmd: '' },
      ],
    },
    {
      name: 'Phishing — Réponse email',
      icon: '🎣', severity: 'HIGH',
      steps: [
        { action: 'Purger l\'email malveillant de toutes les boîtes', cmd: "Search-UnifiedAuditLog -Operations 'Send'" },
        { action: 'Bloquer l\'expéditeur et le domaine', cmd: 'New-TransportRule -SenderDomains evil.com -Action Reject' },
        { action: 'Identifier les victimes qui ont cliqué', cmd: '' },
        { action: 'Analyser les pièces jointes dans sandbox', cmd: '' },
        { action: 'Vérifier les connexions suspectes des victimes', cmd: '' },
        { action: 'Réinitialiser les credentials compromis', cmd: '' },
        { action: 'Former les utilisateurs impactés', cmd: '' },
      ],
    },
    {
      name: 'Data Breach — Fuite de données',
      icon: '🔓', severity: 'HIGH',
      steps: [
        { action: 'Identifier la source et le volume de données', cmd: '' },
        { action: 'Contenir la fuite (bloquer les accès)', cmd: '' },
        { action: 'Notifier le DPO + évaluer obligation RGPD', cmd: '// CNIL: notification dans 72h si violation' },
        { action: 'Préserver les preuves (forensics)', cmd: 'dd if=/dev/sda of=/mnt/backup/disk.img bs=4M' },
        { action: 'Identifier les données exfiltrées', cmd: '' },
        { action: 'Notifier les personnes concernées si requis', cmd: '' },
        { action: 'Analyse post-incident + plan de correction', cmd: '' },
      ],
    },
  ];
}

function escHtml(str) {
  return (str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
