import { useState, useEffect, useCallback, useId } from "react";

// ── Geometry ──────────────────────────────────────────────────
const CR = 36,
  TH = 42,
  N = 12;
const MAX = CR + (N - 1) * TH; // 498
const VW = MAX + 12; // 510
const VH = MAX * 2 + 12; // 1008
const CX = 2;
const CY = VH / 2; // 504

const oR = (id) => CR + id * TH;
const iR = (id) => (id === 0 ? 0 : CR + (id - 1) * TH);
const mR = (id) => (oR(id) + iR(id)) / 2;

function onArc(r, deg) {
  const a = (deg * Math.PI) / 180;
  return [CX + r * Math.cos(a), CY - r * Math.sin(a)];
}

function coverageColor(pct) {
  if (pct >= 80) return "#22c55e";
  if (pct >= 60) return "#84cc16";
  if (pct >= 45) return "#f59e0b";
  if (pct >= 30) return "#f97316";
  return "#ef4444";
}

// ── Threat meter streams ──────────────────────────────────────
const STREAMS = [
  { id: 0, angle: 12, stopId: 11, color: "#ff3366", dur: 2.8, delay: 0 },
  { id: 1, angle: -12, stopId: 11, color: "#00aaff", dur: 3.2, delay: 0.5 },
  { id: 2, angle: 35, stopId: 10, color: "#ff7700", dur: 3.5, delay: 0.9 },
  { id: 3, angle: -35, stopId: 9, color: "#ff7700", dur: 2.6, delay: 1.8 },
  { id: 4, angle: 55, stopId: 8, color: "#d4b800", dur: 2.4, delay: 1.1 },
  { id: 5, angle: -55, stopId: 8, color: "#d4b800", dur: 2.8, delay: 2.6 },
  { id: 6, angle: 70, stopId: 6, color: "#ff7700", dur: 3.1, delay: 0.4 },
  { id: 7, angle: -70, stopId: 5, color: "#ff7700", dur: 3.9, delay: 3.0 },
  { id: 8, angle: 82, stopId: 4, color: "#ff7700", dur: 3.4, delay: 2.0 },
  { id: 9, angle: -82, stopId: 3, color: "#00aaff", dur: 3.7, delay: 1.4 },
  { id: 10, angle: 90, stopId: 2, color: "#aa44ff", dur: 4.3, delay: 2.3 },
];

const LAYERS = [
  {
    id: 0,
    short: "DATA",
    color: "#e82020",
    tc: "#fff",
    badge: "CORE",
    icon: "🗄",
    sub: "Critical Assets",
    coverage: 55,
    maturity: {
      typical: 2,
      levels: [
        [
          "Initial",
          "No formal controls. Plaintext backups, no classification.",
        ],
        ["Managed", "AES-256 at rest. Basic access control in place."],
        ["Defined", "TDE + KMS + documented data classification policy."],
        [
          "Quantified",
          "Automated key rotation + DLP integration + full audit trail.",
        ],
        [
          "Optimizing",
          "Zero-knowledge encryption + ML data discovery + continuous review.",
        ],
      ],
    },
    desc: "Everything we protect — databases, secrets, PII, intellectual property. All other layers exist solely to defend this.",
    items: [
      "Databases (SQL / NoSQL)",
      "Secrets & API keys",
      "PII / personal data",
      "Business logic & source code",
      "IP & trade secrets",
    ],
    enc: [
      "AES-256 at rest",
      "TDE — Transparent DB Encryption",
      "HashiCorp Vault / AWS KMS",
      "Envelope encryption",
    ],
    tools: [
      "HashiCorp Vault",
      "AWS KMS",
      "GCP Cloud KMS",
      "CipherTrust Manager",
    ],
    attacks: [
      "Direct DB injection bypassing app layer",
      "Backup file theft (unencrypted backups)",
      "Data Encrypted for Impact (ransomware)",
      "Unprotected S3 bucket / cloud storage exposure",
    ],
    mitre: [
      ["T1005", "Data from Local System"],
      ["T1213", "Data from Info Repositories"],
      ["T1486", "Data Encrypted for Impact"],
      ["T1530", "Data from Cloud Storage"],
    ],
    compliance: [
      ["PCI DSS", "3.4–3.5 — Protect stored cardholder data"],
      ["ISO 27001", "A.8 — Asset management"],
      ["GDPR", "Art. 32 — Security of processing"],
      ["HIPAA", "§164.312(a)(2)(iv) — Encryption"],
      ["SOC 2", "CC6.7 — Data encryption"],
      ["NIST CSF", "PR.DS — Data security"],
    ],
    zt: "ABAC / RBAC at data level. Every access is logged and attributed.",
    ztOn: true,
  },

  {
    id: 1,
    short: "DLP",
    color: "#ff3300",
    tc: "#fff",
    badge: "PREVENT",
    icon: "🚧",
    sub: "Data Loss Prevention",
    coverage: 40,
    maturity: {
      typical: 1,
      levels: [
        ["Initial", "No DLP. Data exits unchecked via email, USB, cloud."],
        ["Managed", "Basic email DLP rules. USB blocked on some endpoints."],
        ["Defined", "Network + endpoint DLP with content inspection policies."],
        [
          "Quantified",
          "Integrated DLP: endpoint + network + cloud with risk scoring.",
        ],
        [
          "Optimizing",
          "ML-based content classification + adaptive DLP + zero-trust data flows.",
        ],
      ],
    },
    desc: "Detects and blocks unauthorised data exfiltration via email, USB, cloud upload or clipboard. Closest layer to the data.",
    items: [
      "Endpoint DLP — USB / print / clipboard",
      "Network DLP — email / web / FTP",
      "Cloud DLP — SaaS upload scanning",
      "Content inspection: regex + ML",
      "Shadow copy control",
    ],
    enc: [
      "AES-256 policy & incident log storage",
      "TLS 1.3 agent ↔ server",
      "Encrypted policy push channel",
    ],
    tools: [
      "Forcepoint DLP",
      "Symantec DLP",
      "Microsoft Purview",
      "GTB Technologies",
    ],
    attacks: [
      "USB drive exfiltration bypassing DLP agent",
      "Screenshot / print bypass",
      "Cloud sync to personal account",
      "Steganography in allowed file types",
    ],
    mitre: [
      ["T1048", "Exfil Over Alternative Protocol"],
      ["T1052", "Exfil Over Physical Medium"],
      ["T1537", "Transfer Data to Cloud Account"],
      ["T1567", "Exfil Over Web Service"],
    ],
    compliance: [
      ["PCI DSS", "12.3 — Protect stored media"],
      ["ISO 27001", "A.8.3 — Media handling"],
      ["GDPR", "Art. 25 — Data protection by design"],
      ["SOC 2", "CC6.6 — Logical access controls"],
      ["NIST CSF", "PR.DS-5 — Leakage protection"],
    ],
    zt: "Data leaves only via verified, authorised, audited channels.",
    ztOn: true,
  },

  {
    id: 2,
    short: "PAM",
    color: "#ff5500",
    tc: "#fff",
    badge: "ACCESS",
    icon: "🔑",
    sub: "Privileged Access Management",
    coverage: 50,
    maturity: {
      typical: 2,
      levels: [
        [
          "Initial",
          "Shared root passwords. No session recording. Standing admin access everywhere.",
        ],
        ["Managed", "Password vault in place. Basic MFA for admins."],
        [
          "Defined",
          "JIT access + session recording + formal approval workflow.",
        ],
        [
          "Quantified",
          "Automated access reviews + behavioural analytics on sessions.",
        ],
        [
          "Optimizing",
          "Zero standing privilege + continuous session analysis + ML-based anomaly detection.",
        ],
      ],
    },
    desc: "Just-in-time access, password vaulting, session recording. Controls who reaches the core and how. Eliminates standing privileges.",
    items: [
      "CyberArk / BeyondTrust / Thycotic",
      "Just-in-Time (JIT) access",
      "Session recording & replay",
      "Password & key vaulting",
      "Break-glass procedures",
    ],
    enc: [
      "AES-256 encrypted vault",
      "TLS 1.3 for privileged sessions",
      "HSM for master key storage",
      "Encrypted session recordings",
    ],
    tools: ["CyberArk PAM", "BeyondTrust", "Delinea / Thycotic", "Teleport"],
    attacks: [
      "Pass-the-hash / Pass-the-ticket",
      "Kerberoasting & AS-REP Roasting",
      "Golden / Silver Ticket",
      "MFA fatigue / push bombing",
      "Credential stuffing against admin portals",
    ],
    mitre: [
      ["T1078", "Valid Accounts"],
      ["T1098", "Account Manipulation"],
      ["T1556", "Modify Auth Process"],
      ["T1003", "OS Credential Dumping"],
      ["T1558", "Steal / Forge Kerberos Tickets"],
    ],
    compliance: [
      ["PCI DSS", "7.1–7.3 — Least privilege access"],
      ["ISO 27001", "A.9 — Access control"],
      ["SOC 2", "CC6.3 — Logical access provisioning"],
      ["CIS", "Control 5 — Account management"],
      ["NIST 800-53", "AC — Access control family"],
    ],
    zt: "ZT foundation: least-privilege, time-limited credentials. Zero standing admin access.",
    ztOn: true,
  },

  {
    id: 3,
    short: "EDR",
    color: "#f07010",
    tc: "#fff",
    badge: "HOST",
    icon: "💻",
    sub: "Endpoint Detection & Response",
    coverage: 78,
    maturity: {
      typical: 3,
      levels: [
        [
          "Initial",
          "Signature-based AV only. No EDR. Fileless malware invisible.",
        ],
        ["Managed", "EDR deployed on most endpoints. Basic alert triage."],
        ["Defined", "EDR on all endpoints + automated isolation playbooks."],
        ["Quantified", "EDR + threat hunting + host-based telemetry to SIEM."],
        [
          "Optimizing",
          "Full telemetry + AI-based detection + automated remediation + memory forensics.",
        ],
      ],
    },
    desc: "Host-level protection. Sees processes, memory, file activity before any traffic leaves the machine. First responder to ransomware and fileless attacks.",
    items: [
      "CrowdStrike / SentinelOne / MS Defender",
      "Process injection detection",
      "Fileless malware & LOLBin detection",
      "Lateral movement blocking",
      "Ransomware rollback / host isolation",
    ],
    enc: [
      "FDE — Full Disk Encryption",
      "BitLocker / FileVault / LUKS",
      "Secure Boot + TPM 2.0",
      "AMD SME / Intel TME memory encryption",
    ],
    tools: [
      "CrowdStrike Falcon",
      "SentinelOne",
      "Microsoft Defender XDR",
      "Carbon Black",
    ],
    attacks: [
      "Process injection (DLL injection, reflective loading)",
      "LOLBins: powershell, wmic, certutil",
      "Fileless malware in memory only",
      "Ransomware deployment after dwell time",
      "EDR tampering / agent unloading",
    ],
    mitre: [
      ["T1055", "Process Injection"],
      ["T1059", "Command & Scripting Interpreter"],
      ["T1036", "Masquerading"],
      ["T1562.001", "Disable Security Tools"],
      ["T1112", "Modify Registry"],
    ],
    compliance: [
      ["PCI DSS", "5.1 — Anti-malware on all systems"],
      ["ISO 27001", "A.12.2 — Malware protection"],
      ["SOC 2", "CC7.2 — Anomaly detection"],
      ["CIS", "Control 10 — Malware defenses"],
      ["NIST CSF", "DE.CM-4 — Malicious code detection"],
    ],
    zt: "Device trust gate: EDR health status is a hard ZT access condition.",
    ztOn: true,
  },

  {
    id: 4,
    short: "VLAN/802.1X",
    color: "#c8b820",
    tc: "#110e00",
    badge: "NET L2",
    icon: "🔀",
    sub: "Segmentation + PEAP / NAC",
    coverage: 65,
    maturity: {
      typical: 2,
      levels: [
        [
          "Initial",
          "Flat network. No VLAN segmentation. All devices on same broadcast domain.",
        ],
        ["Managed", "Basic VLANs for servers vs users. No NAC."],
        ["Defined", "VLANs + 802.1X NAC + quarantine VLAN for failures."],
        [
          "Quantified",
          "Micro-segmentation + dynamic VLAN assignment based on device posture.",
        ],
        [
          "Optimizing",
          "SDN-based policy enforcement + continuous device trust scoring + automated remediation.",
        ],
      ],
    },
    desc: "Network isolation with identity-aware admission. PEAP / 802.1X verifies device BEFORE VLAN assignment. No auth = quarantine VLAN.",
    items: [
      "802.1Q VLAN trunking",
      "PEAP / EAP-TLS / 802.1X NAC",
      "WPA3-Enterprise for Wi-Fi",
      "Private VLAN (PVLAN)",
      "Micro-segmentation / SDN",
    ],
    enc: [
      "PEAP — TLS tunnel for 802.1X",
      "MACsec (802.1AE) — L2 wire encryption",
      "VXLAN + IPSec overlays",
      "RadSec — RADIUS over TLS",
    ],
    tools: ["Cisco ISE", "Aruba ClearPass", "FreeRADIUS", "Portnox Cloud NAC"],
    attacks: [
      "VLAN hopping (double tagging)",
      "MAC address spoofing to bypass NAC",
      "Rogue access point injection",
      "802.1X bypass via hub between host and switch",
    ],
    mitre: [
      ["T1200", "Hardware Additions"],
      ["T1557", "Adversary-in-the-Middle"],
      ["T1040", "Network Sniffing"],
      ["T1499", "Endpoint Denial of Service"],
    ],
    compliance: [
      ["PCI DSS", "1.3 — Network isolation"],
      ["ISO 27001", "A.13.1 — Network controls"],
      ["SOC 2", "CC6.6 — Logical & physical access"],
      ["CIS", "Control 12 — Network monitoring"],
    ],
    zt: "Segmentation is a ZT cornerstone. 802.1X = identity verified before network access.",
    ztOn: true,
  },

  {
    id: 5,
    short: "Internal FW",
    color: "#70b828",
    tc: "#051200",
    badge: "NET L3",
    icon: "🛡",
    sub: "Internal Firewall — East-West",
    coverage: 45,
    maturity: {
      typical: 1,
      levels: [
        [
          "Initial",
          "No east-west controls. Full trust between internal segments.",
        ],
        ["Managed", "Basic ACLs between VLAN segments. Limited L7 inspection."],
        ["Defined", "Stateful inspection east-west + app-aware policies."],
        [
          "Quantified",
          "Service mesh (Istio) + mTLS between all microservices + policy-as-code.",
        ],
        [
          "Optimizing",
          "Zero-trust network + continuous re-auth + AI-based traffic classification.",
        ],
      ],
    },
    desc: "Controls East-West traffic between internal segments. Stops lateral movement. Often neglected — this is where breaches spread silently.",
    items: [
      "Stateful inspection",
      "East-West ACL rules",
      "App-aware L7 firewall",
      "Service mesh: Istio / Linkerd",
      "Palo Alto / Fortinet / Cisco FTD",
    ],
    enc: [
      "mTLS between microservices",
      "TLS 1.3 management plane",
      "Encrypted GENEVE / VXLAN overlay",
    ],
    tools: [
      "Palo Alto PA-Series",
      "Fortinet FortiGate",
      "Cisco FTD",
      "Istio service mesh",
    ],
    attacks: [
      "SMB lateral movement (EternalBlue, Mimikatz)",
      "RDP pivoting between segments",
      "WMI / PSExec remote execution",
      "Internal port scanning & discovery",
    ],
    mitre: [
      ["T1021", "Remote Services"],
      ["T1563", "Remote Service Session Hijacking"],
      ["T1570", "Lateral Tool Transfer"],
      ["T1046", "Network Service Discovery"],
    ],
    compliance: [
      ["PCI DSS", "1.2 — Firewall between CDE zones"],
      ["ISO 27001", "A.13.1 — Network segregation"],
      ["SOC 2", "CC6.6 — Logical access"],
      ["NIST CSF", "PR.AC-5 — Network integrity"],
    ],
    zt: "ZT enforcement point: default-deny, explicit-allow. Continuous re-verification.",
    ztOn: true,
  },

  {
    id: 6,
    short: "IDS/IPS",
    color: "#20c080",
    tc: "#001810",
    badge: "DETECT",
    icon: "👁",
    sub: "Intrusion Detection & Prevention",
    coverage: 62,
    maturity: {
      typical: 2,
      levels: [
        ["Initial", "No IDS/IPS. Attacks are invisible."],
        [
          "Managed",
          "Signature-based IDS deployed on key segments. Manual alert review.",
        ],
        [
          "Defined",
          "Inline IPS + anomaly detection + automated SIEM forwarding.",
        ],
        [
          "Quantified",
          "ML-enhanced detection + tuned rules + SOAR auto-response.",
        ],
        [
          "Optimizing",
          "AI-driven zero-day detection + encrypted traffic analysis + behavioral IPS.",
        ],
      ],
    },
    desc: "IDS alerts; IPS blocks inline. Combines signature matching, anomaly detection, and deep packet inspection in real time.",
    items: [
      "Snort / Suricata / Zeek (Bro)",
      "Signature + anomaly + ML detection",
      "Deep Packet Inspection (DPI)",
      "Inline IPS / out-of-band IDS",
      "SIEM + SOAR integration",
    ],
    enc: [
      "TLS Inspection — controlled MITM",
      "Encrypted sensor → SIEM: TLS 1.3",
      "DPI on decrypted traffic streams",
    ],
    tools: ["Suricata", "Snort", "Zeek (Bro)", "Cisco Firepower", "Darktrace"],
    attacks: [
      "Encrypted C2 over HTTPS to evade DPI",
      "Low-and-slow attack to avoid thresholds",
      "Protocol obfuscation (allowed ports)",
      "IDS evasion via packet fragmentation",
    ],
    mitre: [
      ["T1562", "Impair Defenses"],
      ["T1070", "Indicator Removal"],
      ["T1071", "Application Layer Protocol"],
      ["T1001", "Data Obfuscation"],
    ],
    compliance: [
      ["PCI DSS", "11.4 — IDS/IPS deployment"],
      ["ISO 27001", "A.12.4 — Event logging"],
      ["SOC 2", "CC7.2 — Anomaly detection"],
      ["CIS", "Control 13 — Network monitoring"],
    ],
    zt: "Catches anomalies among authenticated sessions. Complements ZT, does not replace it.",
    ztOn: false,
  },

  {
    id: 7,
    short: "NTA",
    color: "#18a8a0",
    tc: "#001514",
    badge: "VISIBILITY",
    icon: "📡",
    sub: "Network Traffic Analysis",
    coverage: 30,
    maturity: {
      typical: 1,
      levels: [
        [
          "Initial",
          "No flow analysis. Lateral movement and exfil invisible after perimeter breach.",
        ],
        ["Managed", "NetFlow collection. Manual analysis only."],
        ["Defined", "Automated behavioural baselining + ML anomaly detection."],
        [
          "Quantified",
          "Encrypted traffic analysis (ETA) + UEBA integration + threat scoring.",
        ],
        [
          "Optimizing",
          "AI-powered detection + real-time response + full packet capture on demand.",
        ],
      ],
    },
    desc: "Passively analyses all flows for behavioural anomalies. Fills the blind spot between IDS signatures and WAF rules.",
    items: [
      "NetFlow / IPFIX / sFlow collection",
      "Behavioural baselining (ML)",
      "Encrypted traffic analysis (ETA)",
      "Lateral movement & beaconing detection",
      "C2 communication detection",
    ],
    enc: [
      "Encrypted flow export (TLS)",
      "ETA — TLS metadata only, no decryption",
      "Sensor-to-collector TLS 1.3",
    ],
    tools: [
      "Darktrace",
      "Vectra AI",
      "ExtraHop Reveal(x)",
      "Cisco Stealthwatch",
    ],
    attacks: [
      "DNS tunneling for C2 / exfil",
      "HTTPS beaconing with jitter",
      "Data exfil via authorised cloud uploads",
      "Slow exfil over weeks to avoid volume alerts",
    ],
    mitre: [
      ["T1071.004", "DNS Protocol"],
      ["T1071.001", "Web Protocols"],
      ["T1090", "Proxy"],
      ["T1041", "Exfil Over C2 Channel"],
    ],
    compliance: [
      ["PCI DSS", "10.6 — Log review"],
      ["ISO 27001", "A.12.4 — Monitoring"],
      ["SOC 2", "CC7.2 — Anomaly detection"],
      ["NIST CSF", "DE.CM-1 — Continuous monitoring"],
    ],
    zt: "NTA provides the continuous visibility ZT demands.",
    ztOn: false,
  },

  {
    id: 8,
    short: "WAF",
    color: "#10a8e0",
    tc: "#001520",
    badge: "APP L7",
    icon: "🌐",
    sub: "Web Application Firewall",
    coverage: 72,
    maturity: {
      typical: 3,
      levels: [
        ["Initial", "No WAF. Web apps directly exposed to internet."],
        ["Managed", "WAF in detection mode. Limited rule tuning."],
        ["Defined", "WAF in blocking mode + custom rules + bot management."],
        [
          "Quantified",
          "API-aware WAF + rate limiting + virtual patching + DDoS mitigation.",
        ],
        [
          "Optimizing",
          "AI-based attack detection + mTLS APIs + full OWASP ASVS compliance.",
        ],
      ],
    },
    desc: "Filters HTTP / HTTPS before it reaches applications. Blocks OWASP Top 10, bots, L7 DDoS, and API abuse at the edge.",
    items: [
      "OWASP Top 10 (SQLi / XSS / SSRF / RCE)",
      "Bot management & scraping protection",
      "Rate limiting / API throttling",
      "Cloudflare / AWS WAF / Akamai / F5",
      "Virtual patching",
    ],
    enc: [
      "TLS 1.3 termination at WAF edge",
      "Certificate pinning enforcement",
      "HSTS + HPKP headers",
      "mTLS for API client certificates",
    ],
    tools: ["Cloudflare WAF", "AWS WAF", "Akamai Kona", "F5 Advanced WAF"],
    attacks: [
      "SQL Injection via web app",
      "XSS to hijack user sessions",
      "SSRF to reach internal services",
      "API authentication bypass / BOLA / BFLA",
    ],
    mitre: [
      ["T1190", "Exploit Public-Facing Application"],
      ["T1059.007", "JavaScript Execution"],
      ["T1203", "Exploitation for Client Execution"],
    ],
    compliance: [
      ["PCI DSS", "6.6 — Web app firewall required"],
      ["ISO 27001", "A.14.2 — Secure development"],
      ["SOC 2", "CC6.8 — Change management"],
      ["OWASP", "ASVS — App Security Verification Standard"],
    ],
    zt: "API-level ZT: JWT / OAuth validation + per-request authorisation at the edge.",
    ztOn: true,
  },

  {
    id: 9,
    short: "DMZ",
    color: "#3050f0",
    tc: "#fff",
    badge: "ZONE",
    icon: "🏛",
    sub: "Demilitarized Zone",
    coverage: 82,
    maturity: {
      typical: 3,
      levels: [
        ["Initial", "No DMZ. Internal services directly internet-exposed."],
        ["Managed", "Basic DMZ with reverse proxy. Minimal monitoring."],
        ["Defined", "DMZ + WAF + honeypots + bastion host with MFA."],
        [
          "Quantified",
          "Full DMZ segmentation + TLS everywhere + DoH/DoT + deception tech.",
        ],
        [
          "Optimizing",
          "Identity-aware proxy (BeyondCorp) + zero-trust DMZ + continuous posture assessment.",
        ],
      ],
    },
    desc: "Isolated buffer between internet and internal network. Compromising DMZ assets does not grant access to internal segments.",
    items: [
      "Reverse proxy / Nginx / HAProxy",
      "API Gateway (Kong / Envoy)",
      "Mail transfer agents (MTA)",
      "Bastion host / Jump server",
      "Honeypots & deception assets",
    ],
    enc: [
      "TLS everywhere — HTTPS-only zone",
      "mTLS: DMZ → Internal",
      "Encrypted DNS: DoH / DoT",
      "Certificate-based mutual auth",
    ],
    tools: [
      "Nginx",
      "HAProxy",
      "Kong API Gateway",
      "Envoy Proxy",
      "Cloudflare Access",
    ],
    attacks: [
      "Reverse shell via web vulnerability",
      "Pivot from compromised proxy to internal",
      "SMTP relay abuse for phishing",
      "Weak bastion host authentication",
    ],
    mitre: [
      ["T1133", "External Remote Services"],
      ["T1189", "Drive-by Compromise"],
      ["T1566", "Phishing via SMTP relay"],
      ["T1021.004", "SSH exploitation"],
    ],
    compliance: [
      ["PCI DSS", "1.2–1.3 — DMZ for CDE"],
      ["ISO 27001", "A.13.1 — Network zoning"],
      ["SOC 2", "CC6.6 — Logical access"],
      ["NIST CSF", "PR.AC-5 — Network integrity"],
    ],
    zt: "Modern DMZ evolves into identity-aware proxy (BeyondCorp).",
    ztOn: true,
  },

  {
    id: 10,
    short: "CASB",
    color: "#6020c8",
    tc: "#fff",
    badge: "CLOUD",
    icon: "☁",
    sub: "Cloud Access Security Broker",
    coverage: 38,
    maturity: {
      typical: 1,
      levels: [
        [
          "Initial",
          "No cloud visibility. Shadow IT rampant. SaaS data uncontrolled.",
        ],
        ["Managed", "Basic SaaS visibility. Some conditional access policies."],
        ["Defined", "CASB deployed + shadow IT blocking + cloud DLP rules."],
        [
          "Quantified",
          "CASB + BYOK + risk scoring per cloud app + automated response.",
        ],
        [
          "Optimizing",
          "Real-time cloud posture + HYOK + ML-based data classification + zero-trust cloud access.",
        ],
      ],
    },
    desc: "Broker between users and SaaS / IaaS. Discovers Shadow IT, enforces cloud DLP, controls conditional access.",
    items: [
      "MS Defender for Cloud Apps",
      "Netskope / Zscaler / Skyhigh",
      "Shadow IT discovery & blocking",
      "Cloud DLP — sharing control",
      "Conditional access + MFA enforcement",
    ],
    enc: [
      "TLS proxy inspection (MITM)",
      "BYOK — Bring Your Own Key",
      "HYOK — Hold Your Own Key",
      "AES-256 cloud storage at rest",
    ],
    tools: [
      "Netskope",
      "Zscaler Internet Access",
      "MS Defender for Cloud Apps",
      "Skyhigh Security",
    ],
    attacks: [
      "OAuth token theft via phishing",
      "SaaS misconfiguration (public SharePoint / S3)",
      "OAuth consent phishing",
      "Shadow IT exfil via personal cloud",
    ],
    mitre: [
      ["T1537", "Transfer Data to Cloud Account"],
      ["T1567", "Exfil Over Web Service"],
      ["T1078.004", "Cloud Accounts"],
      ["T1110", "Brute Force on cloud auth"],
    ],
    compliance: [
      ["ISO 27001", "A.15 — Supplier relationships"],
      ["SOC 2", "CC9.2 — Vendor management"],
      ["GDPR", "Art. 28 — Processor obligations"],
      ["CSA CCM", "Cloud Controls Matrix"],
    ],
    zt: "CASB = ZT for the cloud. Continuous risk assessment of every cloud request.",
    ztOn: true,
  },

  {
    id: 11,
    short: "Perimeter FW",
    color: "#8010b0",
    tc: "#fff",
    badge: "PERIM",
    icon: "🔒",
    sub: "Perimeter Firewall — North-South",
    coverage: 96,
    maturity: {
      typical: 4,
      levels: [
        ["Initial", "Basic stateful FW. Any-any rules. No logging."],
        [
          "Managed",
          "Proper ingress/egress rules. GeoIP blocking. Basic logging.",
        ],
        ["Defined", "NGFW + IPS integration + VPN + full logging to SIEM."],
        [
          "Quantified",
          "NGFW + threat intel feeds + automated block lists + BGP/RPKI.",
        ],
        [
          "Optimizing",
          "SASE / ZTNA replacing VPN + cloud-native FW + AI threat intel + zero-touch policy.",
        ],
      ],
    },
    desc: "Outermost boundary. First internet contact. Controls all inbound and outbound traffic. Necessary but no longer sufficient alone.",
    items: [
      "NAT / PAT",
      "Ingress + Egress filtering",
      "GeoIP / ASN blocking",
      "Anti-spoofing (uRPF / BCP38)",
      "BGP / RPKI origin validation",
    ],
    enc: [
      "IPSec VPN (IKEv2 / ESP / AH)",
      "WireGuard",
      "SSL/TLS VPN (AnyConnect / GlobalProtect)",
      "DTLS for UDP tunnels",
    ],
    tools: [
      "Fortinet FortiGate",
      "Palo Alto PA-Series",
      "Cisco ASA / FTD",
      "pfSense / OPNsense",
    ],
    attacks: [
      "DDoS volumetric / amplification",
      "VPN zero-day exploitation",
      "Port scanning & fingerprinting",
      "Firewall misconfiguration (any-any)",
      "BGP hijacking",
    ],
    mitre: [
      ["T1190", "Exploit Public-Facing Application"],
      ["T1133", "External Remote Services"],
      ["T1498", "Network Denial of Service"],
      ["T1046", "Network Service Discovery"],
    ],
    compliance: [
      ["PCI DSS", "1.1–1.4 — Firewall standards"],
      ["ISO 27001", "A.13.1 — Network controls"],
      ["SOC 2", "CC6.6 — Logical access"],
      ["CIS", "Control 12 — Network boundary defense"],
    ],
    zt: "Perimeter-only model is dead. ZTNA replaces VPN. SASE = ZT + cloud + SD-WAN.",
    ztOn: false,
  },
];

// ── Attack Path scenarios ─────────────────────────────────────
// Each step: layerId, result ("blocked"|"slowed"|"bypassed"), how, time (ms)
const ATTACK_PATHS = [
  {
    id: "ransomware",
    label: "Ransomware",
    icon: "💀",
    color: "#ff7700",
    desc: "Phishing email → RDP brute-force → Mimikatz → lateral spread → encrypt everything. Average time to ransom: 21 days. Most stopped at EDR — if it's deployed.",
    cases: [
      {
        name: "WannaCry",
        year: 2017,
        damage: "$4–8B",
        org: "150 countries, NHS UK, Telefónica",
        what: "EternalBlue SMB exploit (NSA zero-day leaked by Shadow Brokers). No phishing needed — self-spreading worm. Encrypted 200,000+ machines in hours. NHS cancelled 19,000 appointments.",
        missed:
          "Perimeter FW (SMB port 445 open), Internal FW (no east-west segmentation), EDR (AV didn't detect EternalBlue), Patching (MS17-010 patch available 2 months earlier)",
      },
      {
        name: "NotPetya",
        year: 2017,
        damage: "$10B+",
        org: "Maersk, Merck, FedEx, Mondelez",
        what: "Disguised as ransomware but was a wiper. Spread via MeDoc accounting software update (supply chain) + EternalBlue. Maersk lost entire AD forest — rebuilt 45,000 PCs in 10 days.",
        missed:
          "Supply chain controls (no code signing verification), EDR (wiper disguised as legitimate update), Backup isolation (backups were on same network), PAM (domain admin credentials harvested)",
      },
      {
        name: "Colonial Pipeline",
        year: 2021,
        damage: "$4.4M ransom + $billions economic",
        org: "Colonial Pipeline (US fuel infrastructure)",
        what: "Single compromised VPN password (no MFA) → DarkSide ransomware → 5,500 mile fuel pipeline shut down for 6 days. East coast fuel shortage.",
        missed:
          "PAM/MFA (VPN account had no MFA), EDR (ransomware deployed before detection), Segmentation (IT/OT network not properly isolated)",
      },
    ],
    steps: [
      {
        id: 11,
        result: "slowed",
        time: 600,
        how: "Perimeter FW blocks RDP from internet — attacker switches to phishing email",
      },
      {
        id: 9,
        result: "bypassed",
        time: 500,
        how: "DMZ SMTP relay accepts the phishing email — passes through to user inbox",
      },
      {
        id: 8,
        result: "bypassed",
        time: 400,
        how: "WAF doesn't inspect email attachments — macro executes on click",
      },
      {
        id: 6,
        result: "slowed",
        time: 700,
        how: "IDS/IPS flags suspicious PowerShell — but alert gets buried in noise",
      },
      {
        id: 5,
        result: "blocked",
        time: 800,
        how: "Internal FW stops lateral movement EAST-WEST ✓",
      },
      {
        id: 4,
        result: "slowed",
        time: 500,
        how: "VLAN segmentation limits blast radius — but attacker pivots via shared service",
      },
      {
        id: 3,
        result: "blocked",
        time: 900,
        how: "EDR detects Mimikatz credential dump and isolates host ✓",
      },
      {
        id: 2,
        result: "blocked",
        time: 700,
        how: "PAM vault prevents access to privileged accounts — no golden ticket ✓",
      },
      {
        id: 1,
        result: "slowed",
        time: 600,
        how: "DLP catches bulk file access pattern — triggers alert",
      },
      {
        id: 0,
        result: "blocked",
        time: 800,
        how: "DATA encrypted at rest — exfiltrated files are unreadable ✓",
      },
    ],
  },

  {
    id: "apt",
    label: "Nation-State APT",
    icon: "🏴",
    color: "#ff3366",
    desc: "Zero-day exploit → custom implant → months of silent espionage → targeted data exfil. Dwell time: 197 days average. Highly evasive — lives off the land.",
    cases: [
      {
        name: "SolarWinds (SUNBURST)",
        year: 2020,
        damage: "Classified / enormous",
        org: "US Treasury, DoJ, DHS, Microsoft, 18,000 orgs",
        what: "APT29 (Cozy Bear) poisoned SolarWinds Orion build pipeline. Malicious DLL shipped in signed update to 18,000 customers. Backdoor dormant for 2 weeks then phoned home over legitimate cloud services. Undetected for 9 months.",
        missed:
          "Supply chain (build pipeline not monitored), EDR (signed binary bypassed AV), NTA (C2 used legitimate Cloudflare/Azure), CASB (OAuth tokens abused via legitimate cloud APIs), SIEM (no correlation rule for this TTPs)",
      },
      {
        name: "Operation Aurora",
        year: 2009,
        damage: "IP theft, classified",
        org: "Google, Adobe, Juniper, 30+ companies",
        what: "APT targeting Google source code and Gmail accounts of Chinese dissidents. Zero-day IE exploit delivered via spear phishing. Exfiltrated source code repositories. Caused Google to partly exit China.",
        missed:
          "EDR (zero-day payload, no signature), WAF (client-side attack, not server), Internal FW (pivot from user workstation to source code repos), DLP (source code exfil not detected for months)",
      },
      {
        name: "Hafnium / Exchange (ProxyLogon)",
        year: 2021,
        damage: "250,000+ servers",
        org: "US gov, defence contractors, NGOs worldwide",
        what: "Chinese APT exploited 4 zero-days in on-prem Exchange Server. No auth required. Installed web shells → stole email → planted backdoors. Exploited within hours of public disclosure.",
        missed:
          "Perimeter FW (port 443 legitimately open), WAF (zero-day, no virtual patch), EDR (web shell written by IIS worker — legitimate process), Patching (orgs unpatched for days after disclosure)",
      },
    ],
    steps: [
      {
        id: 11,
        result: "bypassed",
        time: 500,
        how: "Zero-day in VPN software — perimeter firewall has no signature for it yet",
      },
      {
        id: 10,
        result: "slowed",
        time: 700,
        how: "CASB detects unusual OAuth scope request — but APT uses legitimate cloud service",
      },
      {
        id: 9,
        result: "bypassed",
        time: 500,
        how: "Reverse shell over HTTPS — DMZ proxy passes it as normal web traffic",
      },
      {
        id: 7,
        result: "slowed",
        time: 600,
        how: "NTA detects subtle beaconing pattern — but alert requires manual investigation",
      },
      {
        id: 6,
        result: "bypassed",
        time: 400,
        how: "APT uses encrypted C2 over port 443 — IDS/IPS can't inspect without TLS decryption",
      },
      {
        id: 5,
        result: "slowed",
        time: 700,
        how: "Internal FW limits segment reach — attacker uses legitimate admin tools (LOLBins)",
      },
      {
        id: 4,
        result: "bypassed",
        time: 500,
        how: "APT clones MAC address of trusted device — bypasses 802.1X NAC",
      },
      {
        id: 3,
        result: "slowed",
        time: 800,
        how: "EDR flags suspicious memory injection — but APT uses fileless technique, partial detection",
      },
      {
        id: 2,
        result: "blocked",
        time: 900,
        how: "PAM JIT access denied — APT cannot escalate to domain admin ✓",
      },
      {
        id: 1,
        result: "blocked",
        time: 700,
        how: "DLP blocks bulk exfil of classified files — triggers SIEM alert ✓",
      },
    ],
  },

  {
    id: "insider",
    label: "Insider Threat",
    icon: "🕵",
    color: "#aa44ff",
    desc: "Trusted employee abuses legitimate access. No malware. No exploit. Just a disgruntled sysadmin with admin rights and a USB drive.",
    cases: [
      {
        name: "Edward Snowden / NSA",
        year: 2013,
        damage: "Classified programs exposed",
        org: "NSA / US Intelligence Community",
        what: "NSA contractor used legitimate sysadmin access to copy 1.5 million+ classified documents to USB drives over months. No DLP on classified systems. Colleagues lent him login credentials when asked.",
        missed:
          "PAM (excessive access for a contractor), DLP (USB exfil on classified systems), UEBA (abnormal download volume), Audit (logs existed but nobody reviewed them in real time)",
      },
      {
        name: "Tesla IP Theft",
        year: 2018,
        damage: "$167M+ lawsuit",
        org: "Tesla",
        what: "Engineer stole Autopilot source code before leaving for competitor. Exfiltrated to personal Dropbox and transferred to private server. Claimed he was just backing up his own work.",
        missed:
          "DLP (cloud sync to personal Dropbox), UEBA (bulk download before resignation date), CASB (personal cloud upload not blocked), PAM (no least-privilege on source code repos)",
      },
      {
        name: "Capital One Breach",
        year: 2019,
        damage: "$80M fine + $190M settlement",
        org: "Capital One",
        what: "Former AWS employee exploited SSRF vulnerability in Capital One's WAF to access AWS metadata service → IAM credentials → S3 bucket with 106M customer records. Insider knowledge of cloud architecture.",
        missed:
          "WAF (SSRF not blocked), PAM (IAM over-permissioned), DLP (bulk S3 download not alerted), CASB (unusual cloud API patterns), NTA (abnormal data transfer volume)",
      },
    ],
    steps: [
      {
        id: 11,
        result: "bypassed",
        time: 300,
        how: "Already inside the network — perimeter is irrelevant",
      },
      {
        id: 9,
        result: "bypassed",
        time: 200,
        how: "Insider uses legitimate credentials — DMZ sees normal traffic",
      },
      {
        id: 5,
        result: "bypassed",
        time: 300,
        how: "Insider has legitimate access to multiple segments — east-west rules allow it",
      },
      {
        id: 4,
        result: "bypassed",
        time: 200,
        how: "Insider's device is enrolled — 802.1X passes it through",
      },
      {
        id: 3,
        result: "slowed",
        time: 600,
        how: "EDR flags unusual process activity at 2AM — alert generated but not triaged in time",
      },
      {
        id: 2,
        result: "slowed",
        time: 800,
        how: "PAM records the session — but exfil happens before anyone reviews it",
      },
      {
        id: 1,
        result: "blocked",
        time: 900,
        how: "DLP catches bulk download to USB drive and blocks it ✓",
      },
      {
        id: 0,
        result: "blocked",
        time: 700,
        how: "DATA encryption — even if USB succeeds, files need decryption key ✓",
      },
    ],
  },

  {
    id: "web",
    label: "Web App Attack",
    icon: "🌐",
    color: "#10a8e0",
    desc: "SQL injection → web shell → pivot to internal DB → exfil. Classic OWASP Top 10 attack chain. Stopped at the application boundary if WAF is properly configured.",
    cases: [
      {
        name: "Equifax Breach",
        year: 2017,
        damage: "$575M–$700M settlement",
        org: "Equifax (147M people's data)",
        what: "Apache Struts CVE-2017-5638 RCE vulnerability in public-facing web app. Unpatched for 2 months after public disclosure. Attackers exfiltrated 147M SSNs, DOBs, addresses for 76 days undetected.",
        missed:
          "WAF (no virtual patch for Struts CVE), Patching (2 months late), NTA (76 days of exfil undetected), DLP (bulk PII exfil not alerted), SIEM (alerts existed but went uninvestigated due to expired TLS inspection cert)",
      },
      {
        name: "Target Breach",
        year: 2013,
        damage: "$202M total",
        org: "Target (40M card numbers)",
        what: "HVAC vendor credentials stolen via phishing → VPN access → pivot to POS network (not segmented from vendor access) → RAM scraper malware on POS terminals → 40M credit card numbers stolen.",
        missed:
          "Internal FW (vendor network not segmented from POS network), EDR (RAM scraper not detected on POS), VLAN (POS and vendor management on same network), PAM (vendor had overly broad access)",
      },
      {
        name: "Log4Shell (Log4j)",
        year: 2021,
        damage: "Billions (ongoing)",
        org: "Apple, Amazon, Cloudflare, governments worldwide",
        what: "Single line of text in log input triggered remote code execution in Log4j library used in millions of apps. JNDI injection via any logged user-controlled input (username, User-Agent, etc.).",
        missed:
          "WAF (zero-day, rules took hours to deploy), IDS/IPS (no signature initially), Inventory (most orgs didn't know they were using Log4j), EDR (RCE via Java classloader)",
      },
    ],
    steps: [
      {
        id: 11,
        result: "slowed",
        time: 400,
        how: "Perimeter FW allows port 443 (HTTPS) — web attacks pass through by design",
      },
      {
        id: 9,
        result: "slowed",
        time: 500,
        how: "DMZ reverse proxy forwards request — doesn't inspect application payload",
      },
      {
        id: 8,
        result: "blocked",
        time: 900,
        how: "WAF detects SQL injection pattern and blocks request ✓",
      },
      {
        id: 7,
        result: "slowed",
        time: 600,
        how: "NTA detects unusual DB query volume — alert generated",
      },
      {
        id: 6,
        result: "blocked",
        time: 800,
        how: "IPS inline blocks web shell execution attempt ✓",
      },
      {
        id: 5,
        result: "blocked",
        time: 700,
        how: "Internal FW blocks pivot from web server to DB server — different segments ✓",
      },
      {
        id: 0,
        result: "blocked",
        time: 800,
        how: "DATA: DB encryption prevents reading raw files even if accessed ✓",
      },
    ],
  },

  {
    id: "supply",
    label: "Supply Chain",
    icon: "📦",
    color: "#00aaff",
    desc: "Trojanised software update installs malware on thousands of machines simultaneously. Your own IT team deploys it. Traditional defences are blind to it — trust is the attack vector.",
    cases: [
      {
        name: "3CX Desktop App",
        year: 2023,
        damage: "Classified / financial sector targeted",
        org: "3CX (600,000 companies, 12M daily users)",
        what: "North Korea (Lazarus) compromised 3CX build environment. Trojanised version of 3CX VoIP app shipped to millions. Notably: a supply chain attack (Trading Technologies) was used to compromise 3CX — a supply chain within a supply chain.",
        missed:
          "EDR (signed installer — bypassed most AV for days), CASB (legitimate vendor update traffic), NTA (C2 over HTTPS looked like normal 3CX traffic), Supply chain controls (no integrity verification of build artifacts)",
      },
      {
        name: "Kaseya VSA",
        year: 2021,
        damage: "$70M ransom demand",
        org: "1,500 businesses via 60 MSPs",
        what: "REvil exploited zero-day in Kaseya VSA (IT management software used by MSPs). Deployed ransomware to all managed endpoints in minutes. MSPs trusted VSA completely — no way to distinguish malicious from legitimate commands.",
        missed:
          "Perimeter FW (VSA agent explicitly allowed through), EDR (commands came from trusted management agent), PAM (VSA had system-level access by design), Segmentation (MSP management plane mixed with client networks)",
      },
      {
        name: "XZ Utils Backdoor",
        year: 2024,
        damage: "Near-miss — caught before widespread deployment",
        org: "Linux distributions worldwide (near miss)",
        what: "Attacker spent 2+ years as open-source contributor gaining trust before inserting a sophisticated backdoor in XZ Utils (compression library). Would have enabled SSH auth bypass on millions of Linux servers. Caught by Microsoft engineer noticing 500ms login delay.",
        missed:
          "Supply chain (no multi-party code review), EDR (legitimate library), SIEM (performance anomaly only visible via careful monitoring), Perimeter FW (SSH is legitimate port 22)",
      },
    ],
    steps: [
      {
        id: 11,
        result: "bypassed",
        time: 400,
        how: "Update server is whitelisted — perimeter firewall explicitly allows it",
      },
      {
        id: 10,
        result: "slowed",
        time: 600,
        how: "CASB flags unusual new cloud endpoint in update traffic — but update is 'signed'",
      },
      {
        id: 3,
        result: "slowed",
        time: 800,
        how: "EDR flags unknown process — but it's signed with vendor cert, partial bypass",
      },
      {
        id: 6,
        result: "slowed",
        time: 700,
        how: "IDS detects unusual outbound connection pattern after update",
      },
      {
        id: 5,
        result: "blocked",
        time: 800,
        how: "Internal FW blocks C2 callback — attacker can't receive commands ✓",
      },
      {
        id: 2,
        result: "blocked",
        time: 900,
        how: "PAM prevents privilege escalation — malware runs as user, can't reach sensitive systems ✓",
      },
      {
        id: 1,
        result: "blocked",
        time: 700,
        how: "DLP blocks data exfil attempt — SIEM alert fires ✓",
      },
    ],
  },

  {
    id: "ddos",
    label: "DDoS Attack",
    icon: "💥",
    color: "#f43f5e",
    desc: "Botnet floods public IP with millions of requests → legitimate traffic drowns. Not about stealing data — about killing availability. Outcome depends on WAF + cloud scrubbing.",
    cases: [
      {
        name: "GitHub DDoS",
        year: 2018,
        damage: "28 min downtime",
        org: "GitHub",
        what: "1.35 Tbps memcached amplification — largest DDoS at the time. Attacker sent 8 bytes, got 1.35 Tbps back via misconfigured memcached servers. Mitigated in 8 minutes via Akamai Prolexic scrubbing.",
        missed:
          "Perimeter FW (volumetric overwhelmed upstream capacity), Memcached (UDP port 11211 open to internet — amplification vector)",
      },
      {
        name: "Dyn DNS / Mirai",
        year: 2016,
        damage: "$110M+ economic impact",
        org: "Twitter, Netflix, Reddit, Spotify",
        what: "Mirai botnet (IoT cameras, DVRs with default passwords) launched 1.2 Tbps against Dyn DNS. Took down major internet services. IoT devices used as attack source.",
        missed:
          "Perimeter FW (upstream saturation), IoT security (no NAC on IoT devices — default credentials), Single DNS provider (no redundancy)",
      },
      {
        name: "Belgian Parliament DDoS",
        year: 2021,
        damage: "Parliament offline mid-session",
        org: "Belgian government + 200 orgs via Belnet",
        what: "DDoS on Belnet (Belgian national research network) during parliamentary COVID hearing. Deliberate timing — disrupted democratic process.",
        missed:
          "Perimeter FW (upstream capacity), No cloud scrubbing (Belnet lacked CDN DDoS protection), Redundancy (no failover DNS / CDN)",
      },
    ],
    steps: [
      {
        id: 11,
        result: "slowed",
        time: 700,
        how: "Perimeter FW applies GeoIP + rate limiting — drops some botnet traffic but overwhelmed by sheer volume",
      },
      {
        id: 9,
        result: "slowed",
        time: 600,
        how: "DMZ reverse proxy queues requests — drops legitimate users as connection table fills",
      },
      {
        id: 8,
        result: "blocked",
        time: 900,
        how: "WAF detects HTTP flood, applies JS challenge + rate limiting — L7 DDoS mitigated ✓",
      },
    ],
  },

  {
    id: "dns",
    label: "DNS Tunneling",
    icon: "📡",
    color: "#10b981",
    desc: "Malware encodes stolen data into DNS subdomain queries (abc123.exfil.attacker.com). DNS is almost always allowed outbound. Without NTA, this exfil is invisible for months.",
    cases: [
      {
        name: "Mustang Panda / PlugX",
        year: "2020–ongoing",
        damage: "Classified IP theft",
        org: "European governments, NGOs, telecoms",
        what: "Chinese APT used DNS tunneling for C2 inside PlugX malware. Queries went to attacker-controlled authoritative DNS. Bytes encoded in subdomain labels — looked like legitimate DNS.",
        missed:
          "NTA (no behavioral analysis of DNS query length/frequency), IDS/IPS (no DNS tunnel signatures), Perimeter FW (port 53 outbound open — standard)",
      },
      {
        name: "OilRig (APT34) DNSpionage",
        year: 2019,
        damage: "Government credentials stolen",
        org: "Middle East governments, energy sector",
        what: "Iranian APT encoded stolen credentials into DNS TXT record responses. Tools leaked by Lab Dookhtegan revealed full tooling.",
        missed:
          "NTA (DNS anomaly detection absent), DLP (DNS-encoded data invisible), SIEM (DNS logs not correlated for subdomain length)",
      },
      {
        name: "Heyoka Double-Tunnel",
        year: 2021,
        damage: "8+ months undetected",
        org: "Southeast Asian governments",
        what: "Sophisticated DNS tunnel with asymmetric speeds to evade volume-based detection. Split across hundreds of DNS resolvers.",
        missed:
          "NTA (volume threshold too simple — needed ML baseline), IDS/IPS (polymorphic encoding), SIEM (DNS logs not fully ingested)",
      },
    ],
    steps: [
      {
        id: 11,
        result: "slowed",
        time: 500,
        how: "Perimeter FW allows port 53 outbound (required for DNS) — blocks known bad domains via threat intel",
      },
      {
        id: 3,
        result: "slowed",
        time: 700,
        how: "EDR detects unusual DNS query rate from process — flags but doesn't block (looks legitimate)",
      },
      {
        id: 7,
        result: "blocked",
        time: 900,
        how: "NTA detects anomalous subdomain length + query frequency — DNS tunnel identified ✓",
      },
      {
        id: 6,
        result: "slowed",
        time: 600,
        how: "IDS signature matches known DNScat2 — partial detection (custom tools evade)",
      },
      {
        id: 1,
        result: "slowed",
        time: 700,
        how: "DLP cannot inspect DNS payload — data encoded in protocol fields, not file transfer",
      },
      {
        id: 0,
        result: "blocked",
        time: 800,
        how: "DATA encrypted at rest — even intercepted bytes are unreadable ✓",
      },
    ],
  },

  {
    id: "mitm",
    label: "Man-in-the-Middle",
    icon: "🕸",
    color: "#8b5cf6",
    desc: "ARP spoofing or Evil Twin Wi-Fi puts attacker between victim and network. Without 802.1X + mTLS, attacker reads everything. With them — intercepted traffic is encrypted noise.",
    cases: [
      {
        name: "Dark Hotel APT / Evil Twin",
        year: "2014–ongoing",
        damage: "Corporate espionage (executives)",
        org: "Business travellers at luxury hotels in Asia",
        what: "APT set up rogue Wi-Fi APs matching hotel SSIDs. Executives auto-connected. HTTP traffic fully readable, HTTPS subject to SSL stripping without HSTS. Targeted C-suite for years.",
        missed:
          "VLAN/802.1X (WPA3-Enterprise prevents rogue AP), EDR (no network anomaly on endpoint), Encryption (sites without HSTS vulnerable to SSL strip)",
      },
      {
        name: "BGP Hijack — MyEtherWallet",
        year: 2018,
        damage: "$152,000 ETH stolen",
        org: "MyEtherWallet users worldwide",
        what: "Attackers hijacked BGP routes for Amazon Route53 DNS for 2 hours. Redirected wallet users to phishing site. Users ignored certificate warning — $152K stolen.",
        missed:
          "Perimeter FW (BGP/RPKI not implemented), WAF (certificate warning bypassed by users), CASB (no DNS integrity monitoring)",
      },
      {
        name: "Starbucks Wi-Fi Crypto Miner",
        year: 2017,
        damage: "CPU hijacking, credential risk",
        org: "Starbucks Buenos Aires customers",
        what: "Attacker on public Wi-Fi injected JavaScript into HTTP pages to mine Monero in victims' browsers. No HTTPS = full traffic manipulation.",
        missed:
          "Encryption (plain HTTP), VLAN (no client isolation on guest Wi-Fi), EDR (browser JS injection undetected)",
      },
    ],
    steps: [
      {
        id: 4,
        result: "blocked",
        time: 900,
        how: "VLAN/802.1X rejects rogue device — 802.1X requires cert auth before network assignment ✓",
      },
      {
        id: 5,
        result: "blocked",
        time: 800,
        how: "Internal FW east-west rules prevent ARP spoofing pivot between segments ✓",
      },
      {
        id: 6,
        result: "slowed",
        time: 600,
        how: "IDS detects ARP spoofing (duplicate ARP replies) — alerts generated",
      },
      {
        id: 3,
        result: "slowed",
        time: 700,
        how: "EDR flags suspicious gateway MAC change — unusual network activity detected",
      },
      {
        id: 0,
        result: "blocked",
        time: 900,
        how: "DATA: mTLS + HTTPS — intercepted traffic is encrypted noise, unreadable without private key ✓",
      },
    ],
  },

  {
    id: "bgp",
    label: "BGP Hijacking",
    icon: "🛣",
    color: "#6366f1",
    desc: "Attacker announces more-specific BGP routes for victim's IP space — internet traffic is rerouted through attacker's AS. No exploit needed, just a BGP session. Most orgs never detect it.",
    cases: [
      {
        name: "Pakistan Telecom → YouTube",
        year: 2008,
        damage: "YouTube offline worldwide ~2 hours",
        org: "YouTube / Google",
        what: "Pakistan Telecom accidentally (then deliberately) announced YouTube's IP prefixes via BGP while implementing a government block. Routes propagated globally. YouTube traffic went to Pakistan Telecom → null-routed. Took 2 hours to fix.",
        missed:
          "Perimeter FW (BGP routing is upstream — FW has no control), BGP/RPKI (no route origin validation), ISP filtering (Pakistan Telecom's upstream provider should have filtered the announcement)",
      },
      {
        name: "AWS Route53 BGP Hijack / MyEtherWallet",
        year: 2018,
        damage: "$152,000 ETH stolen",
        org: "MyEtherWallet users",
        what: "Attackers hijacked BGP routes for AWS Route53 DNS servers for 2 hours. Redirected cryptocurrency wallet users to phishing site with valid-looking certificate. Users bypassed browser warning.",
        missed:
          "Perimeter FW (BGP upstream — outside org control), RPKI (AWS Route53 routes not RPKI-signed at the time), WAF (users bypassed certificate warning themselves)",
      },
      {
        name: "Rostelecom BGP Hijack",
        year: 2020,
        damage: "Traffic interception risk",
        org: "Google, Amazon, Facebook, Cloudflare (174 prefixes)",
        what: "Russian state ISP Rostelecom hijacked BGP routes for 174 IP prefixes belonging to major cloud providers. Lasted ~1 hour. Suspected traffic interception / intelligence collection.",
        missed:
          "RPKI (only partially deployed by affected providers at the time), NTA (traffic anomaly not detected internally), No mutual BGP filtering between major carriers",
      },
    ],
    steps: [
      {
        id: 11,
        result: "slowed",
        time: 800,
        how: "Perimeter FW applies RPKI origin validation — rejects routes without valid ROA (if configured)",
      },
      {
        id: 9,
        result: "bypassed",
        time: 500,
        how: "DMZ sees traffic arriving from unexpected upstream — BGP rerouting is transparent to application layer",
      },
      {
        id: 8,
        result: "slowed",
        time: 700,
        how: "WAF TLS certificate mismatch detected — but user must act on browser warning",
      },
      {
        id: 7,
        result: "blocked",
        time: 800,
        how: "NTA detects asymmetric traffic path + latency anomaly — BGP hijack fingerprint identified ✓",
      },
      {
        id: 0,
        result: "blocked",
        time: 900,
        how: "DATA: TLS + certificate pinning — intercepted HTTPS traffic undecryptable without private key ✓",
      },
    ],
  },

  {
    id: "physical",
    label: "Physical Breach",
    icon: "🚪",
    color: "#d97706",
    desc: "Attacker walks into an office, plugs into an empty network port (or posing as contractor/cleaner), and gets direct LAN access. Without NAC, they're on the internal network instantly.",
    cases: [
      {
        name: "Plug-in Raspberry Pi Attack",
        year: "2022 (documented TTP)",
        damage: "Internal network access",
        org: "Multiple enterprises (red team TTP)",
        what: "Red teams and real attackers plug a Raspberry Pi or laptop into an open ethernet port in a conference room, printer alcove, or reception area. Without 802.1X, the device gets a DHCP lease and full VLAN access. Used in penetration tests globally — almost always works without NAC.",
        missed:
          "VLAN/802.1X (no NAC — any device gets IP), Internal FW (once on LAN, lateral movement possible), Physical Security (no tailgating prevention, unlocked port)",
      },
      {
        name: "Target HVAC Vendor Breach",
        year: 2013,
        damage: "40M card numbers, $202M total",
        org: "Target",
        what: "HVAC vendor credentials used to access Target's vendor portal → pivot to POS network. Physical contractor access to building gave network proximity. POS terminals not segregated from vendor management network.",
        missed:
          "VLAN/802.1X (vendor and POS on same network segment), Internal FW (no east-west between vendor and POS), PAM (vendor had excessive network access), Physical (contractor network not isolated)",
      },
      {
        name: "Lapsus$ Social Engineering",
        year: 2022,
        damage: "Source code, internal tools",
        org: "Microsoft, Nvidia, Samsung, Okta, Cisco",
        what: "Lapsus$ called help desks impersonating employees, physically visited offices, bribed insiders for credentials and VPN access. Used physical presence + social engineering to bypass technical controls.",
        missed:
          "PAM (MFA bypass via social engineering), EDR (credentials used legitimately), VLAN/802.1X (insider already enrolled), Physical (tailgating, visitor management failure)",
      },
    ],
    steps: [
      {
        id: 4,
        result: "blocked",
        time: 900,
        how: "VLAN/802.1X — 802.1X NAC requires device certificate auth before any IP assigned. Unknown device → quarantine VLAN ✓",
      },
      {
        id: 5,
        result: "blocked",
        time: 800,
        how: "Internal FW east-west ACL — even if device gets IP, cannot reach servers across segments ✓",
      },
      {
        id: 7,
        result: "slowed",
        time: 600,
        how: "NTA detects new unrecognised device + unusual traffic pattern — fingerprinting alert generated",
      },
      {
        id: 6,
        result: "slowed",
        time: 700,
        how: "IDS detects port scan from new internal IP — lateral movement attempt flagged",
      },
      {
        id: 3,
        result: "slowed",
        time: 600,
        how: "EDR on corporate endpoints detects connection attempt from rogue device — network anomaly alert",
      },
      {
        id: 2,
        result: "blocked",
        time: 900,
        how: "PAM JIT access — even with LAN access, privileged systems require authenticated just-in-time session ✓",
      },
    ],
  },
];

const THREAT_ACTORS = [
  {
    id: "apt",
    label: "Nation-State APT",
    icon: "🏴",
    color: "#ff3366",
    sub: "Advanced Persistent Threat",
    desc: "State-sponsored actors with vast resources. Primary goals: espionage, IP theft, critical infrastructure disruption. Average dwell time before detection: 197 days.",
    tactics: [
      "Zero-day exploits (custom or purchased)",
      "Supply chain compromise (SolarWinds-style)",
      "Spear phishing with weaponised documents",
      "Long-term persistence via custom implants",
    ],
    targets: [11, 10, 9, 2],
    examples: ["APT29 (Cozy Bear)", "APT41", "Lazarus Group", "Sandworm"],
  },
  {
    id: "ransomware",
    label: "Ransomware Groups",
    icon: "💀",
    color: "#ff7700",
    sub: "Financially motivated — RaaS",
    desc: "Ransomware-as-a-Service gangs. Breach → dwell → exfil → encrypt. Double extortion. Average dwell before encryption: 21 days.",
    tactics: [
      "Phishing / RDP brute-force → initial access",
      "Lateral movement via Mimikatz + PsExec",
      "Data exfiltration before encryption",
      "Disabling backups (VSS deletion)",
    ],
    targets: [3, 5, 4, 6],
    examples: ["LockBit 3.0", "ALPHV / BlackCat", "Cl0p", "Conti successors"],
  },
  {
    id: "insider",
    label: "Insider Threat",
    icon: "🕵",
    color: "#aa44ff",
    sub: "Malicious or negligent employee",
    desc: "Trusted insiders with legitimate access. Hardest to detect — they bypass perimeter controls entirely.",
    tactics: [
      "Exfiltrating data via personal cloud / USB",
      "Abusing privileged access for sabotage",
      "Sharing credentials with external parties",
      "Creating backdoor accounts before departure",
    ],
    targets: [0, 1, 2],
    examples: [
      "Disgruntled sysadmin",
      "Corporate espionage plant",
      "Negligent employee",
    ],
  },
  {
    id: "skids",
    label: "Opportunists",
    icon: "🎭",
    color: "#d4b800",
    sub: "Script kiddies & automated scanners",
    desc: "Low-skill actors using public exploit tools and scanners. Volume-based — most give up at a working perimeter.",
    tactics: [
      "Automated CVE scanning (Shodan / Censys)",
      "SQLi / XSS via automated tools",
      "Credential stuffing",
      "DDoS for hire",
    ],
    targets: [11, 8],
    examples: ["Mirai botnet operators", "Script kiddies with Metasploit"],
  },
  {
    id: "supply",
    label: "Supply Chain",
    icon: "📦",
    color: "#00aaff",
    sub: "Third-party & software supply chain",
    desc: "Compromise a trusted vendor or software update to reach the target indirectly. Target's own defences install the malware.",
    tactics: [
      "Trojanised software updates",
      "Compromised vendor with trusted access",
      "Malicious open-source package (typosquatting)",
      "Firmware / hardware implants",
    ],
    targets: [3, 10, 5],
    examples: [
      "SolarWinds (SUNBURST)",
      "3CX / Kaseya VSA",
      "XZ Utils backdoor",
    ],
  },
];

const SATS = [
  {
    id: "siem",
    label: "SIEM",
    icon: "📊",
    color: "#f59e0b",
    sub: "Security Information & Event Management",
    desc: "Aggregates logs from ALL layers. Without SIEM you are blind. Events → correlation → alert → investigation.",
    items: [
      "Splunk / MS Sentinel / IBM QRadar / Elastic",
      "Log aggregation from all layers",
      "Correlation rules + threat hunting",
      "UEBA behavioural analytics",
      "Compliance reporting",
    ],
    enc: [
      "TLS 1.3 log transport",
      "AES-256 log storage",
      "WORM immutable storage",
    ],
    tools: ["Splunk", "Microsoft Sentinel", "IBM QRadar", "Elastic SIEM"],
    attacks: [
      "SIEM log tampering / deletion",
      "Alert fatigue via flooding",
      "Agent uninstall to go dark",
    ],
    mitre: [
      ["T1562.002", "Disable Windows Event Logging"],
      ["T1070.001", "Clear Windows Event Logs"],
    ],
    compliance: [
      ["PCI DSS", "10.5 — Protect audit trails"],
      ["ISO 27001", "A.12.4 — Logging"],
      ["SOC 2", "CC7.2 — Anomaly detection"],
    ],
    zt: "Continuous monitoring is a mandatory ZT pillar.",
    ztOn: true,
  },
  {
    id: "soar",
    label: "SOAR",
    icon: "⚡",
    color: "#10b981",
    sub: "Security Orchestration, Automation & Response",
    desc: "SIEM fires → SOAR runs playbook → threat contained in seconds. MTTR without SOAR: hours. With SOAR: minutes.",
    items: [
      "Palo Alto XSOAR / Splunk SOAR",
      "Automated: block IP, isolate host, reset creds",
      "SIEM + EDR + FW + ticketing integrations",
      "Threat intel enrichment",
      "MTTR: hours → seconds",
    ],
    enc: [
      "All API calls: TLS 1.3",
      "PAM vault for credentials",
      "Signed audit log",
    ],
    tools: ["Palo Alto XSOAR", "Splunk SOAR", "IBM Resilient", "Swimlane"],
    attacks: ["SOAR API key compromise → disable automated response"],
    mitre: [["T1562", "Impair Defenses"]],
    compliance: [
      ["ISO 27001", "A.16 — Incident management"],
      ["SOC 2", "CC7.4 — Incident response"],
    ],
    zt: "SOAR automates ZT policy enforcement and accelerates breach response.",
    ztOn: true,
  },
  {
    id: "ueba",
    label: "UEBA",
    icon: "🧠",
    color: "#06b6d4",
    sub: "User & Entity Behavior Analytics",
    desc: "Baselines normal behaviour per user / device / account — flags deviations. Catches insider threats that signature-based tools miss.",
    items: [
      "Per-entity behavioural baseline (ML)",
      "Insider threat detection",
      "Compromised account detection",
      "Peer-group comparison",
      "Feeds: SIEM / EDR / IAM / HR",
    ],
    enc: [
      "Encrypted telemetry: TLS",
      "AES-256 model storage",
      "RBAC on analytics results",
    ],
    tools: ["Microsoft Sentinel UEBA", "Splunk UBA", "Securonix", "Exabeam"],
    attacks: [
      "Slow account compromise below deviation threshold",
      "Credential sharing (two users, one profile)",
    ],
    mitre: [
      ["T1078", "Valid Accounts abused"],
      ["T1098", "Account Manipulation"],
    ],
    compliance: [
      ["ISO 27001", "A.12.4 — Monitoring"],
      ["SOC 2", "CC7.2 — Detection"],
      ["NIST CSF", "DE.AE — Anomaly detection"],
    ],
    zt: "UEBA validates that identity behaves as expected — continuous-auth backbone of ZT.",
    ztOn: true,
  },
  {
    id: "zt",
    label: "ZERO TRUST",
    icon: "🚫",
    color: "#e879f9",
    sub: "Zero Trust Architecture (NIST SP 800-207)",
    desc: "Never trust, always verify. Not a product — an architecture. The perimeter is dead. Identity is the new perimeter.",
    items: [
      "Never trust, always verify — every request",
      "Least privilege: PAM + RBAC + ABAC",
      "Continuous auth — not only at login",
      "Device health as access gate",
      "ZTNA replaces VPN · SASE · BeyondCorp",
    ],
    enc: [
      "mTLS everywhere (SPIFFE / SPIRE)",
      "IAM / IdP as perimeter",
      "Encrypt transit + rest — always",
      "Short-lived auto-rotated certificates",
    ],
    tools: [
      "Zscaler ZPA",
      "Cloudflare Access",
      "Google BeyondCorp",
      "Okta ZTNA",
    ],
    attacks: [
      "ZT misconfiguration leaving legacy bypass",
      "Compromised IdP = game over",
    ],
    mitre: [
      ["T1078", "Valid Accounts — ZT identity bypass"],
      ["T1556", "Modify Auth Process"],
    ],
    compliance: [
      ["NIST SP 800-207", "Zero Trust Architecture standard"],
      ["EO 14028", "US Federal ZT mandate"],
      ["CISA", "Zero Trust Maturity Model"],
    ],
    zt: "This IS Zero Trust Architecture.",
    ztOn: true,
  },
];

// ── Roadmap metadata per layer ───────────────────────────────
// priority: lower = do first | cost: 1-5 | complexity: 1-5
// impact: security risk reduction (1-5) | prereqs: layer ids needed first
const ROADMAP = {
  0: {
    priority: 1,
    cost: 2,
    complexity: 2,
    impact: 5,
    phase: 1,
    prereqs: [],
    timeMonths: "1-2",
    why: "Your data is the crown jewel. Encrypt it first — even if attacker gets in, they get nothing readable.",
    quickWins: [
      "Enable AES-256 encryption at rest in your DB",
      "Deploy HashiCorp Vault or AWS KMS for secrets",
      "Classify your data — know what you're protecting",
    ],
  },
  1: {
    priority: 8,
    cost: 3,
    complexity: 3,
    impact: 3,
    phase: 2,
    prereqs: [0, 2],
    timeMonths: "3-6",
    why: "Once you know what data you have (Layer 0) and who can access it (Layer 2), DLP stops it from leaving.",
    quickWins: [
      "Block USB drives on corporate endpoints",
      "Set up basic email DLP rules",
      "Monitor cloud uploads to personal accounts",
    ],
  },
  2: {
    priority: 2,
    cost: 3,
    complexity: 2,
    impact: 5,
    phase: 1,
    prereqs: [],
    timeMonths: "1-3",
    why: "Privileged accounts are the skeleton key. PAM is the single highest-ROI control — eliminates 70% of breach paths.",
    quickWins: [
      "Audit all accounts with admin rights — remove unnecessary ones",
      "Implement MFA on every admin account TODAY",
      "Put shared passwords in a vault (even free Bitwarden for teams)",
    ],
  },
  3: {
    priority: 3,
    cost: 3,
    complexity: 2,
    impact: 5,
    phase: 1,
    prereqs: [],
    timeMonths: "1-2",
    why: "EDR on every endpoint stops ransomware, fileless malware, and lateral movement before it starts. Modern EDR is affordable.",
    quickWins: [
      "Deploy EDR on all endpoints — start with servers",
      "Enable tamper protection so malware can't uninstall it",
      "Set up automated isolation on critical alert types",
    ],
  },
  4: {
    priority: 5,
    cost: 2,
    complexity: 3,
    impact: 4,
    phase: 1,
    prereqs: [],
    timeMonths: "2-4",
    why: "Flat networks let ransomware spread everywhere. VLAN segmentation limits blast radius. 802.1X stops rogue devices.",
    quickWins: [
      "Separate servers, users, IoT onto different VLANs",
      "Enable 802.1X on wired switches — even partial coverage helps",
      "Put a quarantine VLAN for unknown devices",
    ],
  },
  5: {
    priority: 6,
    cost: 3,
    complexity: 4,
    impact: 4,
    phase: 2,
    prereqs: [4],
    timeMonths: "3-6",
    why: "Most breaches spread East-West after initial compromise. Internal FW stops lateral movement — the most underrated control.",
    quickWins: [
      "Add ACL rules between your server and user VLANs",
      "Block SMB (port 445) between workstations",
      "Deploy service mesh (Istio) for microservices if applicable",
    ],
  },
  6: {
    priority: 7,
    cost: 3,
    complexity: 3,
    impact: 3,
    phase: 2,
    prereqs: [5],
    timeMonths: "3-6",
    why: "IDS/IPS gives you visibility into what's crossing your network. Without it you're blind to active attacks in progress.",
    quickWins: [
      "Deploy Suricata/Snort on network tap — detection mode first",
      "Connect to SIEM for alert correlation",
      "Enable inline IPS on critical network segments only",
    ],
  },
  7: {
    priority: 10,
    cost: 4,
    complexity: 4,
    impact: 3,
    phase: 3,
    prereqs: [6],
    timeMonths: "6-12",
    why: "NTA fills the gap between IDS signatures and behavioral anomalies. Essential for detecting APT and insider threats.",
    quickWins: [
      "Enable NetFlow collection on core switches",
      "Start with 30-day behavioral baseline before alerting",
      "Focus on detecting beaconing + DNS anomalies first",
    ],
  },
  8: {
    priority: 4,
    cost: 2,
    complexity: 2,
    impact: 4,
    phase: 1,
    prereqs: [],
    timeMonths: "1-2",
    why: "If you have a web app, you need a WAF. Period. Cloudflare free tier blocks most common attacks. Zero excuse not to.",
    quickWins: [
      "Put Cloudflare free tier in front of web apps — takes 30 mins",
      "Enable OWASP Top 10 ruleset",
      "Turn on bot protection and rate limiting",
    ],
  },
  9: {
    priority: 5,
    cost: 2,
    complexity: 2,
    impact: 4,
    phase: 1,
    prereqs: [],
    timeMonths: "1-3",
    why: "DMZ separates your public-facing services from internal network. Compromise of web server shouldn't reach your database.",
    quickWins: [
      "Move web servers to a separate network segment",
      "Deploy reverse proxy (Nginx) in DMZ",
      "Enforce TLS everywhere inside DMZ → internal comms",
    ],
  },
  10: {
    priority: 9,
    cost: 4,
    complexity: 3,
    impact: 3,
    phase: 3,
    prereqs: [3, 5],
    timeMonths: "6-12",
    why: "Once you control endpoints (EDR) and internal network, CASB extends that visibility to cloud. Don't skip earlier steps.",
    quickWins: [
      "Enable Microsoft Defender for Cloud Apps if you use M365 (it's included)",
      "Audit OAuth app permissions — revoke unused",
      "Block personal cloud storage uploads",
    ],
  },
  11: {
    priority: 1,
    cost: 2,
    complexity: 2,
    impact: 4,
    phase: 1,
    prereqs: [],
    timeMonths: "1-2",
    why: "You almost certainly already have a perimeter firewall. Make sure it's configured correctly — default-deny, no any-any rules.",
    quickWins: [
      "Audit firewall rules — delete any 'any-any' rules",
      "Enable GeoIP blocking for countries you don't do business with",
      "Turn on egress filtering — monitor outbound too",
    ],
  },
};

const PHASE_COLORS = {
  1: "#22c55e",
  2: "#f59e0b",
  3: "#8b5cf6",
  done: "#06b6d4",
  skip: "#252535",
};
const PHASE_LABELS = {
  1: "Phase 1 — Quick Wins (0-3 mo)",
  2: "Phase 2 — Foundation (3-9 mo)",
  3: "Phase 3 — Advanced (9-18 mo)",
};

// ── Vendor comparison data ────────────────────────────────────
// ratings: detection/prevention/ease/cost(value)/support — all 1-5
// cost: 1=expensive, 5=cheap/free
const VENDORS = {
  // EDR — Layer 3
  3: [
    {
      name: "CrowdStrike Falcon",
      short: "CS",
      color: "#e2001a",
      tier: "enterprise",
      deploy: "cloud",
      gartner: "Leader",
      price: "~$15/endpoint/mo",
      bestFor: "Large enterprise, mature SOC",
      ratings: { detection: 5, prevention: 5, ease: 3, cost: 1, support: 5 },
      pros: [
        "Best-in-class threat intel",
        "Fastest mean time to detect",
        "OverWatch MDR included",
        "Excellent threat hunting",
      ],
      cons: [
        "Most expensive EDR",
        "Requires cloud connectivity",
        "Complex licensing tiers",
        "Overkill for SMB",
      ],
    },
    {
      name: "SentinelOne",
      short: "S1",
      color: "#6c2dc7",
      tier: "enterprise",
      deploy: "cloud",
      gartner: "Leader",
      price: "~$10/endpoint/mo",
      bestFor: "Enterprise wanting autonomous response",
      ratings: { detection: 5, prevention: 5, ease: 4, cost: 2, support: 4 },
      pros: [
        "Autonomous AI response (no human needed)",
        "On-prem option available",
        "Strong Linux/macOS support",
        "Best rollback capability",
      ],
      cons: [
        "Alert fatigue in noisy environments",
        "Expensive for SMB",
        "Support can be slow",
      ],
    },
    {
      name: "Microsoft Defender XDR",
      short: "MSFT",
      color: "#0078d4",
      tier: "mid",
      deploy: "cloud",
      gartner: "Leader",
      price: "Included in M365 E5",
      bestFor: "Microsoft-heavy orgs, budget-conscious",
      ratings: { detection: 4, prevention: 4, ease: 5, cost: 5, support: 3 },
      pros: [
        "Free if you have M365 E5",
        "Native integration with Azure/Entra",
        "Unified XDR across email+endpoint+identity",
        "Easy to deploy",
      ],
      cons: [
        "Weaker against novel threats",
        "Alert quality inconsistent",
        "Limited non-Windows support",
        "Vendor lock-in",
      ],
    },
    {
      name: "Carbon Black (VMware)",
      short: "CB",
      color: "#00b7a8",
      tier: "mid",
      deploy: "hybrid",
      gartner: "Challenger",
      price: "~$8/endpoint/mo",
      bestFor: "On-prem/hybrid environments",
      ratings: { detection: 3, prevention: 4, ease: 3, cost: 3, support: 3 },
      pros: [
        "Strong on-prem option",
        "Good behavioral detection",
        "VMware integration",
      ],
      cons: [
        "Falling behind cloud-native rivals",
        "Acquisition by Broadcom causing uncertainty",
        "Heavier resource usage",
      ],
    },
  ],
  // WAF — Layer 8
  8: [
    {
      name: "Cloudflare WAF",
      short: "CF",
      color: "#f38020",
      tier: "budget",
      deploy: "cloud",
      gartner: "Challenger",
      price: "Free–$200/mo",
      bestFor: "Startups to mid-market, free tier is excellent",
      ratings: { detection: 4, prevention: 4, ease: 5, cost: 5, support: 3 },
      pros: [
        "Free tier blocks OWASP Top 10",
        "Global Anycast CDN included",
        "Bot management built-in",
        "30-min setup",
      ],
      cons: [
        "Enterprise features expensive",
        "Less customisable than F5",
        "Data residency concerns",
      ],
    },
    {
      name: "Akamai Kona",
      short: "AKM",
      color: "#009bde",
      tier: "enterprise",
      deploy: "cloud",
      gartner: "Leader",
      price: "Custom/expensive",
      bestFor: "Large enterprise, high-traffic sites",
      ratings: { detection: 5, prevention: 5, ease: 2, cost: 1, support: 5 },
      pros: [
        "Best DDoS protection at scale",
        "Largest CDN network",
        "Excellent professional services",
        "Proven at massive scale",
      ],
      cons: [
        "Very expensive",
        "Complex configuration",
        "Slow to deploy custom rules",
        "Requires specialist knowledge",
      ],
    },
    {
      name: "AWS WAF",
      short: "AWS",
      color: "#ff9900",
      tier: "mid",
      deploy: "cloud",
      gartner: "Challenger",
      price: "~$5/mo + $1/million req",
      bestFor: "AWS-native workloads",
      ratings: { detection: 3, prevention: 3, ease: 4, cost: 4, support: 3 },
      pros: [
        "Native AWS integration",
        "Pay-per-use pricing",
        "Easy if already on AWS",
        "Managed rule groups available",
      ],
      cons: [
        "Weak standalone — needs Shield Advanced",
        "Limited bot management",
        "Basic rule engine vs competitors",
      ],
    },
    {
      name: "F5 Advanced WAF",
      short: "F5",
      color: "#e4002b",
      tier: "enterprise",
      deploy: "hybrid",
      gartner: "Leader",
      price: "Hardware+license",
      bestFor: "Financial services, on-prem requirements",
      ratings: { detection: 5, prevention: 5, ease: 2, cost: 1, support: 4 },
      pros: [
        "Most advanced L7 inspection",
        "On-prem/hybrid deployment",
        "PCI DSS compliance features",
        "Application-level DoS protection",
      ],
      cons: [
        "Expensive hardware+license",
        "Steep learning curve",
        "Slow to adapt to cloud-native patterns",
      ],
    },
  ],
  // PAM — Layer 2
  2: [
    {
      name: "CyberArk PAM",
      short: "CA",
      color: "#0066cc",
      tier: "enterprise",
      deploy: "hybrid",
      gartner: "Leader",
      price: "Custom/expensive",
      bestFor: "Large enterprise, regulated industries",
      ratings: { detection: 5, prevention: 5, ease: 2, cost: 1, support: 5 },
      pros: [
        "Market leader — gold standard",
        "Most complete PAM feature set",
        "Strong compliance reporting",
        "Session isolation + recording",
      ],
      cons: [
        "Very expensive",
        "Complex deployment — 6-12 months",
        "Requires dedicated team to operate",
        "Overkill for SMB",
      ],
    },
    {
      name: "BeyondTrust",
      short: "BT",
      color: "#d0021b",
      tier: "enterprise",
      deploy: "hybrid",
      gartner: "Leader",
      price: "~$50-100/user/yr",
      bestFor: "Mid-market, Windows-heavy environments",
      ratings: { detection: 4, prevention: 5, ease: 3, cost: 2, support: 4 },
      pros: [
        "Strong least-privilege enforcement",
        "Good Windows ecosystem integration",
        "Endpoint privilege management",
        "Solid session monitoring",
      ],
      cons: [
        "Less mature on Linux/Mac",
        "UI needs improvement",
        "Slower innovation than CyberArk",
      ],
    },
    {
      name: "Delinea (Thycotic)",
      short: "DL",
      color: "#7b2d8b",
      tier: "mid",
      deploy: "cloud",
      gartner: "Challenger",
      price: "~$20-50/user/yr",
      bestFor: "Mid-market, fast deployment needed",
      ratings: { detection: 3, prevention: 4, ease: 5, cost: 3, support: 3 },
      pros: [
        "Easiest PAM to deploy",
        "Cloud-native option",
        "Good value for mid-market",
        "Fast time-to-value",
      ],
      cons: [
        "Less mature than CyberArk",
        "Fewer advanced features",
        "Smaller threat intel ecosystem",
      ],
    },
    {
      name: "Teleport",
      short: "TP",
      color: "#512fc9",
      tier: "mid",
      deploy: "cloud",
      gartner: "Niche",
      price: "Free (OSS) / ~$5/user/mo",
      bestFor: "DevOps / cloud-native / infrastructure access",
      ratings: { detection: 3, prevention: 4, ease: 4, cost: 5, support: 3 },
      pros: [
        "Open source option available",
        "Certificate-based — no passwords",
        "Excellent for Kubernetes/cloud",
        "Developer-friendly",
      ],
      cons: [
        "Narrow focus (infra access only)",
        "Smaller enterprise feature set",
        "Less compliance reporting",
      ],
    },
  ],
  // CASB — Layer 10
  10: [
    {
      name: "Netskope",
      short: "NS",
      color: "#00a1e0",
      tier: "enterprise",
      deploy: "cloud",
      gartner: "Leader",
      price: "Custom",
      bestFor: "Enterprise with complex SaaS/IaaS usage",
      ratings: { detection: 5, prevention: 5, ease: 3, cost: 2, support: 4 },
      pros: [
        "Best DLP in CASB market",
        "Deepest cloud app visibility",
        "Strong ZTNA integration",
        "Inline and API modes",
      ],
      cons: ["Expensive", "Complex deployment", "Steep learning curve"],
    },
    {
      name: "Zscaler Internet Access",
      short: "ZS",
      color: "#005daa",
      tier: "enterprise",
      deploy: "cloud",
      gartner: "Leader",
      price: "~$8/user/mo",
      bestFor: "Full SSE/SASE adoption, remote workforce",
      ratings: { detection: 4, prevention: 5, ease: 3, cost: 2, support: 4 },
      pros: [
        "Complete SSE platform",
        "Excellent ZTNA (ZPA)",
        "Best for replacing legacy VPN",
        "Strong threat prevention",
      ],
      cons: [
        "Expensive at scale",
        "All-or-nothing architecture",
        "Requires significant change management",
      ],
    },
    {
      name: "MS Defender for Cloud Apps",
      short: "MDA",
      color: "#0078d4",
      tier: "mid",
      deploy: "cloud",
      gartner: "Challenger",
      price: "Included in M365 E5",
      bestFor: "Microsoft shops with M365 E5",
      ratings: { detection: 3, prevention: 3, ease: 5, cost: 5, support: 3 },
      pros: [
        "Free with M365 E5",
        "Deep Microsoft 365 integration",
        "Easy to enable",
        "Good Shadow IT discovery",
      ],
      cons: [
        "Limited non-Microsoft coverage",
        "Weaker DLP vs Netskope",
        "Basic API mode only for most apps",
      ],
    },
  ],
  // SIEM — satellite (id: siem)
  siem: [
    {
      name: "Splunk Enterprise",
      short: "SPL",
      color: "#65a637",
      tier: "enterprise",
      deploy: "hybrid",
      gartner: "Leader",
      price: "~$150/GB/day indexed",
      bestFor: "Large enterprise, mature SOC",
      ratings: { detection: 5, prevention: 3, ease: 2, cost: 1, support: 5 },
      pros: [
        "Most powerful query language (SPL)",
        "Massive ecosystem of apps",
        "Best for complex correlation",
        "Market-defining product",
      ],
      cons: [
        "Most expensive SIEM",
        "Steep SPL learning curve",
        "Licensing shock at scale",
        "Complex infrastructure",
      ],
    },
    {
      name: "Microsoft Sentinel",
      short: "MSFT",
      color: "#0078d4",
      tier: "mid",
      deploy: "cloud",
      gartner: "Leader",
      price: "~$2.50/GB ingested",
      bestFor: "Azure/Microsoft environments, cloud-first",
      ratings: { detection: 4, prevention: 3, ease: 4, cost: 3, support: 4 },
      pros: [
        "Cloud-native, no infra to manage",
        "Native Azure/M365 integration",
        "Good SOAR built-in",
        "Predictable pricing",
      ],
      cons: [
        "Weaker query language vs Splunk",
        "Less mature ecosystem",
        "Data ingestion costs add up",
      ],
    },
    {
      name: "Elastic SIEM",
      short: "ELK",
      color: "#f04e98",
      tier: "budget",
      deploy: "hybrid",
      gartner: "Visionary",
      price: "Free (OSS) / ~$95/mo cloud",
      bestFor: "Budget-conscious, technical teams",
      ratings: { detection: 3, prevention: 2, ease: 3, cost: 5, support: 2 },
      pros: [
        "Open source — free to self-host",
        "Excellent search performance",
        "Flexible data ingestion",
        "Good for threat hunting",
      ],
      cons: [
        "No native SOAR",
        "Requires significant tuning",
        "Support depends on tier",
        "Less out-of-box detection",
      ],
    },
    {
      name: "IBM QRadar",
      short: "QR",
      color: "#054ada",
      tier: "enterprise",
      deploy: "hybrid",
      gartner: "Leader",
      price: "Custom/expensive",
      bestFor: "Large regulated industries (finance, govt)",
      ratings: { detection: 4, prevention: 3, ease: 2, cost: 1, support: 4 },
      pros: [
        "Strong compliance reporting",
        "Good anomaly detection",
        "Long track record in enterprise",
        "Strong threat intel integration",
      ],
      cons: [
        "Legacy UI — outdated",
        "Very expensive",
        "Slow to innovate",
        "Complex administration",
      ],
    },
  ],
};

// Radar chart helper — 5 axes: detection, prevention, ease, cost, support
const VENDOR_AXES = ["detection", "prevention", "ease", "cost", "support"];
const VENDOR_AXIS_LABELS = {
  detection: "Detect",
  prevention: "Prevent",
  ease: "Ease",
  cost: "Value",
  support: "Support",
};

function vendorRadarPoints(ratings, cx, cy, r) {
  return VENDOR_AXES.map((k, i) => {
    const angle = (i / VENDOR_AXES.length) * 2 * Math.PI - Math.PI / 2;
    const val = (ratings[k] || 1) / 5;
    return [cx + r * val * Math.cos(angle), cy + r * val * Math.sin(angle)];
  })
    .map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`)
    .join(" ");
}

function vendorGridPoints(cx, cy, r) {
  return VENDOR_AXES.map((_, i) => {
    const angle = (i / VENDOR_AXES.length) * 2 * Math.PI - Math.PI / 2;
    return [cx + r * Math.cos(angle), cy + r * Math.sin(angle)];
  });
}

const COMPLIANCE_COLORS = {
  "PCI DSS": "#ef4444",
  "ISO 27001": "#3b82f6",
  GDPR: "#1d4ed8",
  "SOC 2": "#22c55e",
  HIPAA: "#14b8a6",
  "NIST CSF": "#8b5cf6",
  "NIST 800-53": "#7c3aed",
  CIS: "#f59e0b",
  OWASP: "#f97316",
  "CSA CCM": "#0ea5e9",
  "EO 14028": "#ec4899",
  CISA: "#ec4899",
  "NIST SP 800-207": "#8b5cf6",
};

const TABS = ["overview", "attacks", "mitre", "compliance", "maturity"];
const TAB_LABELS = {
  overview: "📋 Overview",
  attacks: "⚔ Attacks",
  mitre: "🎯 MITRE",
  compliance: "✅ Compliance",
  maturity: "📈 Maturity",
};
const MATURITY_LABELS = [
  "Initial",
  "Managed",
  "Defined",
  "Quantified",
  "Optimizing",
];
const MATURITY_COLORS = ["#ef4444", "#f97316", "#f59e0b", "#84cc16", "#22c55e"];

// ── Section header component (fixes colour readability) ──────
function SectionLabel({ children, color = "#555" }) {
  return (
    <div
      style={{
        color,
        fontSize: "10.5px",
        letterSpacing: "2px",
        fontFamily: "'Space Mono',monospace",
        marginBottom: "6px",
        fontWeight: "700",
        textTransform: "uppercase",
      }}
    >
      {children}
    </div>
  );
}

// ── Tag components — allow wrapping, no overflow ─────────────
function Tag({ children, cls = "tag" }) {
  return (
    <span
      className={cls}
      style={{ whiteSpace: "normal", wordBreak: "break-word" }}
    >
      {children}
    </span>
  );
}

// ══════════════════════════════════════════════════════════════
//  COMPONENT
// ══════════════════════════════════════════════════════════════

export default function App() {
  const uid = useId();
  const clip = `${uid}-clip`;

  const [sel, setSel] = useState(null);
  const [tab, setTab] = useState("overview");
  const [showEnc, setShowEnc] = useState(false);
  const [showQuantum, setShowQuantum] = useState(false);
  const [showZT, setShowZT] = useState(false);
  const [showHeat, setShowHeat] = useState(false);
  const [showThreat, setShowThreat] = useState(false);
  const [vw, setVw] = useState(900);
  const [apMode, setApMode] = useState(false);
  const [apId, setApId] = useState(null);
  const [apStep, setApStep] = useState(-1);
  const [apPlaying, setApPlaying] = useState(false);
  const [apSubTab, setApSubTab] = useState("steps");
  const [cmpMode, setCmpMode] = useState(false);
  const [cmpA, setCmpA] = useState(null);
  const [cmpB, setCmpB] = useState(null);
  const [cmpTab, setCmpTab] = useState("overview");
  // ── Roadmap state ─────────────────────────────────────────
  const [rmMode, setRmMode] = useState(false);
  const [rmHave, setRmHave] = useState(new Set());
  // ── What If state ─────────────────────────────────────────
  const [wifMode, setWifMode] = useState(false); // what-if mode
  const [wifDisabled, setWifDisabled] = useState(new Set()); // disabled layer ids // layer ids user already has

  useEffect(() => {
    const u = () => setVw(window.innerWidth);
    u();
    window.addEventListener("resize", u);
    return () => window.removeEventListener("resize", u);
  }, []);

  const apPath = ATTACK_PATHS.find((a) => a.id === apId) || null;
  const startAttack = useCallback((id) => {
    setApId(id);
    setApStep(-1);
    setApPlaying(true);
    setSel(null);
    setApSubTab("steps");
  }, []);

  useEffect(() => {
    if (!apPlaying || !apPath) return;
    if (apStep >= apPath.steps.length - 1) {
      setApPlaying(false);
      return;
    }
    const delay = apPath.steps[apStep + 1]?.time || 600;
    const t = setTimeout(() => setApStep((s) => s + 1), delay);
    return () => clearTimeout(t);
  }, [apPlaying, apStep, apPath]);

  const resetAll = useCallback(() => {
    setSel(null);
    setTab("overview");
    setShowEnc(false);
    setShowZT(false);
    setShowHeat(false);
    setShowThreat(false);
    setShowQuantum(false);
    setApMode(false);
    setApId(null);
    setApStep(-1);
    setApPlaying(false);
    setCmpMode(false);
    setCmpA(null);
    setCmpB(null);
    setRmMode(false);
    setRmHave(new Set());
    setWifMode(false);
    setWifDisabled(new Set());
  }, []);

  const pick = useCallback(
    (id, t = "overview") => {
      if (wifMode && typeof id === "number") {
        setWifDisabled((s) => {
          const n = new Set(s);
          n.has(id) ? n.delete(id) : n.add(id);
          return n;
        });
        return;
      }
      if (cmpMode && typeof id === "number") {
        if (cmpA === null) {
          setCmpA(id);
        } else if (cmpA === id) {
          setCmpA(null);
          setCmpB(null);
        } else {
          setCmpB(cmpB === id ? null : id);
        }
        return;
      }
      setSel((s) => (s === id ? null : id));
      setTab(t);
    },
    [wifMode, cmpMode, cmpA, cmpB]
  );

  const selLayer = typeof sel === "number" ? LAYERS[sel] : null;
  const selSat =
    typeof sel === "string" && sel.startsWith("s:")
      ? SATS.find((s) => `s:${s.id}` === sel)
      : null;
  const selThreat =
    typeof sel === "string" && sel.startsWith("ta:")
      ? THREAT_ACTORS.find((t) => `ta:${t.id}` === sel)
      : null;
  const panel = selLayer || selSat || selThreat;

  // What-if: recalculate steps — disabled layers always bypassed
  // Pass-through probability per result: chance attack gets PAST this layer
  const PASS_PROB = { blocked: 0.12, slowed: 0.55, bypassed: 0.97 };

  const apStepsEff = apPath
    ? apPath.steps.map((s) => {
        const result =
          wifMode && wifDisabled.has(s.id) && s.result !== "active"
            ? "bypassed"
            : s.result;
        return {
          ...s,
          result,
          passProb: PASS_PROB[result] ?? 0.5,
          wifChanged:
            wifMode &&
            wifDisabled.has(s.id) &&
            (s.result === "blocked" || s.result === "slowed"),
        };
      })
    : [];

  // Cumulative attack-success probability through step i (product of pass probs)
  const cumulativeSuccess = (uptoIdx) => {
    let p = 1;
    for (let i = 0; i <= uptoIdx && i < apStepsEff.length; i++)
      p *= apStepsEff[i].passProb;
    return p;
  };
  const successColor = (p) =>
    p >= 0.5
      ? "#ef4444"
      : p >= 0.2
      ? "#f59e0b"
      : p >= 0.05
      ? "#84cc16"
      : "#22c55e";

  const apStatus = {};
  if (apPath && apStep >= 0) {
    apStepsEff.forEach((s, i) => {
      if (i < apStep) apStatus[s.id] = s.result;
      if (i === apStep) apStatus[s.id] = "active";
    });
  }

  const highlighted =
    cmpMode && (cmpA !== null || cmpB !== null)
      ? new Set([cmpA, cmpB].filter((x) => x !== null))
      : apMode && apPath && apStep >= 0
      ? new Set(apPath.steps.slice(0, apStep + 1).map((s) => s.id))
      : selThreat
      ? new Set(selThreat.targets)
      : selLayer
      ? new Set([selLayer.id])
      : null;

  const AP_COLORS = {
    blocked: "#22c55e",
    slowed: "#f59e0b",
    bypassed: "#ef4444",
    active: "#fff",
  };
  const ENC_TYPES = {
    // quantum: "safe" (symmetric, survives Grover) | "risk" (RSA/ECC key exchange, breaks under Shor) | "hybrid"
    TLS: {
      color: "#06b6d4",
      label: "TLS / mTLS",
      quantum: "risk",
      qNote:
        "TLS key exchange (RSA/ECDHE) is broken by Shor's algorithm. Migrate to TLS 1.3 + ML-KEM hybrid.",
    },
    AES: {
      color: "#f59e0b",
      label: "AES-256",
      quantum: "safe",
      qNote:
        "AES-256 is quantum-resistant — Grover's algorithm only halves effective strength to 128-bit, still secure.",
    },
    IPSec: {
      color: "#8b5cf6",
      label: "IPSec / VPN",
      quantum: "risk",
      qNote:
        "IKE key exchange relies on DH/ECDH — quantum-vulnerable. RFC 9370 adds PQC hybrid key exchange.",
    },
    FDE: {
      color: "#22c55e",
      label: "Full Disk Enc",
      quantum: "safe",
      qNote: "FDE uses AES-XTS (symmetric) — quantum-safe with 256-bit keys.",
    },
    PEAP: {
      color: "#f43f5e",
      label: "PEAP / 802.1X",
      quantum: "risk",
      qNote:
        "TLS-based EAP methods inherit the same quantum-vulnerable key exchange.",
    },
    other: { color: "#94a3b8", label: "Other", quantum: "safe", qNote: "" },
  };
  const QUANTUM_COLORS = {
    safe: "#22c55e",
    risk: "#ef4444",
    hybrid: "#f59e0b",
  };
  const QUANTUM_LABELS = {
    safe: "Quantum-safe",
    risk: "Quantum-vulnerable",
    hybrid: "Hybrid PQC",
  };
  const getEncType = (l) => {
    const e = (l.enc[0] || "").toUpperCase();
    if (e.includes("TLS") || e.includes("MTLS")) return "TLS";
    if (e.includes("AES") || e.includes("TDE")) return "AES";
    if (e.includes("IPSEC") || e.includes("IKEV") || e.includes("WIREGUARD"))
      return "IPSec";
    if (e.includes("FDE") || e.includes("BITLOCKER") || e.includes("FULL DISK"))
      return "FDE";
    if (e.includes("PEAP") || e.includes("EAP") || e.includes("MACSEC"))
      return "PEAP";
    return "other";
  };

  const ringColor = (l) => {
    if (wifMode && wifDisabled.has(l.id)) return "#2a2a3a";
    if (showQuantum) {
      const dim = highlighted
        ? !highlighted.has(l.id)
        : typeof sel === "number" && sel !== l.id;
      if (dim) return l.color;
      return QUANTUM_COLORS[ENC_TYPES[getEncType(l)].quantum] || l.color;
    }
    if (showEnc) {
      const dim = highlighted
        ? !highlighted.has(l.id)
        : typeof sel === "number" && sel !== l.id;
      if (dim) return l.color;
      return ENC_TYPES[getEncType(l)].color;
    }
    if (rmMode) {
      if (rmHave.has(l.id)) return PHASE_COLORS.done;
      return PHASE_COLORS[ROADMAP[l.id]?.phase] || l.color;
    }
    if (apMode && apPath && apStatus[l.id])
      return AP_COLORS[apStatus[l.id]] || l.color;
    if (showHeat) return coverageColor(l.coverage);
    return l.color;
  };

  // Roadmap: compute personalised order
  const rmPlan = rmMode
    ? (() => {
        const gaps = LAYERS.filter((l) => !rmHave.has(l.id));
        // Sort by phase then priority
        const sorted = [...gaps].sort((a, b) => {
          const ra = ROADMAP[a.id],
            rb = ROADMAP[b.id];
          if (ra.phase !== rb.phase) return ra.phase - rb.phase;
          return ra.priority - rb.priority;
        });
        // Group by phase
        const phases = { 1: [], 2: [], 3: [] };
        sorted.forEach((l) => {
          const p = ROADMAP[l.id].phase;
          phases[p].push(l);
        });
        return phases;
      })()
    : null;
  const narrow = vw < 580;

  const sectionLabel = (text, color) => (
    <div
      style={{
        color: color || "#555",
        fontSize: "10px",
        letterSpacing: "2px",
        fontFamily: "'Space Mono',monospace",
        marginBottom: "6px",
        fontWeight: "700",
        textTransform: "uppercase",
      }}
    >
      {text}
    </div>
  );
  const tags = (items, cls) => (
    <div style={{ display: "flex", flexWrap: "wrap", gap: "4px" }}>
      {items.map((x, i) => (
        <span
          key={i}
          className={cls || "tag"}
          style={{ whiteSpace: "normal", wordBreak: "break-word" }}
        >
          {x}
        </span>
      ))}
    </div>
  );
  const colHead = (L) => (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: "6px",
        padding: "8px 12px",
        background: `${L.color}14`,
        borderBottom: `1px solid ${L.color}22`,
      }}
    >
      <span style={{ fontSize: "18px" }}>{L.icon}</span>
      <div>
        <div
          style={{
            fontFamily: "'Rajdhani',sans-serif",
            fontWeight: 800,
            fontSize: "15px",
            color: L.color,
            letterSpacing: "1px",
          }}
        >
          {L.short}
        </div>
        <div
          style={{ fontSize: "10px", color: "#8080a0", letterSpacing: "1px" }}
        >
          {L.badge}
        </div>
      </div>
    </div>
  );
  const renderPathCard = (ap, layerId, highlight, key) => {
    const step = ap.steps.find((s) => s.id === layerId);
    if (!step) return null;
    const sc = { blocked: "#22c55e", slowed: "#f59e0b", bypassed: "#ef4444" }[
      step.result
    ];
    const si = { blocked: "BLOCKED", slowed: "SLOWED", bypassed: "BYPASSED" }[
      step.result
    ];
    return (
      <div
        key={key}
        style={{
          display: "flex",
          gap: "7px",
          alignItems: "flex-start",
          padding: "7px 9px",
          borderRadius: "6px",
          marginBottom: "4px",
          background: highlight
            ? "rgba(6,182,212,.06)"
            : "rgba(255,255,255,.025)",
          border: `1px solid ${highlight ? "#06b6d433" : sc + "22"}`,
        }}
      >
        <span style={{ fontSize: "16px", flexShrink: 0 }}>{ap.icon}</span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "5px",
              flexWrap: "wrap",
              marginBottom: "3px",
            }}
          >
            <span
              style={{
                fontSize: "10px",
                fontWeight: "700",
                color: ap.color,
                fontFamily: "'Rajdhani',sans-serif",
                letterSpacing: ".5px",
              }}
            >
              {ap.label}
            </span>
            <span
              style={{
                fontSize: "10px",
                fontWeight: "700",
                color: sc,
                fontFamily: "'Space Mono',monospace",
              }}
            >
              {si}
            </span>
          </div>
          <div
            style={{ fontSize: "10.5px", color: "#b0b0c0", lineHeight: "1.45" }}
          >
            {step.how}
          </div>
        </div>
      </div>
    );
  };

  const streamCSS = STREAMS.map((s) => {
    const [sx, sy] = onArc(MAX + 75, s.angle);
    const [ex, ey] = onArc(mR(s.stopId), s.angle);
    return `@keyframes atk${s.id}{0%{transform:translate(${(sx - CX).toFixed(
      1
    )}px,${(sy - CY).toFixed(
      1
    )}px);opacity:0}8%{opacity:.9}80%{transform:translate(${(ex - CX).toFixed(
      1
    )}px,${(ey - CY).toFixed(1)}px);opacity:.9}92%{transform:translate(${(
      ex - CX
    ).toFixed(1)}px,${(ey - CY).toFixed(
      1
    )}px);opacity:0}100%{transform:translate(${(sx - CX).toFixed(1)}px,${(
      sy - CY
    ).toFixed(1)}px);opacity:0}}`;
  }).join("\n");

  return (
    <div
      id="arch-root"
      style={{
        minHeight: "100vh",
        background: "#07080f",
        color: "#fff",
        display: "flex",
        flexDirection: "column",
        fontFamily: "'Space Mono',monospace",
      }}
    >
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Rajdhani:wght@700;800&family=Inter:wght@400;500;600&display=swap');
        @keyframes breathe{0%,100%{opacity:.72}50%{opacity:1}}
        @keyframes fadein{from{opacity:0;transform:translateY(5px)}to{opacity:1;transform:translateY(0)}}
        @keyframes ap-pulse{0%,100%{opacity:1}50%{opacity:.6}}
        .ring{cursor:pointer;transition:opacity .22s,filter .18s;}
        .ring:hover{filter:brightness(1.12);}
        .ring:focus-visible{outline:2px solid #fff;outline-offset:2px;}
        .sat,.ta-btn{cursor:pointer;transition:all .18s;border-radius:7px;}
        .sat:hover,.ta-btn:hover{filter:brightness(1.12);}
        .panel{animation:fadein .2s ease;}
        .tab-btn{cursor:pointer;border-radius:5px;font-family:'Space Mono',monospace;font-size:9px;letter-spacing:.8px;padding:4px 10px;border:1px solid;transition:all .18s;}
        .tag{background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.14);border-radius:4px;padding:4px 9px;font-size:10px;color:#c0c0c0;}
        .etag{background:rgba(240,192,64,.1);border:1px solid rgba(240,192,64,.32);border-radius:4px;padding:4px 9px;font-size:10px;color:#f0c040;}
        .ttag{background:rgba(100,200,255,.08);border:1px solid rgba(100,200,255,.25);border-radius:4px;padding:4px 9px;font-size:10px;color:#90d8ff;}
        .atag{background:rgba(255,80,80,.09);border:1px solid rgba(255,80,80,.28);border-radius:4px;padding:4px 9px;font-size:10px;color:#ff9090;}
        .mtag{background:rgba(160,100,255,.09);border:1px solid rgba(160,100,255,.28);border-radius:4px;padding:4px 9px;font-size:10px;color:#d0a0ff;}
        .chip{cursor:pointer;display:inline-flex;align-items:center;gap:5px;padding:4px 9px;border-radius:20px;border:1px solid;font-size:10px;transition:all .15s;white-space:nowrap;}
        .chip:hover{filter:brightness(1.15);}
        .tbtn{border-radius:6px;cursor:pointer;font-family:'Space Mono',monospace;font-size:10px;letter-spacing:.8px;padding:5px 13px;border-width:1px;border-style:solid;transition:all .2s;}
        ${showThreat ? streamCSS : ""}
      `}</style>

      {/* Header */}
      <div style={{ textAlign: "center", padding: "10px 8px 4px" }}>
        <div
          style={{
            fontFamily: "'Rajdhani',sans-serif",
            fontWeight: 800,
            fontSize: "clamp(15px,5vw,26px)",
            letterSpacing: "5px",
          }}
        >
          SECURITY ARCHITECTURE
        </div>
        <div
          style={{
            color: "#9090b0",
            fontSize: "10.5px",
            letterSpacing: "2px",
            marginTop: "2px",
          }}
        >
          MITRE ATT&CK · ATTACK VECTORS · COMPLIANCE · MATURITY · THREAT ACTORS
        </div>
      </div>

      {/* Toggles */}
      <div
        style={{
          display: "flex",
          gap: "6px",
          justifyContent: "center",
          flexWrap: "wrap",
          padding: "4px 8px 6px",
        }}
      >
        {[
          {
            v: showEnc,
            f: () => setShowEnc((e) => !e),
            c: "#f0c040",
            l: "Encryption",
          },
          {
            v: showQuantum,
            f: () => setShowQuantum((q) => !q),
            c: "#2dd4bf",
            l: "Quantum",
          },
          {
            v: showZT,
            f: () => setShowZT((z) => !z),
            c: "#e879f9",
            l: "Zero Trust",
          },
          {
            v: showHeat,
            f: () => setShowHeat((h) => !h),
            c: "#22c55e",
            l: "Coverage Map",
          },
          {
            v: showThreat,
            f: () => setShowThreat((t) => !t),
            c: "#ff4444",
            l: "Threat Meter",
          },
          {
            v: apMode,
            f: () => {
              setApMode((m) => {
                if (m) {
                  setApId(null);
                  setApStep(-1);
                  setApPlaying(false);
                }
                return !m;
              });
            },
            c: "#f43f5e",
            l: "Attack Path",
          },
          {
            v: cmpMode,
            f: () => {
              setCmpMode((m) => {
                if (m) {
                  setCmpA(null);
                  setCmpB(null);
                }
                return !m;
              });
            },
            c: "#06b6d4",
            l: "Compare",
          },
          {
            v: rmMode,
            f: () => setRmMode((m) => !m),
            c: "#a78bfa",
            l: "Roadmap",
          },
          {
            v: wifMode,
            f: () => {
              setWifMode((m) => {
                if (m) setWifDisabled(new Set());
                return !m;
              });
            },
            c: "#fb923c",
            l: "What If",
          },
        ].map(({ v, f, c, l }) => (
          <button
            key={l}
            className="tbtn"
            onClick={f}
            aria-pressed={v}
            style={{
              background: v ? `${c}18` : "transparent",
              borderColor: v ? c : "#1e1e30",
              color: v ? c : "#404060",
            }}
          >
            {l}
          </button>
        ))}
        <button
          className="tbtn"
          onClick={resetAll}
          style={{ borderColor: "#333", color: "#9090a8" }}
        >
          Reset
        </button>
      </div>

      {/* Encryption legend */}
      {showEnc && (
        <div
          style={{
            display: "flex",
            gap: "10px",
            justifyContent: "center",
            flexWrap: "wrap",
            padding: "0 8px 6px",
            fontSize: "10.5px",
          }}
        >
          {Object.entries(ENC_TYPES).map(([k, { color, label }]) => (
            <div
              key={k}
              style={{ display: "flex", alignItems: "center", gap: "4px" }}
            >
              <div
                style={{
                  width: 10,
                  height: 10,
                  borderRadius: "50%",
                  background: color,
                  flexShrink: 0,
                }}
              />
              <span style={{ color: "#b0b0c0" }}>{label}</span>
            </div>
          ))}
        </div>
      )}

      {/* Quantum legend + explainer */}
      {showQuantum && (
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            padding: "0 8px 8px",
            gap: "6px",
          }}
        >
          <div
            style={{
              display: "flex",
              gap: "14px",
              justifyContent: "center",
              flexWrap: "wrap",
              fontSize: "10.5px",
            }}
          >
            {Object.entries(QUANTUM_LABELS).map(([k, label]) => (
              <div
                key={k}
                style={{ display: "flex", alignItems: "center", gap: "5px" }}
              >
                <div
                  style={{
                    width: 11,
                    height: 11,
                    borderRadius: "50%",
                    background: QUANTUM_COLORS[k],
                    flexShrink: 0,
                  }}
                />
                <span style={{ color: "#c0c0d0" }}>{label}</span>
              </div>
            ))}
          </div>
          <div
            style={{
              maxWidth: "560px",
              textAlign: "center",
              fontSize: "11px",
              color: "#a0a0c0",
              lineHeight: "1.6",
              fontFamily: "'Inter',sans-serif",
            }}
          >
            Symmetric crypto (AES-256, FDE) survives quantum computers —
            Grover's algorithm only halves key strength. Asymmetric key exchange
            (RSA, ECDHE in TLS/IPSec) is broken by Shor's algorithm. Attackers
            harvest encrypted traffic{" "}
            <span style={{ color: "#fb923c" }}>now</span> to decrypt
            <span style={{ color: "#fb923c" }}> later</span> (HNDL) — migrate to
            NIST PQC: ML-KEM, ML-DSA, SLH-DSA.
          </div>
        </div>
      )}

      {/* Coverage legend */}
      {showHeat && (
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            padding: "0 8px 6px",
            gap: "4px",
          }}
        >
          <div
            style={{
              display: "flex",
              gap: "10px",
              justifyContent: "center",
              flexWrap: "wrap",
            }}
          >
            {[
              ["#ef4444", "< 30%"],
              ["#f97316", "30-45%"],
              ["#f59e0b", "45-60%"],
              ["#84cc16", "60-80%"],
              ["#22c55e", "> 80%"],
            ].map(([c, l]) => (
              <div
                key={l}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "4px",
                  fontSize: "10.5px",
                }}
              >
                <div
                  style={{
                    width: 10,
                    height: 10,
                    borderRadius: "50%",
                    background: c,
                  }}
                />
                <span style={{ color: "#b0b0c0" }}>{l}</span>
              </div>
            ))}
          </div>
          <div
            style={{
              fontSize: "11px",
              textAlign: "center",
              color: "#a0a0c0",
              fontFamily: "'Inter',sans-serif",
            }}
          >
            higher % = more widely deployed · low % = common security gap
          </div>
        </div>
      )}

      {/* Threat meter legend */}
      {showThreat && (
        <div
          style={{
            display: "flex",
            gap: "12px",
            justifyContent: "center",
            flexWrap: "wrap",
            padding: "0 8px 6px",
            fontSize: "10px",
          }}
        >
          <span style={{ color: "#ff3366" }}>Nation-state APT</span>
          <span style={{ color: "#ff7700" }}>Ransomware</span>
          <span style={{ color: "#aa44ff" }}>Insider</span>
          <span style={{ color: "#00aaff" }}>Supply chain</span>
          <span style={{ color: "#d4b800" }}>Web attacks</span>
        </div>
      )}

      {/* What If hint */}
      {wifMode && (
        <div
          style={{
            textAlign: "center",
            padding: "0 8px 5px",
            fontSize: "10.5px",
            color: "#fb923caa",
            letterSpacing: "1px",
          }}
        >
          {wifDisabled.size === 0
            ? "Click any layer to disable it — see how attacks change"
            : `Disabled: ${[...wifDisabled]
                .map((id) => LAYERS[id].short)
                .join(", ")} — ${
                apPath
                  ? "attack path recalculated"
                  : "enable Attack Path to see impact"
              }`}
        </div>
      )}

      {/* Compare hint */}
      {cmpMode && (
        <div
          style={{
            textAlign: "center",
            padding: "0 8px 5px",
            fontSize: "10.5px",
            color: "#06b6d4aa",
            letterSpacing: "1px",
          }}
        >
          {cmpA === null
            ? "Click a layer to select first"
            : cmpB === null
            ? `${LAYERS[cmpA].short} selected — click another layer`
            : `Comparing ${LAYERS[cmpA].short} vs ${LAYERS[cmpB].short}`}
        </div>
      )}

      {/* Attack Path controls */}
      {apMode && (
        <div style={{ padding: "0 8px 8px" }}>
          <div
            style={{
              display: "flex",
              gap: "5px",
              flexWrap: "wrap",
              justifyContent: "center",
              marginBottom: "6px",
            }}
          >
            {ATTACK_PATHS.map((ap) => {
              const on = apId === ap.id;
              return (
                <button
                  key={ap.id}
                  onClick={() => startAttack(ap.id)}
                  style={{
                    background: on ? `${ap.color}22` : "rgba(255,255,255,.03)",
                    border: `1.5px solid ${on ? ap.color : ap.color + "44"}`,
                    color: on ? ap.color : ap.color + "aa",
                    borderRadius: "6px",
                    padding: "5px 12px",
                    cursor: "pointer",
                    fontSize: "10px",
                    fontFamily: "'Space Mono',monospace",
                    letterSpacing: ".5px",
                    transition: "all .18s",
                  }}
                >
                  {ap.icon} {ap.label}
                </button>
              );
            })}
          </div>
          <div
            style={{
              display: "flex",
              gap: "12px",
              justifyContent: "center",
              fontSize: "10px",
              flexWrap: "wrap",
              marginBottom: "4px",
            }}
          >
            {[
              ["#22c55e", "BLOCKED"],
              ["#f59e0b", "SLOWED"],
              ["#ef4444", "BYPASSED"],
              ["#fff", "ACTIVE"],
            ].map(([c, l]) => (
              <span
                key={l}
                style={{
                  color: c,
                  display: "flex",
                  alignItems: "center",
                  gap: "4px",
                }}
              >
                <span
                  style={{
                    width: 8,
                    height: 8,
                    borderRadius: "50%",
                    background: c,
                    display: "inline-block",
                  }}
                />
                {l}
              </span>
            ))}
          </div>
          {apPath && (
            <div
              style={{ display: "flex", gap: "6px", justifyContent: "center" }}
            >
              <button
                onClick={() => {
                  setApStep(-1);
                  setApPlaying(true);
                }}
                style={{
                  background: "rgba(244,63,94,.15)",
                  border: "1px solid #f43f5e66",
                  color: "#f43f5e",
                  borderRadius: "5px",
                  padding: "4px 14px",
                  cursor: "pointer",
                  fontSize: "10.5px",
                  fontFamily: "'Space Mono',monospace",
                }}
              >
                Play
              </button>
              <button
                onClick={() => setApPlaying(false)}
                style={{
                  background: "rgba(255,255,255,.04)",
                  border: "1px solid #333",
                  color: "#9090a8",
                  borderRadius: "5px",
                  padding: "4px 14px",
                  cursor: "pointer",
                  fontSize: "10.5px",
                  fontFamily: "'Space Mono',monospace",
                }}
              >
                Pause
              </button>
              <button
                onClick={() => {
                  setApStep((s) => Math.max(-1, s - 1));
                  setApPlaying(false);
                }}
                style={{
                  background: "rgba(255,255,255,.04)",
                  border: "1px solid #333",
                  color: "#9090a8",
                  borderRadius: "5px",
                  padding: "4px 10px",
                  cursor: "pointer",
                  fontSize: "10.5px",
                  fontFamily: "'Space Mono',monospace",
                }}
              >
                Prev
              </button>
              <button
                onClick={() => {
                  setApStep((s) => Math.min(apPath.steps.length - 1, s + 1));
                  setApPlaying(false);
                }}
                style={{
                  background: "rgba(255,255,255,.04)",
                  border: "1px solid #333",
                  color: "#9090a8",
                  borderRadius: "5px",
                  padding: "4px 10px",
                  cursor: "pointer",
                  fontSize: "10.5px",
                  fontFamily: "'Space Mono',monospace",
                }}
              >
                Next
              </button>
            </div>
          )}
        </div>
      )}

      {/* Two-column layout */}
      <div
        style={{
          display: "flex",
          flexDirection: vw >= 768 ? "row" : "column",
          alignItems: vw >= 768 ? "flex-start" : "stretch",
        }}
      >
        {/* LEFT: SVG */}
        <div
          style={{
            width: vw >= 768 ? "32%" : "100%",
            flexShrink: 0,
            position: vw >= 768 ? "sticky" : "static",
            top: 0,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            background: "#07080f",
          }}
        >
          <svg
            viewBox={`0 0 ${VW} ${VH}`}
            style={{ width: "100%", height: "auto", display: "block" }}
            role="img"
            aria-label="Security architecture diagram"
            onClick={(e) => {
              if (e.target.tagName === "svg") setSel(null);
            }}
          >
            <defs>
              <clipPath id={clip}>
                <rect x="0" y="0" width={VW} height={VH} />
              </clipPath>
              {LAYERS.filter((l) => l.id > 0).map((l) => {
                const mr = mR(l.id),
                  cDeg = 8 + (l.id - 1) * 7,
                  span = 28;
                const a1 = ((cDeg + span) * Math.PI) / 180,
                  a2 = ((cDeg - span) * Math.PI) / 180;
                const sx = CX + mr * Math.cos(a1),
                  sy = CY - mr * Math.sin(a1);
                const ex = CX + mr * Math.cos(a2),
                  ey = CY - mr * Math.sin(a2);
                return (
                  <path
                    key={l.id}
                    id={`ap${uid}${l.id}`}
                    d={`M${sx.toFixed(1)},${sy.toFixed(
                      1
                    )} A${mr},${mr} 0 0,1 ${ex.toFixed(1)},${ey.toFixed(1)}`}
                    fill="none"
                    stroke="none"
                  />
                );
              })}
            </defs>

            {showZT && (
              <g clipPath={`url(#${clip})`} style={{ pointerEvents: "none" }}>
                {LAYERS.filter((l) => l.ztOn && l.id > 0).map((l) => (
                  <circle
                    key={l.id}
                    cx={CX}
                    cy={CY}
                    r={mR(l.id)}
                    fill="none"
                    stroke="#e879f9"
                    strokeWidth="2.5"
                    strokeDasharray="7 9"
                    opacity=".32"
                  />
                ))}
              </g>
            )}

            <g clipPath={`url(#${clip})`}>
              {[...LAYERS].reverse().map((l) => {
                const isAct = highlighted
                  ? highlighted.has(l.id)
                  : sel === l.id;
                const dim = highlighted
                  ? !highlighted.has(l.id)
                  : typeof sel === "number" && sel !== l.id;
                return (
                  <circle
                    key={l.id}
                    cx={CX}
                    cy={CY}
                    r={oR(l.id)}
                    fill={ringColor(l)}
                    opacity={dim ? 0.13 : 1}
                    stroke={isAct ? "#fff" : "none"}
                    strokeWidth={isAct ? 3 : 0}
                    className="ring"
                    role="button"
                    tabIndex={0}
                    aria-label={`${l.short}`}
                    aria-pressed={sel === l.id}
                    onClick={() => pick(l.id)}
                    onKeyDown={(e) =>
                      (e.key === "Enter" || e.key === " ") && pick(l.id)
                    }
                  />
                );
              })}
              {LAYERS.filter((l) => l.id > 0).map((l) => (
                <circle
                  key={`dv${l.id}`}
                  cx={CX}
                  cy={CY}
                  r={oR(l.id)}
                  fill="none"
                  stroke="rgba(0,0,0,.28)"
                  strokeWidth=".7"
                  style={{ pointerEvents: "none" }}
                />
              ))}
              <circle
                cx={CX}
                cy={CY}
                r={CR}
                fill={
                  showQuantum
                    ? QUANTUM_COLORS[ENC_TYPES[getEncType(LAYERS[0])].quantum]
                    : showEnc
                    ? ENC_TYPES[getEncType(LAYERS[0])].color
                    : showHeat
                    ? coverageColor(LAYERS[0].coverage)
                    : "#e82020"
                }
                className="ring"
                role="button"
                tabIndex={0}
                stroke={sel === 0 ? "#fff" : "rgba(255,80,80,.4)"}
                strokeWidth={sel === 0 ? 3 : 1.5}
                opacity={
                  highlighted && !highlighted.has(0)
                    ? 0.13
                    : typeof sel === "number" && sel !== 0
                    ? 0.13
                    : 1
                }
                aria-label="DATA"
                aria-pressed={sel === 0}
                onClick={() => pick(0)}
                onKeyDown={(e) =>
                  (e.key === "Enter" || e.key === " ") && pick(0)
                }
                style={{
                  animation: "breathe 4s ease-in-out infinite",
                  willChange: "opacity",
                }}
              />
            </g>

            {showThreat && (
              <g clipPath={`url(#${clip})`} style={{ pointerEvents: "none" }}>
                {STREAMS.map((s) => (
                  <g key={s.id}>
                    <circle
                      cx={CX}
                      cy={CY}
                      r={3.5}
                      fill={s.color}
                      style={{
                        animation: `atk${s.id} ${s.dur}s ${s.delay}s infinite ease-in`,
                      }}
                    />
                    <circle
                      cx={CX}
                      cy={CY}
                      r={2}
                      fill={s.color}
                      opacity={0.4}
                      style={{
                        animation: `atk${s.id} ${s.dur}s ${
                          s.delay + 0.06
                        }s infinite ease-in`,
                      }}
                    />
                  </g>
                ))}
              </g>
            )}

            {showHeat &&
              LAYERS.filter((l) => l.id > 0).map((l) => {
                // Place % on the arc in the lower-right empty zone, horizontal
                const [px, py] = onArc(mR(l.id), -42);
                const dim = highlighted
                  ? !highlighted.has(l.id)
                  : typeof sel === "number" && sel !== l.id;
                return (
                  <g
                    key={l.id}
                    opacity={dim ? 0.1 : 1}
                    style={{ pointerEvents: "none" }}
                  >
                    <text
                      x={px}
                      y={py}
                      textAnchor="middle"
                      dominantBaseline="middle"
                      fill="#000"
                      fontSize="13"
                      fontWeight="700"
                      fontFamily="'Space Mono',monospace"
                      stroke="rgba(255,255,255,.5)"
                      strokeWidth="3"
                      paintOrder="stroke"
                      opacity="0.92"
                    >
                      {l.coverage}%
                    </text>
                  </g>
                );
              })}

            {/* ZT: dashed arcs on ZT-enabled layers */}
            {showZT && (
              <g style={{ pointerEvents: "none" }}>
                {LAYERS.filter((l) => l.ztOn && l.id > 0).map((l) => (
                  <circle
                    key={l.id}
                    cx={CX}
                    cy={CY}
                    r={mR(l.id)}
                    fill="none"
                    stroke="#e879f9"
                    strokeWidth="2"
                    strokeDasharray="6 8"
                    opacity="0.4"
                  />
                ))}
              </g>
            )}

            {LAYERS.filter((l) => l.id > 0).map((l) => {
              const mr = mR(l.id);
              const dim = highlighted
                ? !highlighted.has(l.id)
                : typeof sel === "number" && sel !== l.id;
              const fs = mr < 80 ? 9 : mr < 140 ? 11 : mr < 230 ? 13 : 15;
              const short =
                l.id === 11 ? "PERIM FW" : l.id === 5 ? "INT FW" : l.short;
              return (
                <g
                  key={l.id}
                  opacity={dim ? 0.08 : 1}
                  style={{ pointerEvents: "none", transition: "opacity .22s" }}
                >
                  <text
                    fill={l.tc}
                    fontSize={fs}
                    fontWeight="700"
                    fontFamily="'Space Mono',monospace"
                    letterSpacing="1.5"
                  >
                    <textPath
                      href={`#ap${uid}${l.id}`}
                      startOffset="50%"
                      textAnchor="middle"
                    >
                      {short}
                    </textPath>
                  </text>
                </g>
              );
            })}

            <g style={{ pointerEvents: "none" }}>
              <text
                x={CX + CR * 0.55}
                y={CY - 5}
                textAnchor="middle"
                dominantBaseline="middle"
                fill="#fff"
                fontSize="10"
                fontWeight="700"
                fontFamily="'Space Mono',monospace"
                letterSpacing="1"
              >
                DATA
              </text>
            </g>
            <line
              x1={CX}
              y1={CY - MAX - 8}
              x2={CX}
              y2={CY + MAX + 8}
              stroke="#121222"
              strokeWidth="2"
            />
            {LAYERS.filter((l) => l.id > 0).map((l) => {
              const r = oR(l.id);
              return (
                <g key={l.id} style={{ pointerEvents: "none" }}>
                  <line
                    x1={CX - 5}
                    y1={CY - r}
                    x2={CX + 3}
                    y2={CY - r}
                    stroke={ringColor(l)}
                    strokeWidth="1.2"
                    opacity=".5"
                  />
                  <line
                    x1={CX - 5}
                    y1={CY + r}
                    x2={CX + 3}
                    y2={CY + r}
                    stroke={ringColor(l)}
                    strokeWidth="1.2"
                    opacity=".5"
                  />
                </g>
              );
            })}
          </svg>
        </div>

        {/* RIGHT panel */}
        <div
          style={{
            flex: 1,
            minWidth: 0,
            overflowX: "hidden",
            display: "flex",
            flexDirection: "column",
            borderLeft: vw >= 768 ? "1px solid #141428" : "none",
            background: "#07080f",
            paddingTop: vw >= 768 ? "4px" : "0",
          }}
        >
          {/* Layer chips */}
          <div
            style={{
              display: "flex",
              flexWrap: "wrap",
              gap: "4px",
              justifyContent: "center",
              padding: "4px 8px",
            }}
          >
            {LAYERS.map((l) => {
              const on = sel === l.id,
                hi = highlighted?.has(l.id),
                c = ringColor(l);
              return (
                <div
                  key={l.id}
                  className="chip"
                  role="button"
                  tabIndex={0}
                  aria-pressed={on}
                  onClick={() => pick(l.id)}
                  onKeyDown={(e) =>
                    (e.key === "Enter" || e.key === " ") && pick(l.id)
                  }
                  style={{
                    borderColor: on || hi ? c : c + "44",
                    background: on || hi ? `${c}22` : "rgba(255,255,255,.02)",
                    color: on || hi ? c : c + "99",
                    boxShadow: hi ? `0 0 8px ${c}66` : "none",
                  }}
                >
                  <div
                    style={{
                      width: 6,
                      height: 6,
                      borderRadius: "50%",
                      background: c,
                      flexShrink: 0,
                      boxShadow: on ? `0 0 5px ${c}` : "none",
                    }}
                  />
                  {l.id === 11 ? "PERIM" : l.id === 5 ? "INT FW" : l.short}
                  {showHeat && (
                    <span style={{ fontSize: "10px", opacity: 0.7 }}>
                      {" "}
                      {l.coverage}%
                    </span>
                  )}
                </div>
              );
            })}
          </div>

          {/* Threat Actors */}
          <div style={{ padding: "3px 8px 2px" }}>
            <div
              style={{
                color: "#8080a0",
                fontSize: "10px",
                letterSpacing: "2px",
                textAlign: "center",
                marginBottom: "4px",
              }}
            >
              THREAT ACTORS
            </div>
            <div
              style={{
                display: "flex",
                gap: "5px",
                flexWrap: "wrap",
                justifyContent: "center",
              }}
            >
              {THREAT_ACTORS.map((t) => {
                const on = sel === `ta:${t.id}`;
                return (
                  <div
                    key={t.id}
                    className="ta-btn"
                    role="button"
                    tabIndex={0}
                    aria-pressed={on}
                    onClick={() => pick(`ta:${t.id}`, "attacks")}
                    onKeyDown={(e) =>
                      (e.key === "Enter" || e.key === " ") &&
                      pick(`ta:${t.id}`, "attacks")
                    }
                    style={{
                      flex: "1",
                      minWidth: "85px",
                      maxWidth: "180px",
                      background: on ? `${t.color}18` : "rgba(255,255,255,.02)",
                      border: `1.5px solid ${on ? t.color : t.color + "33"}`,
                      padding: "7px 10px",
                      transition: "all .2s",
                      boxShadow: on ? `0 0 12px ${t.color}44` : "none",
                    }}
                  >
                    <div style={{ fontSize: "18px", marginBottom: "2px" }}>
                      {t.icon}
                    </div>
                    <div
                      style={{
                        fontFamily: "'Rajdhani',sans-serif",
                        fontWeight: 800,
                        fontSize: "11px",
                        color: on ? t.color : t.color + "bb",
                        letterSpacing: ".5px",
                        lineHeight: "1.2",
                      }}
                    >
                      {t.label}
                    </div>
                    <div
                      style={{
                        color: "#9090b0",
                        fontSize: "10.5px",
                        marginTop: "2px",
                      }}
                    >
                      L{t.targets.join(", L")}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Satellites */}
          <div
            style={{
              display: "flex",
              gap: "5px",
              padding: "5px 8px",
              flexWrap: "wrap",
              justifyContent: "center",
            }}
          >
            {SATS.map((s) => {
              const on = sel === `s:${s.id}`;
              return (
                <div
                  key={s.id}
                  className="sat"
                  role="button"
                  tabIndex={0}
                  aria-pressed={on}
                  onClick={() => pick(`s:${s.id}`)}
                  onKeyDown={(e) =>
                    (e.key === "Enter" || e.key === " ") && pick(`s:${s.id}`)
                  }
                  style={{
                    flex: "1",
                    minWidth: "90px",
                    maxWidth: "185px",
                    background: on ? `${s.color}16` : "rgba(255,255,255,.02)",
                    border: `1.5px solid ${on ? s.color : s.color + "30"}`,
                    padding: "7px 10px",
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "6px",
                    }}
                  >
                    <span style={{ fontSize: "16px" }}>{s.icon}</span>
                    <div>
                      <div
                        style={{
                          fontFamily: "'Rajdhani',sans-serif",
                          fontWeight: 800,
                          fontSize: "12px",
                          color: on ? s.color : s.color + "bb",
                          letterSpacing: "1px",
                        }}
                      >
                        {s.label}
                      </div>
                      <div style={{ color: "#7878a0", fontSize: "10.5px" }}>
                        cross-cutting
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Attack Path log */}
          {apMode && apPath && apStep >= 0 && (
            <div
              style={{
                margin: "4px 8px 0",
                borderRadius: "10px",
                border: "1px solid #f43f5e44",
                borderLeft: "3px solid #f43f5e",
                background: "rgba(244,63,94,.04)",
                overflow: "hidden",
              }}
            >
              <div
                style={{
                  padding: "10px 14px 8px",
                  borderBottom: "1px solid rgba(255,255,255,.05)",
                }}
              >
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "8px",
                    marginBottom: "8px",
                  }}
                >
                  <span style={{ fontSize: "18px" }}>{apPath.icon}</span>
                  <div style={{ flex: 1 }}>
                    <div
                      style={{
                        fontFamily: "'Rajdhani',sans-serif",
                        fontWeight: 800,
                        fontSize: "15px",
                        color: "#f43f5e",
                        letterSpacing: "1px",
                      }}
                    >
                      {apPath.label}
                    </div>
                    <div
                      style={{
                        color: "#9090b0",
                        fontSize: "10px",
                        letterSpacing: "1.5px",
                      }}
                    >
                      ATTACK PATH
                    </div>
                  </div>
                  <span style={{ fontSize: "10.5px", color: "#8080a0" }}>
                    Step {apStep + 1}/{apPath.steps.length}
                  </span>
                  {apStep === apPath.steps.length - 1 && (
                    <span style={{ fontSize: "10.5px", color: "#22c55e88" }}>
                      complete
                    </span>
                  )}
                </div>
                <div style={{ display: "flex", gap: "4px", flexWrap: "wrap" }}>
                  {[
                    ["steps", "Steps"],
                    ["cases", "Real Cases"],
                  ].map(([t, l]) => (
                    <button
                      key={t}
                      onClick={() => setApSubTab(t)}
                      style={{
                        background:
                          apSubTab === t ? "rgba(244,63,94,.2)" : "transparent",
                        border: `1px solid ${
                          apSubTab === t ? "#f43f5e" : "#252535"
                        }`,
                        color: apSubTab === t ? "#f43f5e" : "#505070",
                        borderRadius: "5px",
                        padding: "4px 12px",
                        cursor: "pointer",
                        fontSize: "10.5px",
                        fontFamily: "'Space Mono',monospace",
                        transition: "all .18s",
                      }}
                    >
                      {l}
                    </button>
                  ))}
                </div>
                {/* Live attack-success probability meter */}
                {(() => {
                  const p = cumulativeSuccess(apStep);
                  const pct = Math.round(p * 100);
                  const c = successColor(p);
                  return (
                    <div style={{ marginTop: "10px" }}>
                      <div
                        style={{
                          display: "flex",
                          justifyContent: "space-between",
                          alignItems: "center",
                          marginBottom: "4px",
                        }}
                      >
                        <span
                          style={{
                            fontSize: "10px",
                            color: "#9090b0",
                            fontFamily: "'Space Mono',monospace",
                            letterSpacing: "1px",
                          }}
                        >
                          ATTACK SUCCESS PROBABILITY
                        </span>
                        <span
                          style={{
                            fontSize: "15px",
                            fontWeight: "700",
                            color: c,
                            fontFamily: "'Rajdhani',sans-serif",
                          }}
                        >
                          {pct < 1 ? "<1" : pct}%
                        </span>
                      </div>
                      <div
                        style={{
                          height: 8,
                          borderRadius: 4,
                          background: "#151525",
                          overflow: "hidden",
                        }}
                      >
                        <div
                          style={{
                            height: "100%",
                            borderRadius: 4,
                            width: `${Math.max(pct, 2)}%`,
                            background: c,
                            transition: "width .4s, background .4s",
                          }}
                        />
                      </div>
                      <div
                        style={{
                          fontSize: "9px",
                          color: "#7878a0",
                          marginTop: "3px",
                          fontFamily: "'Inter',sans-serif",
                        }}
                      >
                        Chance this attack reaches DATA given the controls
                        crossed so far
                      </div>
                    </div>
                  );
                })()}
              </div>
              <div style={{ padding: "12px 14px" }}>
                <div
                  style={{
                    color: "#c8c8d4",
                    fontSize: "11.5px",
                    lineHeight: "1.6",
                    marginBottom: "10px",
                    fontFamily: "'Inter',sans-serif",
                  }}
                >
                  {apPath.desc}
                </div>
                {apSubTab === "steps" && (
                  <div
                    style={{
                      display: "flex",
                      flexDirection: "column",
                      gap: "4px",
                    }}
                  >
                    {apPath.steps.slice(0, apStep + 1).map((_, i) => {
                      const s = apStepsEff[i];
                      if (!s) return null;
                      const l = LAYERS[s.id];
                      const isActive = i === apStep;
                      const sc = {
                        blocked: "#22c55e",
                        slowed: "#f59e0b",
                        bypassed: "#ef4444",
                        active: "#fff",
                      }[isActive ? "active" : s.result];
                      const si = {
                        blocked: "BLOCKED",
                        slowed: "SLOWED",
                        bypassed: "BYPASSED",
                      }[s.result];
                      const isDisabled = wifMode && wifDisabled.has(s.id);
                      return (
                        <div
                          key={i}
                          style={{
                            display: "flex",
                            gap: "8px",
                            alignItems: "flex-start",
                            padding: "7px 10px",
                            borderRadius: "6px",
                            background: isActive
                              ? `${sc}12`
                              : isDisabled
                              ? "rgba(251,146,60,.06)"
                              : "rgba(255,255,255,.02)",
                            border: `1px solid ${
                              isActive
                                ? sc + "44"
                                : isDisabled
                                ? "#fb923c44"
                                : "#151525"
                            }`,
                            animation: isActive
                              ? "ap-pulse .7s ease-in-out infinite"
                              : "none",
                          }}
                        >
                          <div
                            style={{
                              flexShrink: 0,
                              display: "flex",
                              flexDirection: "column",
                              alignItems: "center",
                              gap: "2px",
                            }}
                          >
                            <div
                              style={{
                                width: 28,
                                height: 28,
                                borderRadius: "50%",
                                background: isDisabled
                                  ? "#2a2a3a"
                                  : `${l.color}33`,
                                border: `2px solid ${
                                  isDisabled ? "#fb923c66" : l.color + "66"
                                }`,
                                display: "flex",
                                alignItems: "center",
                                justifyContent: "center",
                                fontSize: "13px",
                                opacity: isDisabled ? 0.5 : 1,
                              }}
                            >
                              {l.icon}
                            </div>
                            <span
                              style={{
                                fontSize: "10.5px",
                                color: isDisabled ? "#fb923c" : l.color,
                                fontWeight: "700",
                                fontFamily: "'Space Mono',monospace",
                              }}
                            >
                              {l.id === 11
                                ? "PERIM"
                                : l.id === 5
                                ? "INT FW"
                                : l.short}
                            </span>
                          </div>
                          <div style={{ flex: 1 }}>
                            <div
                              style={{
                                display: "flex",
                                alignItems: "center",
                                gap: "6px",
                                flexWrap: "wrap",
                              }}
                            >
                              <span
                                style={{
                                  fontSize: "10.5px",
                                  fontWeight: "700",
                                  color: sc,
                                  fontFamily: "'Space Mono',monospace",
                                }}
                              >
                                {si}
                              </span>
                              <span
                                style={{
                                  fontSize: "9px",
                                  color: "#7878a0",
                                  fontFamily: "'Space Mono',monospace",
                                }}
                              >
                                {Math.round(s.passProb * 100)}% pass-through
                              </span>
                              {s.wifChanged && (
                                <span
                                  style={{
                                    fontSize: "10px",
                                    color: "#fb923c",
                                    background: "rgba(251,146,60,.12)",
                                    padding: "1px 6px",
                                    borderRadius: "3px",
                                    border: "1px solid #fb923c44",
                                  }}
                                >
                                  was BLOCKED — now bypassed
                                </span>
                              )}
                              {isDisabled && !s.wifChanged && (
                                <span
                                  style={{
                                    fontSize: "10px",
                                    color: "#fb923c88",
                                  }}
                                >
                                  layer disabled
                                </span>
                              )}
                            </div>
                            <div
                              style={{
                                color: isActive ? "#e8e8f0" : "#a8a8c0",
                                fontSize: "11px",
                                lineHeight: "1.55",
                                marginTop: "2px",
                                fontFamily: "'Inter',sans-serif",
                              }}
                            >
                              {s.how}
                            </div>
                          </div>
                        </div>
                      );
                    })}
                    {apStep === apPath.steps.length - 1 &&
                      !apPlaying &&
                      (() => {
                        const blocked = apStepsEff.filter(
                          (s) => s.result === "blocked"
                        ).length;
                        const bypassed = apStepsEff.filter(
                          (s) => s.result === "bypassed"
                        ).length;
                        const slowed = apStepsEff.filter(
                          (s) => s.result === "slowed"
                        ).length;
                        const reached =
                          apStepsEff[apStepsEff.length - 1]?.id === 0;
                        const wifImpact = apStepsEff.filter(
                          (s) => s.wifChanged
                        ).length;
                        const finalP = cumulativeSuccess(apStepsEff.length - 1);
                        const finalPct = Math.round(finalP * 100);
                        const fc = successColor(finalP);
                        return (
                          <div
                            style={{
                              marginTop: "10px",
                              padding: "10px 12px",
                              borderRadius: "8px",
                              background: reached
                                ? "rgba(239,68,68,.08)"
                                : "rgba(34,197,94,.08)",
                              border: `1px solid ${
                                reached ? "#ef444444" : "#22c55e44"
                              }`,
                            }}
                          >
                            <div
                              style={{
                                fontFamily: "'Rajdhani',sans-serif",
                                fontWeight: 800,
                                fontSize: "14px",
                                color: reached ? "#ef4444" : "#22c55e",
                                marginBottom: "4px",
                              }}
                            >
                              {reached ? "DATA REACHED" : "ATTACK STOPPED"}
                            </div>
                            <div
                              style={{
                                display: "flex",
                                gap: "14px",
                                fontSize: "10.5px",
                                marginBottom: "8px",
                              }}
                            >
                              <span style={{ color: "#22c55e" }}>
                                {blocked} blocked
                              </span>
                              <span style={{ color: "#f59e0b" }}>
                                {slowed} slowed
                              </span>
                              <span style={{ color: "#ef4444" }}>
                                {bypassed} bypassed
                              </span>
                            </div>
                            {/* Final probability */}
                            <div
                              style={{
                                display: "flex",
                                alignItems: "center",
                                gap: "8px",
                                padding: "8px 10px",
                                borderRadius: "6px",
                                background: `${fc}12`,
                                border: `1px solid ${fc}33`,
                              }}
                            >
                              <span
                                style={{
                                  fontSize: "22px",
                                  fontWeight: "700",
                                  color: fc,
                                  fontFamily: "'Rajdhani',sans-serif",
                                }}
                              >
                                {finalPct < 1 ? "<1" : finalPct}%
                              </span>
                              <div>
                                <div
                                  style={{
                                    fontSize: "11px",
                                    color: fc,
                                    fontWeight: "600",
                                    fontFamily: "'Inter',sans-serif",
                                  }}
                                >
                                  end-to-end attack success probability
                                </div>
                                <div
                                  style={{
                                    fontSize: "9.5px",
                                    color: "#a8a8c0",
                                    fontFamily: "'Inter',sans-serif",
                                  }}
                                >
                                  {finalP >= 0.5
                                    ? "High risk — defence-in-depth is failing on this path"
                                    : finalP >= 0.2
                                    ? "Moderate risk — one strong control would help"
                                    : finalP >= 0.05
                                    ? "Low risk — layers are doing their job"
                                    : "Very low risk — strong defence-in-depth"}
                                </div>
                              </div>
                            </div>
                            {wifImpact > 0 && (
                              <div
                                style={{
                                  marginTop: "6px",
                                  fontSize: "10.5px",
                                  color: "#fb923c",
                                  borderTop: "1px solid #fb923c22",
                                  paddingTop: "6px",
                                }}
                              >
                                What If: {wifImpact} layer
                                {wifImpact > 1 ? "s" : ""} disabled —{" "}
                                {wifImpact} control{wifImpact > 1 ? "s" : ""}{" "}
                                removed from your defence
                              </div>
                            )}
                          </div>
                        );
                      })()}
                  </div>
                )}
                {apSubTab === "cases" && apPath.cases && (
                  <div
                    style={{
                      display: "flex",
                      flexDirection: "column",
                      gap: "10px",
                    }}
                  >
                    {apPath.cases.map((c) => (
                      <div
                        key={c.name}
                        style={{
                          borderRadius: "8px",
                          overflow: "hidden",
                          border: `1px solid ${apPath.color}33`,
                          background: "rgba(255,255,255,.025)",
                        }}
                      >
                        <div
                          style={{
                            padding: "8px 12px",
                            background: `${apPath.color}14`,
                            borderBottom: `1px solid ${apPath.color}22`,
                            display: "flex",
                            alignItems: "center",
                            gap: "8px",
                            flexWrap: "wrap",
                          }}
                        >
                          <div>
                            <span
                              style={{
                                fontFamily: "'Rajdhani',sans-serif",
                                fontWeight: 800,
                                fontSize: "15px",
                                color: apPath.color,
                              }}
                            >
                              {c.name}
                            </span>
                            <span
                              style={{
                                color: "#8080a0",
                                fontSize: "10.5px",
                                marginLeft: "8px",
                              }}
                            >
                              {c.year}
                            </span>
                          </div>
                          <span
                            style={{
                              marginLeft: "auto",
                              background: "rgba(239,68,68,.15)",
                              color: "#ef4444",
                              fontSize: "10px",
                              padding: "2px 7px",
                              borderRadius: "4px",
                              border: "1px solid #ef444433",
                            }}
                          >
                            {c.damage}
                          </span>
                        </div>
                        <div
                          style={{
                            padding: "10px 12px",
                            display: "flex",
                            flexDirection: "column",
                            gap: "8px",
                          }}
                        >
                          <div>
                            {sectionLabel("TARGET", "#404060")}
                            <div
                              style={{
                                color: "#d0d0dc",
                                fontSize: "11px",
                                fontFamily: "'Inter',sans-serif",
                              }}
                            >
                              {c.org}
                            </div>
                          </div>
                          <div>
                            {sectionLabel("WHAT HAPPENED", "#404060")}
                            <div
                              style={{
                                color: "#c8c8d4",
                                fontSize: "11px",
                                lineHeight: "1.6",
                                fontFamily: "'Inter',sans-serif",
                              }}
                            >
                              {c.what}
                            </div>
                          </div>
                          <div>
                            {sectionLabel("LAYERS THAT FAILED", "#ef444488")}
                            <div
                              style={{
                                color: "#e08080",
                                fontSize: "11px",
                                lineHeight: "1.6",
                                fontFamily: "'Inter',sans-serif",
                              }}
                            >
                              {c.missed}
                            </div>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Compare Panel */}
          {cmpMode &&
            cmpA !== null &&
            cmpB !== null &&
            (() => {
              const LA = LAYERS[cmpA],
                LB = LAYERS[cmpB];
              const CMP_TABS = [
                "overview",
                "enc",
                "mitre",
                "compliance",
                "maturity",
                "attacks",
              ];
              const CMP_LABELS = {
                overview: "General",
                enc: "Encryption",
                mitre: "MITRE",
                compliance: "Compliance",
                maturity: "Maturity",
                attacks: "Attacks",
              };
              return (
                <div
                  style={{
                    margin: "4px 8px 0",
                    borderRadius: "10px",
                    border: "1px solid #06b6d433",
                    borderLeft: "3px solid #06b6d4",
                    background: "rgba(6,182,212,.03)",
                    overflow: "hidden",
                  }}
                >
                  <div
                    style={{
                      padding: "10px 14px 8px",
                      borderBottom: "1px solid rgba(255,255,255,.05)",
                    }}
                  >
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "8px",
                        marginBottom: "8px",
                      }}
                    >
                      <div
                        style={{
                          fontFamily: "'Rajdhani',sans-serif",
                          fontWeight: 800,
                          fontSize: "15px",
                          color: "#06b6d4",
                          flex: 1,
                        }}
                      >
                        {LA.short} vs {LB.short}
                      </div>
                      <button
                        onClick={() => {
                          setCmpA(null);
                          setCmpB(null);
                        }}
                        style={{
                          background: "transparent",
                          border: "1px solid #333",
                          color: "#9090a8",
                          borderRadius: "5px",
                          padding: "2px 8px",
                          cursor: "pointer",
                          fontSize: "11px",
                          fontFamily: "inherit",
                        }}
                      >
                        X
                      </button>
                    </div>
                    <div
                      style={{
                        display: "flex",
                        gap: "12px",
                        marginBottom: "8px",
                      }}
                    >
                      {[LA, LB].map((L) => (
                        <div key={L.id} style={{ flex: 1 }}>
                          <div
                            style={{
                              display: "flex",
                              justifyContent: "space-between",
                              marginBottom: "3px",
                              fontSize: "10.5px",
                            }}
                          >
                            <span style={{ color: L.color, fontWeight: "700" }}>
                              {L.short}
                            </span>
                            <span style={{ color: coverageColor(L.coverage) }}>
                              {L.coverage}%
                            </span>
                          </div>
                          <div
                            style={{
                              height: 6,
                              borderRadius: 3,
                              background: "#151525",
                            }}
                          >
                            <div
                              style={{
                                height: "100%",
                                borderRadius: 3,
                                width: `${L.coverage}%`,
                                background: coverageColor(L.coverage),
                                transition: "width .4s",
                              }}
                            />
                          </div>
                          <div
                            style={{
                              fontSize: "10px",
                              color: "#8080a0",
                              marginTop: "2px",
                            }}
                          >
                            industry coverage
                          </div>
                        </div>
                      ))}
                    </div>
                    <div
                      style={{ display: "flex", gap: "4px", flexWrap: "wrap" }}
                    >
                      {CMP_TABS.map((t) => (
                        <button
                          key={t}
                          onClick={() => setCmpTab(t)}
                          style={{
                            background:
                              cmpTab === t
                                ? "rgba(6,182,212,.15)"
                                : "transparent",
                            border: `1px solid ${
                              cmpTab === t ? "#06b6d4" : "#252535"
                            }`,
                            color: cmpTab === t ? "#06b6d4" : "#505070",
                            borderRadius: "5px",
                            padding: "4px 10px",
                            cursor: "pointer",
                            fontSize: "10.5px",
                            fontFamily: "'Space Mono',monospace",
                            transition: "all .18s",
                          }}
                        >
                          {CMP_LABELS[t]}
                        </button>
                      ))}
                    </div>
                  </div>

                  {cmpTab === "attacks" ? (
                    (() => {
                      const pathsA = ATTACK_PATHS.filter((ap) =>
                        ap.steps.some((s) => s.id === LA.id)
                      );
                      const pathsB = ATTACK_PATHS.filter((ap) =>
                        ap.steps.some((s) => s.id === LB.id)
                      );
                      const pathsBoth = ATTACK_PATHS.filter(
                        (ap) =>
                          ap.steps.some((s) => s.id === LA.id) &&
                          ap.steps.some((s) => s.id === LB.id)
                      );
                      const pathsOnlyA = pathsA.filter(
                        (ap) => !pathsB.some((pb) => pb.id === ap.id)
                      );
                      const pathsOnlyB = pathsB.filter(
                        (ap) => !pathsA.some((pa) => pa.id === ap.id)
                      );
                      return (
                        <div style={{ padding: "10px 14px" }}>
                          {pathsBoth.length > 0 && (
                            <div style={{ marginBottom: "14px" }}>
                              <div
                                style={{
                                  fontSize: "10px",
                                  color: "#06b6d4aa",
                                  letterSpacing: "2px",
                                  marginBottom: "6px",
                                  fontFamily: "'Space Mono',monospace",
                                }}
                              >
                                ATTACK PATHS CROSSING BOTH LAYERS
                              </div>
                              {pathsBoth.map((ap) => (
                                <div
                                  key={ap.id}
                                  style={{
                                    marginBottom: "10px",
                                    borderRadius: "8px",
                                    overflow: "hidden",
                                    border: `1px solid ${ap.color}33`,
                                  }}
                                >
                                  <div
                                    style={{
                                      padding: "6px 10px",
                                      background: `${ap.color}12`,
                                      borderBottom: `1px solid ${ap.color}22`,
                                      display: "flex",
                                      alignItems: "center",
                                      gap: "6px",
                                    }}
                                  >
                                    <span style={{ fontSize: "14px" }}>
                                      {ap.icon}
                                    </span>
                                    <span
                                      style={{
                                        fontFamily: "'Rajdhani',sans-serif",
                                        fontWeight: 800,
                                        fontSize: "13px",
                                        color: ap.color,
                                      }}
                                    >
                                      {ap.label}
                                    </span>
                                  </div>
                                  <div
                                    style={{
                                      display: "grid",
                                      gridTemplateColumns: "1fr 1fr",
                                    }}
                                  >
                                    {[LA, LB].map((L, i) => (
                                      <div
                                        key={L.id}
                                        style={{
                                          padding: "8px 10px",
                                          borderRight:
                                            i === 0
                                              ? "1px solid #151525"
                                              : "none",
                                        }}
                                      >
                                        <div
                                          style={{
                                            fontSize: "10px",
                                            color: L.color,
                                            fontWeight: "700",
                                            marginBottom: "5px",
                                            fontFamily:
                                              "'Space Mono',monospace",
                                          }}
                                        >
                                          {L.short}
                                        </div>
                                        {renderPathCard(
                                          ap,
                                          L.id,
                                          true,
                                          `${ap.id}-${L.id}`
                                        )}
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              ))}
                            </div>
                          )}
                          <div
                            style={{
                              display: "grid",
                              gridTemplateColumns: "1fr 1fr",
                              gap: "10px",
                            }}
                          >
                            {[
                              { L: LA, paths: pathsOnlyA },
                              { L: LB, paths: pathsOnlyB },
                            ].map(({ L, paths }) => (
                              <div key={L.id}>
                                <div
                                  style={{
                                    fontSize: "10px",
                                    color: L.color + "aa",
                                    letterSpacing: "2px",
                                    marginBottom: "6px",
                                    fontFamily: "'Space Mono',monospace",
                                  }}
                                >
                                  UNIQUE TO {L.short}
                                </div>
                                {paths.length === 0 ? (
                                  <div
                                    style={{
                                      fontSize: "10.5px",
                                      color: "#303040",
                                      fontStyle: "italic",
                                    }}
                                  >
                                    All paths shared
                                  </div>
                                ) : (
                                  paths.map((ap) =>
                                    renderPathCard(
                                      ap,
                                      L.id,
                                      false,
                                      `${ap.id}-${L.id}-u`
                                    )
                                  )
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      );
                    })()
                  ) : (
                    <div
                      style={{
                        display: "grid",
                        gridTemplateColumns: "1fr 1fr",
                      }}
                    >
                      {[LA, LB].map((L, i) => (
                        <div
                          key={L.id}
                          style={{
                            borderRight: i === 0 ? "1px solid #151525" : "none",
                          }}
                        >
                          {colHead(L)}
                          <div
                            style={{
                              padding: "10px 12px",
                              display: "flex",
                              flexDirection: "column",
                              gap: "12px",
                            }}
                          >
                            {cmpTab === "overview" && (
                              <>
                                <div
                                  style={{
                                    fontSize: "11.5px",
                                    color: "#c8c8d4",
                                    lineHeight: "1.6",
                                    fontFamily: "'Inter',sans-serif",
                                  }}
                                >
                                  {L.desc}
                                </div>
                                <div>
                                  {sectionLabel("Technologies", "#aaa")}
                                  {tags(L.items)}
                                </div>
                                <div>
                                  {sectionLabel("Tools", "#60a8d0")}
                                  {tags(L.tools, "ttag")}
                                </div>
                              </>
                            )}
                            {cmpTab === "enc" && (
                              <>
                                <div>
                                  {sectionLabel("Encryption", "#d4a830")}
                                  {tags(L.enc, "etag")}
                                </div>
                                {L.zt && (
                                  <div
                                    style={{
                                      display: "flex",
                                      gap: "6px",
                                      paddingTop: "8px",
                                      borderTop: "1px solid #0d0d1a",
                                    }}
                                  >
                                    <span
                                      style={{
                                        fontSize: "12px",
                                        flexShrink: 0,
                                      }}
                                    >
                                      ZT
                                    </span>
                                    <div
                                      style={{
                                        color: "#7030a0",
                                        fontSize: "10px",
                                        lineHeight: "1.5",
                                      }}
                                    >
                                      {L.zt}
                                    </div>
                                  </div>
                                )}
                              </>
                            )}
                            {cmpTab === "mitre" &&
                              (() => {
                                const other = L.id === LA.id ? LB : LA;
                                const otherIds =
                                  other.mitre?.map((x) => x[0]) || [];
                                return L.mitre?.map(([id, name]) => {
                                  const unique = !otherIds.includes(id);
                                  return (
                                    <div
                                      key={id}
                                      style={{
                                        display: "flex",
                                        gap: "6px",
                                        alignItems: "flex-start",
                                        background: unique
                                          ? "rgba(6,182,212,.06)"
                                          : "transparent",
                                        borderRadius: 4,
                                        padding: "3px 4px",
                                      }}
                                    >
                                      <span
                                        style={{
                                          color: unique ? "#06b6d4" : "#c090ff",
                                          fontWeight: "700",
                                          fontFamily: "'Space Mono',monospace",
                                          fontSize: "10px",
                                          whiteSpace: "nowrap",
                                          flexShrink: 0,
                                        }}
                                      >
                                        {id}
                                      </span>
                                      <span
                                        style={{
                                          color: "#b0b0c0",
                                          fontSize: "10.5px",
                                        }}
                                      >
                                        {name}
                                      </span>
                                    </div>
                                  );
                                });
                              })()}
                            {cmpTab === "compliance" &&
                              (() => {
                                const other = L.id === LA.id ? LB : LA;
                                const otherFws = new Set(
                                  other.compliance?.map(([fw]) => fw) || []
                                );
                                return L.compliance?.map(([fw, req]) => {
                                  const c = COMPLIANCE_COLORS[fw] || "#666";
                                  const shared = otherFws.has(fw);
                                  return (
                                    <div
                                      key={fw + req}
                                      style={{
                                        display: "flex",
                                        gap: "6px",
                                        alignItems: "flex-start",
                                        background: shared
                                          ? "rgba(6,182,212,.06)"
                                          : "rgba(255,255,255,.025)",
                                        borderRadius: "5px",
                                        padding: "5px 7px",
                                        border: `1px solid ${
                                          shared ? "#06b6d433" : c + "22"
                                        }`,
                                      }}
                                    >
                                      <span
                                        style={{
                                          background: `${c}22`,
                                          color: c,
                                          fontSize: "10.5px",
                                          fontWeight: "700",
                                          padding: "2px 5px",
                                          borderRadius: "3px",
                                          whiteSpace: "nowrap",
                                          flexShrink: 0,
                                          lineHeight: "1.6",
                                        }}
                                      >
                                        {fw}
                                      </span>
                                      <span
                                        style={{
                                          color: "#b0b0c0",
                                          fontSize: "10.5px",
                                          lineHeight: "1.4",
                                        }}
                                      >
                                        {req}
                                      </span>
                                    </div>
                                  );
                                });
                              })()}
                            {cmpTab === "maturity" &&
                              L.maturity?.levels.map(([name, desc], i) => {
                                const isTyp = i === L.maturity.typical,
                                  isPast = i < L.maturity.typical;
                                const c = MATURITY_COLORS[i];
                                return (
                                  <div
                                    key={i}
                                    style={{
                                      display: "flex",
                                      gap: "7px",
                                      alignItems: "flex-start",
                                      padding: "6px 8px",
                                      borderRadius: "5px",
                                      background: isTyp
                                        ? `${c}18`
                                        : "rgba(255,255,255,.02)",
                                      border: `1px solid ${
                                        isTyp
                                          ? c
                                          : isPast
                                          ? c + "33"
                                          : "#151525"
                                      }`,
                                      opacity: isPast ? 0.5 : 1,
                                    }}
                                  >
                                    <div
                                      style={{
                                        width: 18,
                                        height: 18,
                                        borderRadius: "50%",
                                        flexShrink: 0,
                                        background:
                                          isPast || isTyp ? c : "#1a1a2e",
                                        border: `2px solid ${c}`,
                                        display: "flex",
                                        alignItems: "center",
                                        justifyContent: "center",
                                        fontSize: "10px",
                                        color: isPast || isTyp ? "#000" : c,
                                        fontWeight: "700",
                                      }}
                                    >
                                      {i + 1}
                                    </div>
                                    <div>
                                      <div
                                        style={{
                                          display: "flex",
                                          gap: "4px",
                                          alignItems: "center",
                                          marginBottom: "2px",
                                        }}
                                      >
                                        <span
                                          style={{
                                            fontSize: "10px",
                                            fontWeight: "700",
                                            color: c,
                                            fontFamily: "'Rajdhani',sans-serif",
                                          }}
                                        >
                                          {MATURITY_LABELS[i]}
                                        </span>
                                        {isTyp && (
                                          <span
                                            style={{
                                              fontSize: "10.5px",
                                              color: c,
                                              background: `${c}22`,
                                              padding: "1px 4px",
                                              borderRadius: "3px",
                                              border: `1px solid ${c}44`,
                                            }}
                                          >
                                            typical
                                          </span>
                                        )}
                                      </div>
                                      <div
                                        style={{
                                          color: "#9090a8",
                                          fontSize: "10.5px",
                                          lineHeight: "1.4",
                                        }}
                                      >
                                        {desc}
                                      </div>
                                    </div>
                                  </div>
                                );
                              })}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                  {cmpTab === "compliance" &&
                    (() => {
                      const aFws = new Set(
                        LA.compliance?.map(([fw]) => fw) || []
                      );
                      const bFws = new Set(
                        LB.compliance?.map(([fw]) => fw) || []
                      );
                      const shared = [...aFws].filter((fw) => bFws.has(fw));
                      if (!shared.length) return null;
                      return (
                        <div
                          style={{
                            padding: "8px 14px",
                            borderTop: "1px solid #151525",
                            fontSize: "10.5px",
                            color: "#06b6d488",
                          }}
                        >
                          Shared frameworks: {shared.join(", ")}
                        </div>
                      );
                    })()}
                </div>
              );
            })()}

          {/* ── ROADMAP PANEL ── */}
          {rmMode && (
            <div
              style={{
                margin: "4px 8px 0",
                borderRadius: "10px",
                border: "1px solid #a78bfa44",
                borderLeft: "3px solid #a78bfa",
                background: "rgba(167,139,250,.03)",
                overflow: "hidden",
              }}
            >
              {/* Header */}
              <div
                style={{
                  padding: "12px 14px 10px",
                  borderBottom: "1px solid rgba(255,255,255,.05)",
                }}
              >
                <div
                  style={{
                    fontFamily: "'Rajdhani',sans-serif",
                    fontWeight: 800,
                    fontSize: "16px",
                    color: "#a78bfa",
                    letterSpacing: "1px",
                    marginBottom: "4px",
                  }}
                >
                  Security Roadmap
                </div>
                <div
                  style={{
                    color: "#9090b0",
                    fontSize: "10.5px",
                    lineHeight: "1.5",
                    marginBottom: "10px",
                  }}
                >
                  Check the layers you already have. We'll build a prioritised
                  plan for the rest.
                </div>

                {/* "What do you have?" checklist */}
                <div style={{ display: "flex", flexWrap: "wrap", gap: "5px" }}>
                  {LAYERS.map((l) => {
                    const have = rmHave.has(l.id);
                    return (
                      <div
                        key={l.id}
                        onClick={() =>
                          setRmHave((s) => {
                            const n = new Set(s);
                            have ? n.delete(l.id) : n.add(l.id);
                            return n;
                          })
                        }
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: "5px",
                          padding: "4px 10px",
                          borderRadius: "20px",
                          cursor: "pointer",
                          border: `1px solid ${
                            have ? PHASE_COLORS.done : "#252535"
                          }`,
                          background: have
                            ? "rgba(6,182,212,.15)"
                            : "rgba(255,255,255,.02)",
                          color: have ? PHASE_COLORS.done : "#404060",
                          fontSize: "10px",
                          transition: "all .18s",
                        }}
                      >
                        <div
                          style={{
                            width: 6,
                            height: 6,
                            borderRadius: "50%",
                            background: have ? PHASE_COLORS.done : "#252535",
                            flexShrink: 0,
                          }}
                        />
                        {l.id === 11
                          ? "PERIM"
                          : l.id === 5
                          ? "INT FW"
                          : l.short}
                      </div>
                    );
                  })}
                </div>

                {/* Coverage summary */}
                {rmHave.size > 0 && (
                  <div
                    style={{
                      marginTop: "10px",
                      display: "flex",
                      gap: "12px",
                      fontSize: "10.5px",
                      color: "#9090b0",
                    }}
                  >
                    <span style={{ color: PHASE_COLORS.done }}>
                      {rmHave.size} covered
                    </span>
                    <span style={{ color: PHASE_COLORS[1] }}>
                      {
                        LAYERS.filter(
                          (l) => !rmHave.has(l.id) && ROADMAP[l.id]?.phase === 1
                        ).length
                      }{" "}
                      quick wins left
                    </span>
                    <span>
                      {LAYERS.filter((l) => !rmHave.has(l.id)).length} total
                      gaps
                    </span>
                  </div>
                )}
              </div>

              {/* Roadmap phases */}
              {rmPlan && (
                <div
                  style={{
                    padding: "12px 14px",
                    display: "flex",
                    flexDirection: "column",
                    gap: "16px",
                  }}
                >
                  {[1, 2, 3].map((phase) => {
                    const layers = rmPlan[phase];
                    if (!layers.length) return null;
                    const phaseColor = PHASE_COLORS[phase];
                    return (
                      <div key={phase}>
                        {/* Phase header */}
                        <div
                          style={{
                            display: "flex",
                            alignItems: "center",
                            gap: "8px",
                            marginBottom: "8px",
                          }}
                        >
                          <div
                            style={{
                              width: 24,
                              height: 24,
                              borderRadius: "50%",
                              background: `${phaseColor}22`,
                              border: `2px solid ${phaseColor}`,
                              display: "flex",
                              alignItems: "center",
                              justifyContent: "center",
                              fontSize: "11px",
                              fontWeight: "700",
                              color: phaseColor,
                              flexShrink: 0,
                            }}
                          >
                            {phase}
                          </div>
                          <div
                            style={{
                              fontFamily: "'Rajdhani',sans-serif",
                              fontWeight: 800,
                              fontSize: "13px",
                              color: phaseColor,
                              letterSpacing: "1px",
                            }}
                          >
                            {PHASE_LABELS[phase]}
                          </div>
                        </div>

                        {/* Layer cards in phase */}
                        <div
                          style={{
                            display: "flex",
                            flexDirection: "column",
                            gap: "8px",
                          }}
                        >
                          {layers.map((l, idx) => {
                            const rm = ROADMAP[l.id];
                            const prereqsMissing = rm.prereqs.filter(
                              (id) => !rmHave.has(id)
                            );
                            const blocked = prereqsMissing.length > 0;
                            return (
                              <div
                                key={l.id}
                                style={{
                                  borderRadius: "8px",
                                  border: `1px solid ${
                                    blocked ? "#252535" : phaseColor + "44"
                                  }`,
                                  background: blocked
                                    ? "rgba(255,255,255,.015)"
                                    : `${phaseColor}08`,
                                  opacity: blocked ? 0.55 : 1,
                                  overflow: "hidden",
                                }}
                              >
                                {/* Card header */}
                                <div
                                  style={{
                                    padding: "8px 12px",
                                    borderBottom: `1px solid ${phaseColor}22`,
                                    display: "flex",
                                    alignItems: "center",
                                    gap: "8px",
                                  }}
                                >
                                  <span style={{ fontSize: "16px" }}>
                                    {l.icon}
                                  </span>
                                  <div style={{ flex: 1 }}>
                                    <div
                                      style={{
                                        display: "flex",
                                        alignItems: "center",
                                        gap: "6px",
                                        flexWrap: "wrap",
                                      }}
                                    >
                                      <span
                                        style={{
                                          fontFamily: "'Rajdhani',sans-serif",
                                          fontWeight: 800,
                                          fontSize: "13px",
                                          color: phaseColor,
                                          letterSpacing: ".5px",
                                        }}
                                      >
                                        {l.id === 11
                                          ? "Perimeter FW"
                                          : l.id === 5
                                          ? "Internal FW"
                                          : l.short}
                                      </span>
                                      {idx === 0 && phase === 1 && !blocked && (
                                        <span
                                          style={{
                                            background: `${phaseColor}22`,
                                            color: phaseColor,
                                            fontSize: "10.5px",
                                            padding: "1px 6px",
                                            borderRadius: "3px",
                                            border: `1px solid ${phaseColor}44`,
                                            letterSpacing: "1px",
                                          }}
                                        >
                                          START HERE
                                        </span>
                                      )}
                                      {blocked && (
                                        <span
                                          style={{
                                            color: "#9090a8",
                                            fontSize: "10.5px",
                                            letterSpacing: "1px",
                                          }}
                                        >
                                          needs:{" "}
                                          {prereqsMissing
                                            .map((id) => LAYERS[id].short)
                                            .join(", ")}
                                        </span>
                                      )}
                                    </div>
                                    <div
                                      style={{
                                        color: "#8080a0",
                                        fontSize: "10px",
                                        marginTop: "1px",
                                      }}
                                    >
                                      {l.sub}
                                    </div>
                                  </div>
                                  {/* Cost + complexity + time */}
                                  <div
                                    style={{
                                      display: "flex",
                                      flexDirection: "column",
                                      alignItems: "flex-end",
                                      gap: "2px",
                                      flexShrink: 0,
                                    }}
                                  >
                                    <div
                                      style={{
                                        fontSize: "10px",
                                        color: "#d8d8e0",
                                      }}
                                    >
                                      {rm.timeMonths} months
                                    </div>
                                    <div
                                      style={{ display: "flex", gap: "3px" }}
                                    >
                                      {["cost", "complexity"].map((key) => (
                                        <div
                                          key={key}
                                          style={{
                                            display: "flex",
                                            gap: "1px",
                                          }}
                                        >
                                          {[1, 2, 3, 4, 5].map((i) => (
                                            <div
                                              key={i}
                                              style={{
                                                width: 4,
                                                height: 4,
                                                borderRadius: "1px",
                                                background:
                                                  i <= rm[key]
                                                    ? key === "cost"
                                                      ? "#ef4444"
                                                      : "#f59e0b"
                                                    : "#1a1a2e",
                                              }}
                                            />
                                          ))}
                                        </div>
                                      ))}
                                    </div>
                                    <div
                                      style={{
                                        fontSize: "10.5px",
                                        color: "#9090a8",
                                        display: "flex",
                                        gap: "8px",
                                      }}
                                    >
                                      <span>cost</span>
                                      <span>complexity</span>
                                    </div>
                                  </div>
                                </div>

                                {/* Why + quick wins */}
                                <div style={{ padding: "8px 12px" }}>
                                  <div
                                    style={{
                                      color: "#c4c4d0",
                                      fontSize: "10px",
                                      lineHeight: "1.6",
                                      marginBottom: "8px",
                                    }}
                                  >
                                    {rm.why}
                                  </div>
                                  <div
                                    style={{
                                      fontSize: "10px",
                                      color: phaseColor + "88",
                                      letterSpacing: "1.5px",
                                      marginBottom: "5px",
                                      fontFamily: "'Space Mono',monospace",
                                    }}
                                  >
                                    QUICK WINS
                                  </div>
                                  <div
                                    style={{
                                      display: "flex",
                                      flexDirection: "column",
                                      gap: "4px",
                                    }}
                                  >
                                    {rm.quickWins.map((w, wi) => (
                                      <div
                                        key={wi}
                                        style={{
                                          display: "flex",
                                          gap: "6px",
                                          alignItems: "flex-start",
                                          fontSize: "10px",
                                        }}
                                      >
                                        <span
                                          style={{
                                            color: phaseColor,
                                            flexShrink: 0,
                                            fontSize: "10px",
                                          }}
                                        >
                                          →
                                        </span>
                                        <span
                                          style={{
                                            color: "#c8c8d4",
                                            lineHeight: "1.5",
                                            fontFamily: "'Inter',sans-serif",
                                          }}
                                        >
                                          {w}
                                        </span>
                                      </div>
                                    ))}
                                  </div>

                                  {/* Impact bar */}
                                  <div
                                    style={{
                                      marginTop: "8px",
                                      display: "flex",
                                      alignItems: "center",
                                      gap: "6px",
                                    }}
                                  >
                                    <span
                                      style={{
                                        fontSize: "10px",
                                        color: "#9090a8",
                                        flexShrink: 0,
                                      }}
                                    >
                                      risk reduction
                                    </span>
                                    <div
                                      style={{
                                        flex: 1,
                                        height: 4,
                                        borderRadius: 2,
                                        background: "#151525",
                                      }}
                                    >
                                      <div
                                        style={{
                                          height: "100%",
                                          borderRadius: 2,
                                          width: `${rm.impact * 20}%`,
                                          background: phaseColor,
                                          transition: "width .4s",
                                        }}
                                      />
                                    </div>
                                    <span
                                      style={{
                                        fontSize: "10px",
                                        color: phaseColor,
                                        flexShrink: 0,
                                      }}
                                    >
                                      {rm.impact}/5
                                    </span>
                                  </div>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    );
                  })}

                  {/* Done! */}
                  {LAYERS.every((l) => rmHave.has(l.id)) && (
                    <div
                      style={{
                        textAlign: "center",
                        padding: "20px",
                        color: "#22c55e",
                        fontSize: "14px",
                        fontFamily: "'Rajdhani',sans-serif",
                        fontWeight: 800,
                      }}
                    >
                      All layers covered. You have a mature security posture!
                    </div>
                  )}
                </div>
              )}

              {/* Empty state */}
              {!rmPlan && rmHave.size === 0 && (
                <div
                  style={{
                    padding: "16px 14px",
                    color: "#8080a0",
                    fontSize: "10px",
                    textAlign: "center",
                    lineHeight: "2",
                  }}
                >
                  <div style={{ fontSize: "28px", marginBottom: "8px" }}>🗺</div>
                  Check the layers you already have above
                  <br />
                  to generate your personalised roadmap
                </div>
              )}
            </div>
          )}

          {/* Detail Panel */}
          {panel && (
            <div
              key={String(sel)}
              className="panel"
              style={{
                margin: "4px 8px 14px",
                borderRadius: "10px",
                border: `1px solid ${panel.color}44`,
                borderLeft: `3px solid ${panel.color}`,
                background: "rgba(255,255,255,.022)",
                overflow: "hidden",
              }}
            >
              <div
                style={{
                  padding: "12px 14px 8px",
                  borderBottom: "1px solid rgba(255,255,255,.05)",
                }}
              >
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "9px",
                    flexWrap: "wrap",
                  }}
                >
                  <span style={{ fontSize: "20px" }}>{panel.icon}</span>
                  <div style={{ flex: 1 }}>
                    <div
                      style={{
                        fontFamily: "'Rajdhani',sans-serif",
                        fontWeight: 800,
                        fontSize: "17px",
                        color: panel.color,
                        letterSpacing: "1px",
                      }}
                    >
                      {panel.label || panel.short}
                    </div>
                    <div
                      style={{
                        color: "#9090b0",
                        fontSize: "10px",
                        letterSpacing: "1.5px",
                      }}
                    >
                      {(panel.sub || "").toUpperCase()}
                    </div>
                  </div>
                  {"badge" in panel && (
                    <span
                      style={{
                        background: `${panel.color}16`,
                        color: panel.color,
                        fontSize: "10px",
                        padding: "2px 7px",
                        borderRadius: "4px",
                        border: `1px solid ${panel.color}30`,
                      }}
                    >
                      {panel.badge}
                    </span>
                  )}
                  {selThreat && (
                    <span
                      style={{
                        fontSize: "10.5px",
                        color: panel.color + "88",
                        padding: "2px 7px",
                        border: `1px solid ${panel.color}30`,
                        borderRadius: "4px",
                      }}
                    >
                      L{panel.targets.join(", L")}
                    </span>
                  )}
                  {selLayer && showHeat && (
                    <div
                      style={{
                        display: "flex",
                        flexDirection: "column",
                        alignItems: "center",
                        padding: "3px 8px",
                        borderRadius: "6px",
                        background: `${coverageColor(panel.coverage)}18`,
                        border: `1px solid ${coverageColor(panel.coverage)}44`,
                      }}
                    >
                      <div
                        style={{
                          fontSize: "14px",
                          fontWeight: "700",
                          color: coverageColor(panel.coverage),
                          fontFamily: "'Rajdhani',sans-serif",
                        }}
                      >
                        {panel.coverage}%
                      </div>
                      <div
                        style={{
                          fontSize: "10.5px",
                          color:
                            panel.coverage < 45 ? "#ef444499" : "#22c55e99",
                        }}
                      >
                        {panel.coverage < 45
                          ? "most miss this"
                          : panel.coverage < 70
                          ? "partial"
                          : "widely deployed"}
                      </div>
                    </div>
                  )}
                  <button
                    onClick={() => setSel(null)}
                    style={{
                      background: "transparent",
                      border: "1px solid #333",
                      color: "#9090a8",
                      borderRadius: "5px",
                      padding: "2px 8px",
                      cursor: "pointer",
                      fontSize: "11px",
                      fontFamily: "inherit",
                    }}
                  >
                    X
                  </button>
                </div>
                {!selThreat && (
                  <div
                    style={{
                      display: "flex",
                      gap: "4px",
                      marginTop: "8px",
                      flexWrap: "wrap",
                    }}
                  >
                    {[
                      "overview",
                      "attacks",
                      "mitre",
                      "compliance",
                      "maturity",
                      "vendors",
                    ]
                      .filter((t) => {
                        if (t === "mitre") return !!panel.mitre;
                        if (t === "compliance") return !!panel.compliance;
                        if (t === "attacks") return !!panel.attacks;
                        if (t === "maturity") return !!panel.maturity;
                        if (t === "vendors")
                          return !!(
                            VENDORS[selLayer?.id] || VENDORS[selSat?.id]
                          );
                        return true;
                      })
                      .map((t) => (
                        <button
                          key={t}
                          className="tab-btn"
                          onClick={() => setTab(t)}
                          aria-pressed={tab === t}
                          style={{
                            background:
                              tab === t ? `${panel.color}22` : "transparent",
                            borderColor: tab === t ? panel.color : "#303045",
                            color: tab === t ? panel.color : "#505070",
                          }}
                        >
                          {
                            {
                              overview: "Overview",
                              attacks: "Attacks",
                              mitre: "MITRE",
                              compliance: "Compliance",
                              maturity: "Maturity",
                              vendors: "Vendors",
                            }[t]
                          }
                        </button>
                      ))}
                  </div>
                )}
              </div>
              <div style={{ padding: "14px 16px" }}>
                <div
                  style={{
                    color: "#d8d8e0",
                    fontSize: "13px",
                    lineHeight: "1.7",
                    marginBottom: "14px",
                    fontFamily: "'Inter',sans-serif",
                  }}
                >
                  {panel.desc}
                </div>
                {selThreat && (
                  <div
                    style={{
                      display: "flex",
                      flexDirection: "column",
                      gap: "14px",
                    }}
                  >
                    <div>
                      {sectionLabel("Tactics", "#cc6060")}
                      <div
                        style={{
                          display: "flex",
                          flexWrap: "wrap",
                          gap: "5px",
                        }}
                      >
                        {panel.tactics.map((t, i) => (
                          <span
                            key={i}
                            className="atag"
                            style={{
                              whiteSpace: "normal",
                              wordBreak: "break-word",
                            }}
                          >
                            {t}
                          </span>
                        ))}
                      </div>
                    </div>
                    <div>
                      {sectionLabel("Known Groups", "#777")}
                      <div
                        style={{
                          display: "flex",
                          flexWrap: "wrap",
                          gap: "5px",
                        }}
                      >
                        {panel.examples.map((e, i) => (
                          <span
                            key={i}
                            className="tag"
                            style={{
                              whiteSpace: "normal",
                              wordBreak: "break-word",
                            }}
                          >
                            {e}
                          </span>
                        ))}
                      </div>
                    </div>
                    <div>
                      {sectionLabel("Targeted Layers", "#777")}
                      <div
                        style={{
                          display: "flex",
                          flexWrap: "wrap",
                          gap: "5px",
                        }}
                      >
                        {panel.targets.map((id) => {
                          const l = LAYERS[id];
                          return (
                            <span
                              key={id}
                              style={{
                                background: `${l.color}22`,
                                border: `1px solid ${l.color}55`,
                                borderRadius: "4px",
                                padding: "4px 9px",
                                fontSize: "10px",
                                color: l.color,
                              }}
                            >
                              {l.short}
                            </span>
                          );
                        })}
                      </div>
                    </div>
                  </div>
                )}
                {!selThreat && tab === "overview" && (
                  <div
                    style={{
                      display: "flex",
                      flexDirection: "column",
                      gap: "16px",
                    }}
                  >
                    <div>
                      {sectionLabel("Technologies", "#aaa")}
                      <div
                        style={{
                          display: "flex",
                          flexWrap: "wrap",
                          gap: "5px",
                        }}
                      >
                        {panel.items?.map((x, i) => (
                          <span
                            key={i}
                            className="tag"
                            style={{
                              whiteSpace: "normal",
                              wordBreak: "break-word",
                            }}
                          >
                            {x}
                          </span>
                        ))}
                      </div>
                    </div>
                    {panel.enc && (
                      <div>
                        {sectionLabel("Encryption", "#d4a830")}
                        <div
                          style={{
                            display: "flex",
                            flexWrap: "wrap",
                            gap: "5px",
                          }}
                        >
                          {panel.enc.map((x, i) => (
                            <span
                              key={i}
                              className="etag"
                              style={{
                                whiteSpace: "normal",
                                wordBreak: "break-word",
                              }}
                            >
                              {x}
                            </span>
                          ))}
                        </div>
                        {selLayer &&
                          (() => {
                            const q = ENC_TYPES[getEncType(selLayer)];
                            if (!q.qNote) return null;
                            return (
                              <div
                                style={{
                                  marginTop: "8px",
                                  display: "flex",
                                  gap: "8px",
                                  alignItems: "flex-start",
                                  padding: "8px 10px",
                                  borderRadius: "6px",
                                  background: `${QUANTUM_COLORS[q.quantum]}10`,
                                  border: `1px solid ${
                                    QUANTUM_COLORS[q.quantum]
                                  }33`,
                                }}
                              >
                                <div
                                  style={{
                                    width: 9,
                                    height: 9,
                                    borderRadius: "50%",
                                    flexShrink: 0,
                                    marginTop: "3px",
                                    background: QUANTUM_COLORS[q.quantum],
                                  }}
                                />
                                <div>
                                  <span
                                    style={{
                                      fontSize: "10px",
                                      fontWeight: "700",
                                      color: QUANTUM_COLORS[q.quantum],
                                      fontFamily: "'Space Mono',monospace",
                                      letterSpacing: "1px",
                                    }}
                                  >
                                    {QUANTUM_LABELS[q.quantum].toUpperCase()}
                                  </span>
                                  <div
                                    style={{
                                      color: "#c0c0d0",
                                      fontSize: "10.5px",
                                      lineHeight: "1.55",
                                      marginTop: "2px",
                                      fontFamily: "'Inter',sans-serif",
                                    }}
                                  >
                                    {q.qNote}
                                  </div>
                                </div>
                              </div>
                            );
                          })()}
                      </div>
                    )}
                    {panel.tools && (
                      <div>
                        {sectionLabel("Tools", "#60a8d0")}
                        <div
                          style={{
                            display: "flex",
                            flexWrap: "wrap",
                            gap: "5px",
                          }}
                        >
                          {panel.tools.map((x, i) => (
                            <span
                              key={i}
                              className="ttag"
                              style={{
                                whiteSpace: "normal",
                                wordBreak: "break-word",
                              }}
                            >
                              {x}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                    {panel.zt && (
                      <div
                        style={{
                          paddingTop: "12px",
                          borderTop: "1px solid #181828",
                          display: "flex",
                          gap: "8px",
                          alignItems: "flex-start",
                        }}
                      >
                        <div>
                          {sectionLabel("Zero Trust", "#b060d0")}
                          <div
                            style={{
                              color: "#9050b8",
                              fontSize: "11.5px",
                              lineHeight: "1.6",
                            }}
                          >
                            {panel.zt}
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                )}
                {!selThreat && tab === "attacks" && panel.attacks && (
                  <div>
                    {sectionLabel("Attack Vectors", "#cc6060")}
                    <div
                      style={{ display: "flex", flexWrap: "wrap", gap: "5px" }}
                    >
                      {panel.attacks.map((a, i) => (
                        <span
                          key={i}
                          className="atag"
                          style={{
                            whiteSpace: "normal",
                            wordBreak: "break-word",
                          }}
                        >
                          {a}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                {!selThreat && tab === "mitre" && panel.mitre && (
                  <div>
                    {sectionLabel("MITRE ATT&CK", "#b080e0")}
                    <div
                      style={{
                        display: "flex",
                        flexWrap: "wrap",
                        gap: "5px",
                        marginBottom: "8px",
                      }}
                    >
                      {panel.mitre.map(([id, name]) => (
                        <div
                          key={id}
                          className="mtag"
                          style={{
                            display: "flex",
                            alignItems: "center",
                            gap: "6px",
                          }}
                        >
                          <span
                            style={{
                              color: "#c090ff",
                              fontWeight: "700",
                              fontSize: "10px",
                            }}
                          >
                            {id}
                          </span>
                          <span style={{ color: "#aaa", fontSize: "10.5px" }}>
                            {name}
                          </span>
                        </div>
                      ))}
                    </div>
                    <div style={{ fontSize: "10.5px", color: "#8080a0" }}>
                      attack.mitre.org
                    </div>
                  </div>
                )}
                {!selThreat && tab === "compliance" && panel.compliance && (
                  <div>
                    {sectionLabel("Compliance", "#60a060")}
                    <div
                      style={{
                        display: "flex",
                        flexDirection: "column",
                        gap: "5px",
                      }}
                    >
                      {panel.compliance.map(([fw, req]) => {
                        const c = COMPLIANCE_COLORS[fw] || "#666";
                        return (
                          <div
                            key={fw + req}
                            style={{
                              display: "flex",
                              gap: "8px",
                              alignItems: "flex-start",
                              background: "rgba(255,255,255,.03)",
                              borderRadius: "5px",
                              padding: "7px 10px",
                              border: `1px solid ${c}33`,
                            }}
                          >
                            <span
                              style={{
                                background: `${c}22`,
                                color: c,
                                fontSize: "10px",
                                fontWeight: "700",
                                padding: "2px 6px",
                                borderRadius: "3px",
                                whiteSpace: "nowrap",
                                flexShrink: 0,
                                lineHeight: "1.6",
                              }}
                            >
                              {fw}
                            </span>
                            <span
                              style={{
                                color: "#d0d0dc",
                                fontSize: "11px",
                                fontFamily: "'Inter',sans-serif",
                                lineHeight: "1.5",
                              }}
                            >
                              {req}
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
                {!selThreat && tab === "maturity" && panel.maturity && (
                  <div>
                    {sectionLabel("Maturity Model", "#70aa40")}
                    <div
                      style={{
                        display: "flex",
                        flexDirection: "column",
                        gap: "6px",
                      }}
                    >
                      {panel.maturity.levels.map(([name, desc], i) => {
                        const isTyp = i === panel.maturity.typical,
                          isPast = i < panel.maturity.typical;
                        const c = MATURITY_COLORS[i];
                        return (
                          <div
                            key={i}
                            style={{
                              display: "flex",
                              gap: "10px",
                              alignItems: "flex-start",
                              padding: "8px 10px",
                              borderRadius: "6px",
                              background: isTyp
                                ? `${c}18`
                                : "rgba(255,255,255,.02)",
                              border: `1px solid ${
                                isTyp ? c : isPast ? c + "33" : "#1a1a2e"
                              }`,
                              opacity: isPast ? 0.55 : 1,
                            }}
                          >
                            <div
                              style={{
                                display: "flex",
                                flexDirection: "column",
                                alignItems: "center",
                                flexShrink: 0,
                                width: "22px",
                              }}
                            >
                              <div
                                style={{
                                  width: 20,
                                  height: 20,
                                  borderRadius: "50%",
                                  background: isPast || isTyp ? c : "#1a1a2e",
                                  border: `2px solid ${c}`,
                                  display: "flex",
                                  alignItems: "center",
                                  justifyContent: "center",
                                  fontSize: "10.5px",
                                  color: isPast || isTyp ? "#000" : c,
                                  fontWeight: "700",
                                }}
                              >
                                {i + 1}
                              </div>
                              {i < 4 && (
                                <div
                                  style={{
                                    width: 1,
                                    height: 8,
                                    background: c + "44",
                                    marginTop: 2,
                                  }}
                                />
                              )}
                            </div>
                            <div style={{ flex: 1 }}>
                              <div
                                style={{
                                  display: "flex",
                                  alignItems: "center",
                                  gap: "6px",
                                  marginBottom: "3px",
                                }}
                              >
                                <span
                                  style={{
                                    fontSize: "11px",
                                    fontWeight: "700",
                                    color: c,
                                    fontFamily: "'Rajdhani',sans-serif",
                                    letterSpacing: "1px",
                                  }}
                                >
                                  {MATURITY_LABELS[i]}
                                </span>
                                {isTyp && (
                                  <span
                                    style={{
                                      background: `${c}22`,
                                      color: c,
                                      fontSize: "10.5px",
                                      padding: "1px 5px",
                                      borderRadius: "3px",
                                      border: `1px solid ${c}44`,
                                    }}
                                  >
                                    typical
                                  </span>
                                )}
                              </div>
                              <div
                                style={{
                                  color: "#d0d0dc",
                                  fontSize: "11px",
                                  fontFamily: "'Inter',sans-serif",
                                  lineHeight: "1.5",
                                }}
                              >
                                {desc}
                              </div>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}

                {!selThreat &&
                  tab === "vendors" &&
                  (() => {
                    const layerKey = selLayer
                      ? selLayer.id
                      : selSat
                      ? selSat.id
                      : null;
                    const vlist = VENDORS[layerKey];
                    if (!vlist) return null;
                    const CX = 60,
                      CY = 60,
                      R = 48;
                    const gridPts = vendorGridPoints(CX, CY, R);
                    const tiers = {
                      budget: "#22c55e",
                      mid: "#f59e0b",
                      enterprise: "#8b5cf6",
                    };

                    return (
                      <div
                        style={{
                          display: "flex",
                          flexDirection: "column",
                          gap: "16px",
                        }}
                      >
                        {sectionLabel(
                          "Vendor Comparison — click a card to explore",
                          "#60a8d0"
                        )}

                        {/* Radar chart + summary table */}
                        <div
                          style={{
                            display: "flex",
                            gap: "14px",
                            flexWrap: "wrap",
                            alignItems: "flex-start",
                          }}
                        >
                          {/* Radar */}
                          <div style={{ flexShrink: 0 }}>
                            <svg width="140" height="140" viewBox="0 0 140 140">
                              {/* Grid rings */}
                              {[1, 2, 3, 4, 5].map((ring) => (
                                <polygon
                                  key={ring}
                                  fill="none"
                                  stroke="#1a1a2e"
                                  strokeWidth="1"
                                  points={VENDOR_AXES.map((_, i) => {
                                    const a =
                                      (i / VENDOR_AXES.length) * 2 * Math.PI -
                                      Math.PI / 2;
                                    const rv = (ring / 5) * R;
                                    return `${(CX + rv * Math.cos(a)).toFixed(
                                      1
                                    )},${(CY + rv * Math.sin(a)).toFixed(1)}`;
                                  }).join(" ")}
                                />
                              ))}
                              {/* Axis lines */}
                              {gridPts.map(([x, y], i) => (
                                <line
                                  key={i}
                                  x1={CX}
                                  y1={CY}
                                  x2={x.toFixed(1)}
                                  y2={y.toFixed(1)}
                                  stroke="#252535"
                                  strokeWidth="1"
                                />
                              ))}
                              {/* Axis labels */}
                              {gridPts.map(([x, y], i) => {
                                const angle =
                                  (i / VENDOR_AXES.length) * 2 * Math.PI -
                                  Math.PI / 2;
                                const lx = CX + (R + 16) * Math.cos(angle),
                                  ly = CY + (R + 16) * Math.sin(angle);
                                return (
                                  <text
                                    key={i}
                                    x={lx.toFixed(1)}
                                    y={ly.toFixed(1)}
                                    textAnchor="middle"
                                    dominantBaseline="middle"
                                    fill="#505070"
                                    fontSize="8"
                                    fontFamily="'Space Mono',monospace"
                                  >
                                    {VENDOR_AXIS_LABELS[VENDOR_AXES[i]]}
                                  </text>
                                );
                              })}
                              {/* Vendor polygons */}
                              {vlist.map((v, vi) => (
                                <polygon
                                  key={vi}
                                  fill={v.color + "33"}
                                  stroke={v.color}
                                  strokeWidth="1.5"
                                  opacity="0.85"
                                  points={vendorRadarPoints(
                                    v.ratings,
                                    CX,
                                    CY,
                                    R
                                  )}
                                />
                              ))}
                            </svg>
                            {/* Legend */}
                            <div
                              style={{
                                display: "flex",
                                flexWrap: "wrap",
                                gap: "4px",
                                marginTop: "4px",
                              }}
                            >
                              {vlist.map((v) => (
                                <div
                                  key={v.name}
                                  style={{
                                    display: "flex",
                                    alignItems: "center",
                                    gap: "3px",
                                    fontSize: "10px",
                                  }}
                                >
                                  <div
                                    style={{
                                      width: 8,
                                      height: 8,
                                      borderRadius: "2px",
                                      background: v.color,
                                      flexShrink: 0,
                                    }}
                                  />
                                  <span style={{ color: v.color }}>
                                    {v.short}
                                  </span>
                                </div>
                              ))}
                            </div>
                          </div>

                          {/* Ratings table */}
                          <div style={{ flex: 1, minWidth: "140px" }}>
                            <div
                              style={{
                                display: "grid",
                                gridTemplateColumns: `repeat(${vlist.length},1fr)`,
                                gap: "4px",
                                marginBottom: "8px",
                              }}
                            >
                              {vlist.map((v) => (
                                <div
                                  key={v.name}
                                  style={{ textAlign: "center" }}
                                >
                                  <div
                                    style={{
                                      fontSize: "10.5px",
                                      fontWeight: "700",
                                      color: v.color,
                                      fontFamily: "'Rajdhani',sans-serif",
                                    }}
                                  >
                                    {v.short}
                                  </div>
                                  <div
                                    style={{
                                      fontSize: "10.5px",
                                      color: "#8080a0",
                                      marginTop: "1px",
                                    }}
                                  >
                                    {v.gartner || ""}
                                  </div>
                                </div>
                              ))}
                            </div>
                            {VENDOR_AXES.map((axis) => (
                              <div key={axis} style={{ marginBottom: "4px" }}>
                                <div
                                  style={{
                                    fontSize: "10.5px",
                                    color: "#8080a0",
                                    fontFamily: "'Space Mono',monospace",
                                    marginBottom: "2px",
                                  }}
                                >
                                  {VENDOR_AXIS_LABELS[axis]}
                                </div>
                                <div
                                  style={{
                                    display: "grid",
                                    gridTemplateColumns: `repeat(${vlist.length},1fr)`,
                                    gap: "4px",
                                  }}
                                >
                                  {vlist.map((v) => (
                                    <div
                                      key={v.name}
                                      style={{
                                        height: 4,
                                        borderRadius: 2,
                                        background: "#151525",
                                      }}
                                    >
                                      <div
                                        style={{
                                          height: "100%",
                                          borderRadius: 2,
                                          width: `${
                                            (v.ratings[axis] || 0) * 20
                                          }%`,
                                          background: v.color,
                                          transition: "width .3s",
                                        }}
                                      />
                                    </div>
                                  ))}
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>

                        {/* Individual vendor cards */}
                        {vlist.map((v) => (
                          <div
                            key={v.name}
                            style={{
                              borderRadius: "8px",
                              overflow: "hidden",
                              border: `1px solid ${v.color}44`,
                              background: "rgba(255,255,255,.025)",
                            }}
                          >
                            {/* Card header */}
                            <div
                              style={{
                                padding: "8px 12px",
                                background: `${v.color}14`,
                                borderBottom: `1px solid ${v.color}22`,
                                display: "flex",
                                alignItems: "center",
                                gap: "8px",
                                flexWrap: "wrap",
                              }}
                            >
                              <div
                                style={{
                                  width: 32,
                                  height: 32,
                                  borderRadius: "6px",
                                  background: `${v.color}22`,
                                  border: `1px solid ${v.color}44`,
                                  display: "flex",
                                  alignItems: "center",
                                  justifyContent: "center",
                                  fontSize: "11px",
                                  fontWeight: "700",
                                  color: v.color,
                                  fontFamily: "'Space Mono',monospace",
                                  flexShrink: 0,
                                }}
                              >
                                {v.short}
                              </div>
                              <div style={{ flex: 1 }}>
                                <div
                                  style={{
                                    fontFamily: "'Rajdhani',sans-serif",
                                    fontWeight: 800,
                                    fontSize: "14px",
                                    color: v.color,
                                    letterSpacing: "1px",
                                  }}
                                >
                                  {v.name}
                                </div>
                                <div
                                  style={{ color: "#9090b0", fontSize: "10px" }}
                                >
                                  {v.bestFor}
                                </div>
                              </div>
                              <div
                                style={{
                                  display: "flex",
                                  flexDirection: "column",
                                  alignItems: "flex-end",
                                  gap: "3px",
                                }}
                              >
                                <span
                                  style={{
                                    background: `${tiers[v.tier] || "#666"}22`,
                                    color: tiers[v.tier] || "#666",
                                    fontSize: "10.5px",
                                    padding: "1px 6px",
                                    borderRadius: "3px",
                                    border: `1px solid ${
                                      tiers[v.tier] || "#666"
                                    }44`,
                                    letterSpacing: "1px",
                                  }}
                                >
                                  {v.tier.toUpperCase()}
                                </span>
                                <span
                                  style={{ color: "#8080a0", fontSize: "10px" }}
                                >
                                  {v.price}
                                </span>
                                {v.gartner && (
                                  <span
                                    style={{
                                      color: "#9090b0",
                                      fontSize: "10.5px",
                                    }}
                                  >
                                    Gartner: {v.gartner}
                                  </span>
                                )}
                              </div>
                            </div>
                            {/* Pros / Cons */}
                            <div
                              style={{
                                display: "grid",
                                gridTemplateColumns: "1fr 1fr",
                                padding: "8px 12px",
                                gap: "10px",
                              }}
                            >
                              <div>
                                <div
                                  style={{
                                    fontSize: "10.5px",
                                    color: "#22c55e88",
                                    letterSpacing: "1.5px",
                                    marginBottom: "4px",
                                    fontFamily: "'Space Mono',monospace",
                                  }}
                                >
                                  PROS
                                </div>
                                {v.pros.map((p, i) => (
                                  <div
                                    key={i}
                                    style={{
                                      display: "flex",
                                      gap: "5px",
                                      alignItems: "flex-start",
                                      marginBottom: "3px",
                                    }}
                                  >
                                    <span
                                      style={{
                                        color: "#22c55e",
                                        flexShrink: 0,
                                        fontSize: "10.5px",
                                      }}
                                    >
                                      +
                                    </span>
                                    <span
                                      style={{
                                        color: "#c4c4d0",
                                        fontSize: "10px",
                                        lineHeight: "1.45",
                                        fontFamily: "'Inter',sans-serif",
                                      }}
                                    >
                                      {p}
                                    </span>
                                  </div>
                                ))}
                              </div>
                              <div>
                                <div
                                  style={{
                                    fontSize: "10.5px",
                                    color: "#ef444488",
                                    letterSpacing: "1.5px",
                                    marginBottom: "4px",
                                    fontFamily: "'Space Mono',monospace",
                                  }}
                                >
                                  CONS
                                </div>
                                {v.cons.map((c, i) => (
                                  <div
                                    key={i}
                                    style={{
                                      display: "flex",
                                      gap: "5px",
                                      alignItems: "flex-start",
                                      marginBottom: "3px",
                                    }}
                                  >
                                    <span
                                      style={{
                                        color: "#ef4444",
                                        flexShrink: 0,
                                        fontSize: "10.5px",
                                      }}
                                    >
                                      -
                                    </span>
                                    <span
                                      style={{
                                        color: "#c4c4d0",
                                        fontSize: "10px",
                                        lineHeight: "1.45",
                                        fontFamily: "'Inter',sans-serif",
                                      }}
                                    >
                                      {c}
                                    </span>
                                  </div>
                                ))}
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    );
                  })()}
              </div>
            </div>
          )}
        </div>
        {/* end right pane */}
      </div>
      {/* end two-column */}
    </div>
  );
}
