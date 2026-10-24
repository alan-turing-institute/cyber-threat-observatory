# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-10-24 10:26:01Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-10-23`
- **Included count:** 12

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-57209 | Directly impacts Digital Identity infrastructure by compromising an Identity Aware Proxy (IAP), allowing attackers to bypass IP-based access controls and undermine authentication/authorization boundaries. | A ready-to-exploit header injection in a popular cloud-native Identity Aware Proxy (Heimdall) lets attackers spoof client IPs and bypass critical access controls. For DPI and regulated environments relying on IAPs for secure identity routing, patching to v0.17.17 is urgent to protect the authentication boundary. |
| 5 | 2 | CVE-2026-89320 | Breaks JWE integrity in a widely used Go IdAM library, enabling token manipulation that bypasses authorization in digital identity, finance, and government portals. | A critical integrity flaw in a popular Go JOSE library silently strips authentication tags from JWE tokens, leaving IdAM systems and citizen-facing portals vulnerable to token manipulation. Switching to AEAD/GCM or patching immediately is essential for regulated identity infrastructure. |
| 4 | 2 | CVE-2026-105482 | Foundational Node.js runtime flaw enabling SSRF bypass in public-facing APIs and microservices that underpin cross-sector digital public services. | A TIER 2 vulnerability in Node.js allows NUL-byte injection to bypass domain allowlists, creating a critical SSRF vector for internet-exposed APIs. Organizations running Node.js-based DPI backends should prioritize patching to prevent internal network pivoting and cloud metadata exposure. |
| 4 | 2 | CVE-2026-10632 | Impacts session integrity and account boundaries in Zimbra, an enterprise email platform widely deployed across government and financial sectors for secure communications and digital identity workflows. | Enterprise email platforms like Zimbra are critical to government and financial communications, but a chained XSS flaw could let attackers hijack authenticated sessions and exfiltrate sensitive data. Patching to 10.1.17 and enforcing strict CSP headers are essential to protect institutional identity and session boundaries. |
| 4 | 2 | CVE-2026-115937 | Finance sector: unauthenticated webhook manipulation allows forged payment confirmations and direct financial loss for e-commerce merchants. | E-commerce platforms relying on payment webhooks must enforce strict data binding. This TIER 2 flaw in Craft CMS's Mollie plugin lets attackers bypass actual payments, underscoring the critical need for transaction integrity in digital commerce infrastructure. |
| 4 | 2 | CVE-2026-46651 | Unauthenticated SSRF and potential RCE in Goobi viewer, a public-facing digital library platform widely deployed by national libraries and cultural heritage institutions (Government sector). | Public-facing digital libraries face a critical unauthenticated SSRF flaw that could expose metadata or enable remote code execution. National libraries and cultural heritage institutions should apply endpoint blocking or patch immediately to protect public digital infrastructure. |
| 4 | 2 | CVE-2026-46652 | Unauthenticated RCE in Goobi viewer, a public-facing web portal widely deployed by national libraries, state museums, and public archives (Government/Cultural Heritage sector). | Public archives and national libraries running Goobi viewer face immediate risk from an unauthenticated RCE flaw that requires zero interaction. Patch or apply the vendor’s Apache/Tomcat workarounds now to protect citizen-facing cultural heritage portals. |
| 4 | 2 | CVE-2026-55459 | Directly impacts OIDC/JWT authentication flows in public-sector digital libraries and national archives, enabling unauthorized access to citizen-facing cultural heritage platforms. | Public sector digital libraries and national archives relying on OIDC for citizen access face a critical authentication bypass risk. Improper JWT audience validation in multi-RP setups could allow attackers to hijack sessions and access restricted cultural heritage data. |
| 4 | 2 | CVE-2026-57210 | Digital Identity sector: IP spoofing in Heimdall IAP bypasses access control rules, impacting cloud-native authentication and authorization pipelines. | Identity-aware proxies are the gatekeepers of modern digital infrastructure, but flawed header parsing can undermine IP-based access controls. Patch Heimdall to v0.17.17 to secure your authz pipelines and prevent spoofing attacks. |
| 4 | 2 | CVE-2026-58202 | Impacts Healthcare and Digital Identity sectors by enabling unauthenticated account takeover and passkey hijacking in public-facing clinic/hospital scheduling platforms. | Unauthenticated account takeover in clinic scheduling software highlights the critical intersection of Healthcare and Digital Identity. Host header injection bypasses passkey registration, stressing the need for strict proxy allowlists in public-facing health IT. |
| 4 | 2 | CVE-2026-65824 | Authentication bypass in a public-facing healthcare appointment booking system compromises staff/admin accounts and patient scheduling data, impacting Healthcare and Digital Identity sectors. | Healthcare digital infrastructure faces a critical authentication gap: a token replay flaw in OpenReception allows attackers to hijack staff accounts and access patient scheduling data. Patching and monitoring invite tokens are essential for protecting healthcare tenant environments. |
| 3 | 2 | CVE-2026-55457 | Impacts public-facing digital library and archive portals frequently deployed by government and cultural heritage institutions, risking unauthorized access to civic digital collections. | Public libraries and archives relying on Goobi Viewer should verify their API token configurations. This TIER 2 auth bypass highlights how a simple missing config can expose civic digital heritage to unauthenticated access. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2025-30043.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-30045.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-30046.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-30047.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-30049.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-30050.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-30052.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-30054.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105483.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107685.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110975.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115486.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115546.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115547.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115570.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115572.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115580.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115723.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115778.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115863.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115895.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16762.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-25716.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-39902.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50053.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50056.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50057.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54630.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54668.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55486.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56832.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56833.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56835.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56836.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56838.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57113.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57121.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57142.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57146.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57845.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63120.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79979.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91093.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93631.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93639.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93640.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-115484.md` — heuristic TIER 3/4
