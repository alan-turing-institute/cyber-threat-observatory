# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-10-30 13:35:19Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-10-29`
- **Included count:** 15

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-112256 | Critical unauthenticated authentication bypass in OpenText Advanced Authentication Server directly compromises enterprise IdP/MFA gateways, fully matching the Digital Identity sector criteria. | A critical, unauthenticated bypass in OpenText's Advanced Authentication Server allows attackers to skip MFA and gain full access to protected resources. As a core enterprise IdP component, this vulnerability underscores the urgent need to patch identity infrastructure before it becomes a primary attack vector. |
| 5 | 2 | CVE-2026-119127 | Core Identity Provider (ZITADEL) host header injection enables full account takeover via poisoned credential recovery links, directly impacting Digital Identity infrastructure. | A TIER 2 flaw in ZITADEL's default Login V2 UI allows attackers to hijack password-reset and verification emails via host header injection. For any organization relying on this open-source IdP for OIDC/SAML authentication, patching to v4.19.5 or hardening reverse proxies is critical to prevent full account takeover. |
| 5 | 2 | CVE-2026-119128 | Critical authentication bypass in ZITADEL IdAM platform enables unauthenticated account takeover, directly impacting the Digital Identity sector and zero-trust architectures. | A critical flaw in the open-source ZITADEL identity platform allows attackers to forge verification cookies and hijack accounts without credentials. For organizations relying on ZITADEL for digital identity and zero-trust access, immediate patching is essential to prevent full account takeover. |
| 5 | 2 | CVE-2026-119129 | Core IAM/IdP flaw enabling account takeover via OAuth 2.0 Device Authorization bypass, directly impacting Digital Identity infrastructure. | A TIER 2 vulnerability in ZITADEL's OAuth 2.0 Device Authorization flow enables account takeover via a single malicious link. Organizations using open-source IAM for public or regulated services must patch immediately to protect identity boundaries. |
| 5 | 2 | CVE-2026-119283 | Core JWT/JWE processing library for identity providers; unauthenticated DoS directly threatens authentication and session management services in public-sector and enterprise digital identity stacks. | A single unauthenticated request can exhaust CPU on identity providers via a flawed JWT/JWE parser. As digital identity services scale, securing foundational token libraries like joserfc is critical to prevent authentication outages—patch to v1.7.5 or enforce strict payload limits. |
| 5 | 2 | CVE-2026-62374 | Directly impacts Digital Identity infrastructure by compromising SD-JWT verification, a core component of the EU Digital Identity Wallet and government verifiable credential systems. | A silent authorization bypass in SD-JWT libraries could undermine the integrity of digital identity wallets and verifiable credentials. As governments roll out EUDIW-compliant services, patching this claim-stripping flaw is critical to maintaining trust in decentralized identity ecosystems. |
| 4 | 2 | CVE-2026-114358 | Unauthenticated SQLi in an M2M platform deployed for smart city utilities and public transport telemetry, directly impacting Government and critical infrastructure resilience. | Critical unauthenticated SQL injection in Radius Xenia M2M platforms exposes smart city and utility management systems to full database compromise. Public sector and infrastructure operators should prioritize patching and WAF deployment to protect citizen-facing telemetry and operational data. |
| 4 | 2 | CVE-2026-114488 | TIER 2 authentication bypass in JBoss/WildFly middleware impacts Red Hat SSO (Keycloak-based IdAM) and enterprise backends widely deployed across government, finance, and healthcare. | Enterprise middleware is the backbone of regulated digital services. This TIER 2 flaw in JBoss/WildFly bypasses authentication in IIOP calls, directly impacting Keycloak-based SSO deployments and sector-critical backends. Verify that caller-propagation remains disabled by default. |
| 4 | 2 | CVE-2026-119049 | Digital Identity: Authorization bypass in a public temp-mail service enables theft of OTPs and verification codes, directly undermining identity assurance and 2FA flows. | Temporary email platforms are increasingly woven into identity verification and OTP delivery chains. This TIER 2 flaw in FreeMail shows how a simple authorization bypass can silently hijack mailboxes, steal verification codes, and bypass 2FA—highlighting the hidden identity risks in lightweight email infrastructure. |
| 4 | 2 | CVE-2026-119144 | SSTI in Frappe Framework enables RCE in enterprise ERP systems widely deployed for financial operations, payroll, and government citizen services. | Frappe/ERPNext deployments face critical RCE risk via authenticated SSTI, threatening financial data integrity and public sector service continuity. Prioritize patching for internet-exposed ERP instances. |
| 4 | 2 | CVE-2026-42922 | TIER 2 unauthenticated RCE in FUXA SCADA/HMI platform impacts Government/Critical Infrastructure sectors (energy, water, transport) under national security oversight. | CVE-2026-42922 enables unauthenticated RCE in FUXA SCADA platforms, threatening critical infrastructure like energy and water networks. Operators should patch to v1.3.3 immediately and restrict internet exposure to protect government-regulated assets. |
| 4 | 2 | CVE-2026-84295 | Unauthenticated credential theft in enterprise FTP infrastructure explicitly tied to regulated data exchanges and government procurement portals. | A critical unauthenticated flaw in Progress WS_FTP Server exposes administrative credentials on internet-facing file transfer systems. With widespread use in government procurement and regulated supply chains, immediate patching is essential to protect critical data exchange pipelines. |
| 4 | 2 | CVE-2026-90868 | Critical RCE in enterprise FTP gateways widely deployed for Finance, Healthcare, and Government B2B/civic data pipelines. | Enterprise file transfer gateways like Progress WS_FTP are critical plumbing for regulated sectors. This TIER 2 RCE highlights why patching and strict access controls remain essential for protecting B2B payment, healthcare, and civic data pipelines. |
| 4 | 2 | CVE-2026-93757 | Strong Digital Identity relevance due to SSO authentication bypass and account binding flaw in a widely deployed WordPress plugin used by public and regulated sectors. | A flawed SSO fallback in a popular WordPress plugin allows attackers to hijack admin sessions via email collisions. Organizations relying on integrated identity management should patch immediately to protect public-facing digital services. |
| 3 | 2 | CVE-2026-66090 | Authenticated XXE/SSRF in openEQUELLA ePortfolio platforms widely deployed by public universities and government-funded educational institutions (Government sector). | Public sector education infrastructure faces risk from authenticated XXE/SSRF flaws in openEQUELLA ePortfolio systems, enabling file exfiltration and internal network probing. Institutions should prioritize patching to v2026.1.0 and restrict outbound network access. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2023-22793.md` — heuristic TIER 3/4
- `TIER_3_CVE-2023-7357.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-62839.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-62841.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101288.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103092.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103093.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103094.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104317.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104324.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104328.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107238.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107239.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107327.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107328.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107347.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110196.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110244.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110245.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110309.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111418.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111419.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114148.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115708.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115709.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115713.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115805.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-11587.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-117611.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118758.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118761.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118763.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118764.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118765.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118905.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118984.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119027.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119028.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119052.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119115.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119118.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119119.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119168.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119191.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119197.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119203.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119204.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119205.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119206.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119207.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119208.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119209.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119282.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13303.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15564.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-33923.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-33924.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-45049.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-49142.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61576.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61654.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61671.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61707.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61719.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84294.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85890.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85897.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90863.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90864.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90866.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90867.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90869.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92092.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92744.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96228.md` — heuristic TIER 3/4
