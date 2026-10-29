# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-10-29 13:23:19Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-10-28`
- **Included count:** 14

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2025-14260 | Unauthenticated SSRF in WSO2 middleware directly impacts Digital Identity and Finance sectors by compromising SSO gateways, open banking APIs, and government citizen portals. | Unauthenticated SSRF in widely deployed WSO2 middleware exposes critical identity and banking API gateways to internal pivoting and cloud metadata theft. Organizations relying on WSO2 for SSO or open banking must prioritize patching and egress filtering immediately. |
| 5 | 2 | CVE-2026-104383 | Critical code injection in an enterprise MFA/IAM platform enables container root RCE, directly threatening digital identity infrastructure and zero-trust access controls across government, finance, and healthcare. | A critical flaw in a widely deployed enterprise MFA service could let attackers bypass zero-trust controls and take over identity infrastructure. For DPI operators, this underscores why patching IAM platforms and enforcing strict API segmentation is non-negotiable. |
| 5 | 2 | CVE-2026-118669 | TIER 2 authorization bypass in Python oauthlib enables privilege escalation in OAuth2/OIDC token endpoints, directly impacting Digital Identity infrastructure and public/enterprise identity federation. | A TIER 2 flaw in the widely used Python oauthlib library allows attackers to bypass authorization checks and impersonate high-privilege OAuth clients. Critical for any organization relying on OAuth2/OIDC for digital identity and API access—upgrade to v4.0.0 immediately. |
| 5 | 2 | CVE-2026-59185 | Cross-tenant IDOR in a machine identity/OIDC platform breaks multi-tenant authorization boundaries, directly impacting Digital Identity infrastructure. | Multi-tenant identity platforms are critical to modern DPI, but a single IDOR flaw can let attackers pivot across customer environments. Patch identrail to 1.0.2 and enforce OAuth user authorization to protect your identity federation boundaries. |
| 5 | 2 | CVE-2026-59979 | Healthcare sector: missing authorization in FHIR-based clinical service and task management APIs enables cross-tenant data manipulation and disrupts national digital health booking/billing workflows. | A TIER 2 vulnerability in a healthcare SaaS platform exposes cross-tenant service catalogues and clinical task templates to low-privilege users. With FHIR APIs lacking tenant scoping, digital health systems face direct risks to booking integrity and billing availability. |
| 4 | 2 | CVE-2026-118264 | Critical authentication bypass in the Echo Go framework directly impacts Digital Identity infrastructure, allowing attackers to circumvent IAM, OAuth/OIDC, and session validation middleware in public-facing services. | A critical auth bypass in the widely used Echo Go framework could let attackers slip past IAM and OAuth/OIDC middleware in public-facing APIs. If your digital identity or citizen-facing services rely on Echo as a reverse proxy, patching to v4.16.1/v5.4.1 is a priority to protect access control layers. |
| 4 | 2 | CVE-2026-118377 | Finance sector: bypasses cryptographic verification in public-facing payment gateway callbacks, enabling unauthenticated order completion without actual fund transfer. | Payment webhooks are inherently public-facing, making missing hash verification a critical risk for e-commerce and fintech platforms. This TIER 2 flaw allows attackers to forge successful transactions without real bank authorization, highlighting the need for strict callback validation in financial infrastructure. |
| 4 | 2 | CVE-2026-118665 | TIER 2 authentication bypass in a GraphQL gateway library that retains session tokens across connections, directly impacting the Digital Identity sector and API security in regulated/public services. | GraphQL gateways powering public APIs and digital identity services are at risk of silent user impersonation due to a session token retention flaw. Ensure your Node.js executors are patched or instantiated per-request to protect citizen and customer data. |
| 4 | 2 | CVE-2026-76418 | Critical general infrastructure vulnerability affecting Cisco ASA/FTD VPN gateways that secure Government, Finance, and Healthcare network perimeters, with confirmed in-wild exploitation causing service disruption. | Confirmed in-wild exploitation of a Cisco ASA/FTD VPN DoS vulnerability highlights the fragility of public-sector and regulated enterprise network perimeters. While a configuration barrier limits blast radius, the availability impact on critical remote access gateways demands immediate patching or interim controls. |
| 4 | 2 | CVE-2026-84725 | Foundational enterprise Java middleware underpinning Government, Finance, and Healthcare digital services; requires patching despite non-default exploitation prerequisites. | Enterprise Java servers like Red Hat JBoss EAP remain critical backbone infrastructure for regulated sectors. This TIER 2 RCE highlights why legacy IIOP configurations and security manager settings must be audited in government and financial deployments. |
| 4 | 2 | CVE-2026-86400 | Unauthenticated root RCE in Dell enterprise backup appliances threatens data integrity and recovery capabilities across Government, Finance, and Healthcare sectors. | Critical backup infrastructure is the backbone of digital public services. This unauthenticated RCE in Dell Data Domain appliances highlights why network segmentation and rapid patching are non-negotiable for protecting national data recovery capabilities. |
| 3 | 2 | CVE-2026-103409 | Tier 2 SD-WAN edge router flaw grants unauthenticated root access during pre-onboarding, impacting government and critical infrastructure networking deployments. | Juniper SD-WAN routers face a critical pre-onboarding authentication gap (CVE-2026-103409) that could expose government and enterprise networks to full administrative takeover. Patching and strict provisioning isolation are essential to secure the edge. |
| 3 | 2 | CVE-2026-104895 | Foundational Java backend library underpinning APIs across Finance, Healthcare, and Government; async parser DoS threatens service availability in regulated digital infrastructure. | A trivial 10-byte payload can crash Java backend threads in reactive architectures. While Jackson is a general-purpose library, its widespread use in regulated Finance, Healthcare, and Government APIs makes this async parser DoS a critical supply-chain availability risk for digital public infrastructure. |
| 3 | 2 | CVE-2026-110879 | Critical RCE in jackson-databind, a foundational Java serialization framework powering public-facing APIs and backend services across regulated and public-sector digital infrastructure. | A critical deserialization bypass in jackson-databind (CVE-2026-110879) enables RCE in Java backends with polymorphism enabled. While requiring specific configuration, its widespread use in public-facing APIs makes patching urgent for DPI and enterprise service providers. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2025-30414.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100105.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103401.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103402.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103403.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103407.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103408.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103411.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103506.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103779.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103780.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103792.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103799.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106079.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109411.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110540.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110541.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112197.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112198.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112357.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116641.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116778.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116794.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-117574.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-117610.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118035.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118036.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118037.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118038.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118039.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118040.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118246.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118249.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118252.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118254.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118255.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118261.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118370.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118374.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118375.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118378.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118641.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118642.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118643.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118644.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118646.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118647.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118648.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118659.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118664.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118668.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118676.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118678.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118682.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118683.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118684.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118686.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118687.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118688.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118752.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118753.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13451.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-44179.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59164.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-6647.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67073.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67074.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78674.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85749.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86377.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86378.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86379.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86380.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86385.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86389.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86393.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86394.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86395.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86396.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86397.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86398.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86399.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87102.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87103.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90717.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93517.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93518.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93519.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93520.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93521.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93522.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93523.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93851.md` — heuristic TIER 3/4
