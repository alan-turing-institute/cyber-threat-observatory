# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-09-04 13:39:23Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-09-03`
- **Included count:** 10

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-53728 | TIER 2 OAuth redirect flaw in Medplum healthcare platform enables full account takeover and PHI exposure, directly impacting Healthcare and Digital Identity sectors. | Healthcare platforms relying on OAuth for patient data access face a critical account takeover risk. CVE-2026-53728 bypasses PKCE protections via redirect URI prefix matching, threatening PHI integrity and HIPAA compliance. Patch to v5.1.6 and audit redirect configs immediately. |
| 5 | 2 | CVE-2026-63219 | Unauthenticated file upload in GeoNetwork, a foundational platform for national Spatial Data Infrastructures and government geoportals, enabling RCE on public-facing civic systems. | GeoNetwork, the backbone of many national Spatial Data Infrastructures, faces an unauthenticated RCE chain. Government agencies running public geoportals should apply reverse-proxy mitigations or patch immediately to protect critical civic geospatial data. |
| 5 | 2 | CVE-2026-80465 | Directly impacts Digital Identity infrastructure by allowing unauthenticated SAML signature bypass and session hijacking in enterprise SSO deployments. | A TIER 2 flaw in the Mendix SAML module lets attackers bypass signature validation and hijack SSO sessions. For any organization relying on SAML for digital identity, this underscores the critical need to enforce strict IdP trust and patch promptly. |
| 5 | 2 | CVE-2026-83711 | Critical unauthenticated authorization bypass in Microsoft Entra ID B2C, a core cloud-native Digital Identity and Access Management (IdAM) platform. | A critical, unauthenticated privilege escalation flaw in Microsoft Entra ID B2C could allow attackers to bypass authorization and take over enterprise identity tenants. With no customer-side mitigations available, organizations relying on this SaaS IdP must monitor for vendor patches closely. |
| 5 | 2 | CVE-2026-85394 | Critical default authentication bypass in a foundational JWT library directly impacts Digital Identity, SSO gateways, and enterprise/public-sector access control systems. | A critical flaw in the widely-used python-jose JWT library allows attackers to forge authentication tokens by default, bypassing identity controls in SSO and API gateways. Public infrastructure relying on Python-based auth stacks must explicitly restrict algorithms or patch immediately to prevent unauthorized access. |
| 4 | 2 | CVE-2026-58400 | Critical RCE in GeoNetwork, a foundational platform for national Spatial Data Infrastructures and government geoportals, requiring urgent patching for public-sector deployments. | National geoportals and spatial data infrastructures face a critical RCE risk in GeoNetwork. While authentication is required, the widespread public-sector deployment makes immediate patching essential for government data resilience. |
| 4 | 2 | CVE-2026-67398 | Finance sector relevance: unauthenticated PII disclosure in a widely deployed payment gateway and billing platform (WHMCS), impacting regulated transaction processing and customer account management. | Unauthenticated PII exposure in WHMCS’s 2Checkout module highlights the risks of public-facing payment gateways in regulated billing ecosystems. Organizations should verify module configurations and apply patches to protect customer financial and personal data. |
| 4 | 2 | CVE-2026-80098 | Critical privilege escalation in Microsoft Copilot Studio's internet-facing APIs, directly impacting government agencies and public-sector AI service automation. | Public sector agencies relying on Microsoft Copilot Studio for citizen services face a critical, internet-exposed privilege escalation flaw. Patching and monitoring API access controls are essential to protect government AI workflows from unauthorized takeover. |
| 4 | 2 | CVE-2026-85089 | TIER 2 authenticated credential leak in FreeRDP remote access proxies, directly impacting Digital Identity and government/enterprise session security. | Remote access gateways are a critical DPI chokepoint. CVE-2026-85089 shows how a simple padding oversight in FreeRDP can leak cleartext credentials and session tokens post-auth. Patching RDP proxies isn't just about uptime—it's about protecting the identity layer of your workforce. |
| 4 | 2 | CVE-2026-85393 | Directly impacts Digital Identity infrastructure by enabling signature forgery in JWT, OAuth/OIDC, and SAML token validation for identity providers and API gateways. | A cryptographic signature forgery in the node-forge library could allow attackers to bypass token validation in identity providers and API gateways. Though it requires a non-default RSA key configuration, DPI teams should audit their IdAM deployments and enforce standard key exponents to protect digital identity services. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2021-38489.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-12737.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-33630.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-44506.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62906.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62916.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67397.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71220.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71221.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71404.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71963.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73600.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75033.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75034.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75035.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76174.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76175.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76176.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76177.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76642.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78583.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82180.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82302.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82520.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83961.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84736.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84830.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84832.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84964.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84971.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84989.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85012.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85028.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85047.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85093.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85166.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85168.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85169.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85170.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85171.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85176.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85179.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85182.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85183.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85211.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85213.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85216.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85221.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85236.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85237.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85238.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85239.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85390.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85395.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85425.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85427.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85428.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85429.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85430.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85431.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85433.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85434.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85435.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-9853.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-9854.md` — heuristic TIER 3/4
