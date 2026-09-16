# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-09-15 23:35:41Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-09-14`
- **Included count:** 15

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-21391 | Critical authentication bypass in PingAM IdP/SSO platform allows unauthenticated attackers to forge ID Token claims, directly impacting Digital Identity infrastructure and federated access controls. | A critical TIER 2 flaw in Ping Identity's PingAM platform lets attackers bypass authentication and forge ID tokens, threatening the trust anchors of enterprise and government SSO ecosystems. Patching and strict claim validation are essential to protect digital identity infrastructure. |
| 5 | 1 | CVE-2026-76461 | Foundational perimeter email gateway infrastructure actively exploited in the wild, directly impacting Government, Healthcare, and Finance communications and data routing. | Actively exploited, unauthenticated root RCE in Cisco Secure Email Gateways (CVE-2026-76461) now on the CISA KEV catalog demands immediate patching. As a foundational perimeter control for government, healthcare, and financial services, this vulnerability bypasses internal defenses and threatens critical cross-sector communications. |
| 5 | 2 | CVE-2026-78336 | Exposes plaintext OIDC client secrets to any authenticated user in Apache Syncope, directly compromising enterprise SSO/IdAM infrastructure (Digital Identity) and enabling token forgery across identity-bound services. | A single valid account can dump plaintext OIDC secrets from Apache Syncope, bypassing entitlements and risking full SSO ecosystem compromise. Critical patch and secret rotation required for any organization relying on centralized identity providers. |
| 5 | 2 | CVE-2026-87802 | Critical authentication bypass in Apache Syncope IAM gateway allows JWT forgery and full user impersonation, directly impacting Digital Identity infrastructure. | Enterprise IAM gateways are only as secure as their configuration. CVE-2026-87802 shows how a missing JWKS URI in Apache Syncope can turn OAuth 2.0 into an open door for attackers. Audit your token validation settings today. |
| 5 | 2 | CVE-2026-90942 | Digital Identity: Critical authorization flaw in Casdoor IdP allows org admins to extract global JWT signing keys, enabling cross-tenant token forgery and full platform compromise. | A TIER 2 flaw in Casdoor exposes the global JWT signing key to organization admins, breaking multi-tenant isolation and enabling cross-organization token forgery. Identity providers must patch immediately and rotate signing keys to prevent global admin impersonation. |
| 4 | 2 | CVE-2026-19290 | Unauthenticated remote data exposure on IBM Sterling File Gateway, a perimeter B2B integration component widely deployed across finance, healthcare, and government for secure EDI and document exchange. | Unauthenticated access to perimeter file gateways poses immediate data leakage risks for regulated sectors. IBM Sterling File Gateway deployments in finance, healthcare, and government should prioritize patching this TIER 2 vulnerability to protect sensitive B2B exchanges. |
| 4 | 2 | CVE-2026-67399 | Unauthenticated RCE in WHMCS billing platform directly impacts financial operations infrastructure and payment processing for hosting providers and ISPs. | Critical unauthenticated RCE in WHMCS exposes payment gateways and client financial data across the hosting ecosystem. Finance and infrastructure teams should prioritize patching to 9.0.8/8.13.7 immediately. |
| 4 | 2 | CVE-2026-76441 | Critical unauthenticated bypass in perimeter email gateways widely deployed across government, healthcare, and finance sectors for secure communications. | Unauthenticated remote access to internet-facing email gateways poses a critical perimeter breach risk for regulated sectors. Organizations in government, healthcare, and finance should prioritize patching Cisco Secure Email Gateway to protect sensitive communications and prevent lateral movement. |
| 4 | 2 | CVE-2026-76443 | Critical general infrastructure flaw in internet-facing email gateways widely deployed across government, finance, and healthcare, enabling remote code execution and potential data interception. | Email gateways are the frontline for organizational communications. This critical Cisco vulnerability (CVSS 9.8) affects default deployments across government, finance, and healthcare—prompt patching is essential to secure perimeter access and prevent data interception. |
| 4 | 2 | CVE-2026-90805 | Unauthenticated SQL injection in a clinic management system bypasses doctor authentication and exposes patient appointment data, directly impacting healthcare infrastructure confidentiality. | Healthcare digital infrastructure faces critical risks from unauthenticated SQL injection flaws that bypass clinical login controls and expose patient records. Immediate patching and input validation are essential to protect clinic management systems. |
| 4 | 2 | CVE-2026-90840 | Unauthenticated admin access in a blood donor management system compromises healthcare data integrity and donor PII. | Blood bank and hospital IT teams should patch this TIER 2 flaw immediately: missing session validation in the PHPGurukul Blood Donor Management System allows attackers to bypass login and delete donor records or steal PII. |
| 3 | 2 | CVE-2026-53714 | Foundational Kubernetes service mesh/gateway component with unauthenticated internal config/secret exposure, impacting cloud-native deployments across regulated and public sector environments. | Envoy Gateway's internal xDS server lacks authentication by default, allowing lateral movement and TLS key theft within Kubernetes clusters. Critical patch for any DPI or regulated cloud-native deployment relying on service mesh infrastructure. |
| 3 | 2 | CVE-2026-57578 | Critical authorization bypass in a .NET web framework widely used for internal LOB and public-facing services in regulated sectors. | A trivial authorization bypass in the DotVVM .NET framework could expose protected endpoints in enterprise and public-sector web apps. Patching or switching to AuthorizeAttribute is critical for any regulated deployment relying on this stack. |
| 3 | 2 | CVE-2026-76442 | General infrastructure flaw in enterprise email gateways, explicitly tied to government and public sector network deployments. | Unauthenticated remote flaws in Cisco Secure Email Gateways pose a direct risk to public sector and enterprise perimeter defenses. With no workarounds available, agencies relying on these appliances for critical communications must prioritize immediate patching to prevent network footholds. |
| 3 | 2 | CVE-2026-90841 | Unauthenticated SQLi in a blood donor management system exposes clinical donor PII and credentials, directly impacting healthcare digital infrastructure. | Healthcare data security alert: An unauthenticated SQL injection in a widely deployed blood donor management system allows attackers to extract full donor records and admin credentials. Clinics and NGOs using this PHP-based platform should patch immediately to protect sensitive patient data. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2023-28148.md` — heuristic TIER 3/4
- `TIER_3_CVE-2023-32803.md` — heuristic TIER 3/4
- `TIER_3_CVE-2023-46273.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12756.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12944.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13107.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13275.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13285.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13287.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13293.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15955.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16335.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16338.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16428.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16432.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16466.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16673.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17133.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17156.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17416.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17467.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19499.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19624.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19816.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20353.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-25687.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-31278.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-43689.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-43692.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-43786.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47701.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53713.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53752.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54087.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54155.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54178.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54180.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54567.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55451.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56839.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57119.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57127.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57145.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59569.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61701.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65364.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72524.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73178.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73195.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73236.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73370.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73470.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73579.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73668.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75030.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77051.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77181.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78330.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82028.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82035.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82232.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82427.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82428.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82429.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82430.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82431.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82432.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82434.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82435.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82438.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82441.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82762.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82765.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82766.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82768.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82770.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82772.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82774.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82777.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82779.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82780.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82786.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82787.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82789.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82791.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82793.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86460.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86830.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86836.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87779.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87785.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-8821.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90707.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90895.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90927.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90928.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90929.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90930.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90932.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90933.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90934.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90961.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91145.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91197.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91200.md` — heuristic TIER 3/4
