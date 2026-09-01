# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-09-01 12:23:08Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-08-31`
- **Included count:** 8

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-17615 | Directly impacts Keycloak IdAM deployments and core enterprise middleware, risking unauthenticated exposure of identity credentials and token signing keys across government, finance, and healthcare sectors. | A TIER 2 XXE flaw in RESTEasy could silently expose token signing keys and database credentials in widely deployed Keycloak IdAM instances. Organizations relying on Red Hat’s identity and middleware stacks should verify endpoint configurations and apply patches to protect critical authentication infrastructure. |
| 5 | 2 | CVE-2026-82801 | Unauthenticated SSRF in NASA's public Earthdata Search portal enables internal network mapping and backend access, directly impacting Government digital infrastructure. | NASA's public Earthdata Search portal faces an unauthenticated SSRF flaw allowing attackers to map internal networks via a timing oracle. A TIER 2 risk for government data infrastructure with a ready-to-use PoC and no vendor patch yet. |
| 4 | 2 | CVE-2026-72001 | TIER 2 authentication bypass in Pangolin remote access platform undermines SSO and token verification, directly impacting Digital Identity and Government sector access controls. | A single share link is all it takes to bypass SSO and access arbitrary resources across organizations in Pangolin. This TIER 2 auth bypass highlights critical risks in remote access gateways for government and enterprise digital identity infrastructure. Patch to 1.22.0 immediately. |
| 4 | 2 | CVE-2026-82877 | Impacts government and public-sector education infrastructure via authenticated credential theft in widely deployed LMS platforms. | Government and public education agencies using ILIAS LMS should prioritize patching an authenticated arbitrary file read flaw that exposes database credentials and citizen data. Restricting SOAP endpoints offers immediate mitigation. |
| 4 | 2 | CVE-2026-82957 | Enterprise blockchain middleware (Hyperledger Firefly) with SSRF risk, explicitly noted for deployment in Finance and Government digital infrastructure contexts. | A TIER 2 SSRF in Hyperledger Firefly underscores the importance of egress filtering in enterprise blockchain middleware. As permissioned networks underpin finance and government DPI, securing internal API layers against reconnaissance and lateral movement remains a priority. |
| 3 | 2 | CVE-2026-82397 | Foundational web framework DoS threatens availability of public-facing APIs and backend services underpinning government, finance, and healthcare digital infrastructure. | A single crafted POST request can freeze Tornado-based backends, disrupting citizen and enterprise services. DPI teams should patch to v6.5.8 and enforce strict reverse-proxy body limits to maintain service availability. |
| 3 | 2 | CVE-2026-82921 | Finance sector relevance: e-commerce platform handling payments and customer financial data faces public RCE risk via unrestricted file upload. | A TIER 2 vulnerability in ShopEx ECShop allows unauthenticated remote code execution on internet-facing e-commerce storefronts, directly threatening payment flows and customer financial data. |
| 3 | 2 | CVE-2026-82922 | Finance sector relevance: unauthenticated SQLi in a public-facing e-commerce platform directly threatens payment processing, customer accounts, and transactional data integrity. | Unauthenticated SQL injection in ShopEx ECShop exposes payment data and customer accounts. E-commerce platforms handling financial transactions must prioritize WAF rules and input validation to protect consumer trust and regulatory compliance. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-13732.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19410.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19616.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19702.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19873.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-40463.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-49003.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53552.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53553.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54599.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59111.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-5956.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61640.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61641.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75757.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77850.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78422.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79744.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79746.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79748.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79749.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79750.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81315.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81624.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81892.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82217.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82392.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82608.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82621.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82659.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82662.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82673.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82815.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82855.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82856.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82857.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82858.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82859.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82860.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82861.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82864.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82869.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82872.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82882.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82914.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83596.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-82863.md` — heuristic TIER 3/4
