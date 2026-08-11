# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-08-11 15:36:43Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-08-10`
- **Included count:** 8

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-72564 | Breaks multi-tenant isolation in a zero-trust identity platform, enabling cross-organizational lateral movement via token reuse. | Zero-trust platforms are only as strong as their tenant isolation. This critical flaw in Pangolin lets attackers pivot across organizations using a single valid token, highlighting the need for strict scope validation in identity-aware access systems. |
| 5 | 2 | CVE-2026-72575 | Unauthenticated authorization bypass in daptin’s core permission middleware directly compromises OAuth/OIDC and JWT-based identity management, impacting Digital Identity infrastructure. | A zero-auth bypass in daptin’s permission layer lets attackers manipulate user groups and escalate privileges without credentials. For teams relying on self-hosted BaaS for citizen or enterprise identity services, this underscores the critical need to harden OAuth/OIDC backends and restrict API exposure. |
| 4 | 2 | CVE-2026-10754 | Session/crypto signature bypass in Pega Platform directly threatens government citizen portals and financial services workflows relying on its case management and authentication controls. | Pega Platform’s Session API vulnerability (CVE-2026-10754) enables cryptographic signature bypass, posing a direct risk to government citizen services and financial workflows. Patching is critical for regulated deployments managing sensitive public and customer data. |
| 4 | 2 | CVE-2026-47754 | Unauthenticated path traversal in Metacat 2.x threatens federally funded scientific data repositories (NSF DataONE, USGS, NOAA), directly impacting Government sector research infrastructure and sensitive data assets. | A trivial, unauthenticated path traversal in Metacat 2.x is exposing federally funded scientific data networks to immediate credential and dataset theft. With verified PoCs and default-exposed endpoints, government research infrastructure requires urgent patching or API lockdowns to secure public data assets. |
| 4 | 2 | CVE-2026-72584 | Directly compromises OTP-based account recovery and authentication flows in a BaaS framework, impacting Digital Identity integrity and access control. | A race condition in FastSchema’s account recovery flow lets attackers bypass OTP limits and brute-force 6-digit codes by default. For any organization relying on BaaS for user management, this underscores the critical need for atomic auth checks and external rate limiting to protect digital identity systems. |
| 4 | 2 | CVE-2026-72688 | Unauthenticated remote read of legally binding contracts in a public-facing e-signature platform directly impacts government procurement, citizen services, and financial compliance workflows. | Public-facing e-signature platforms are critical nodes in digital governance and financial compliance. This unauthenticated flaw in OpenSign allows attackers to bypass all access controls and exfiltrate legally binding contracts, underscoring the need for strict authentication in citizen-facing digital service infrastructure. |
| 4 | 2 | CVE-2026-72692 | Cross-sector e-signature infrastructure flaw enabling unauthenticated document decline and audit trail falsification, impacting Government, Finance, and Healthcare compliance workflows. | Unauthenticated attackers can now forge e-signature declines and tamper with audit trails in OpenSign, posing direct compliance and legal risks for government, finance, and healthcare digital services. Patch immediately to protect regulated document workflows. |
| 3 | 2 | CVE-2026-66738 | RCE in SPIP CMS, widely deployed by government and civic organizations for public-facing portals, posing a direct risk to institutional web infrastructure. | Public-sector and civic websites running SPIP need to patch immediately: a new authenticated RCE flaw targets SQLite-backed instances, highlighting the ongoing risk to institutional web infrastructure. Upgrade to 4.4.18 or restrict backend access to protect government and academic portals. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2025-15681.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-15682.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13717.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14450.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14886.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15467.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15581.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18608.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18611.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18617.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18618.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18620.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18621.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18941.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18947.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18949.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18950.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18951.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18982.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19387.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19389.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19433.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48158.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48160.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48161.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55814.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63622.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65942.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65948.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-6791.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70622.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71576.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72566.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72568.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72572.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72573.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72577.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72578.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72579.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72718.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72734.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72864.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72870.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72883.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72886.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72900.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72909.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72910.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72911.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72913.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72915.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73030.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-8718.md` — heuristic TIER 3/4
