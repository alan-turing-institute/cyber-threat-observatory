# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-07-13 07:35:03Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-07-12`
- **Included count:** 3

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 4 | 2 | CVE-2026-15479 | Affects Digital Identity systems by enabling unauthorized admin access to enterprise network devices, compromising authentication mechanisms. | A critical vulnerability in H3C NX15 routers allows attackers to change admin passwords without authentication, potentially leading to full network compromise. This highlights the importance of securing internal network infrastructure and managing administrative credentials properly. |
| 4 | 2 | CVE-2026-56238 | Exposes financial and user metrics through an identity-access management context, relevant to Digital Identity infrastructure. | A Capgo vulnerability reveals unauthenticated access to sensitive financial KPIs via Supabase PostgREST, highlighting risks in backend services that manage digital identity and account data. This underscores the importance of securing internal APIs handling user metrics. |
| 4 | 2 | CVE-2026-56308 | Affects Digital Identity by enabling unauthorized email address changes without re-authentication, compromising account recovery and access control. | A critical vulnerability in Capgo's email change functionality allows attackers to takeover accounts by simply changing the primary email without verification. This bypasses MFA and recovery controls—highlighting the importance of secure identity management in cloud-based developer platforms. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-10666.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-10667.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15480.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15484.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15498.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15506.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58596.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61876.md` — heuristic TIER 3/4
