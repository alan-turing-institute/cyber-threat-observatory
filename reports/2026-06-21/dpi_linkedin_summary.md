# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-06-22 07:30:41Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-06-21`
- **Included count:** 4

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 4 | 2 | CVE-2026-56239 | Affects Digital Identity and Finance sectors through privilege escalation in Capgo's Supabase backend billing system, enabling unauthorized credit depletion and fraudulent billing events. | Capgo's Supabase backend vulnerability allows authenticated users to manipulate billing data for other organizations. This highlights the importance of securing database functions with SECURITY DEFINER attributes and enforcing proper authorization checks in financial systems. |
| 4 | 2 | CVE-2026-56253 | Affects Digital Identity infrastructure by exposing user account information and roles through improper access control in a Supabase RPC function. | A Capgo vulnerability allows unauthenticated enumeration of organization members via Supabase RPC, potentially exposing email addresses and roles. This impacts digital identity systems where access control is critical. |
| 3 | 2 | CVE-2025-71348 | Affects AI/ML supply chains used in Digital Identity and Healthcare systems, where pickle deserialization can lead to RCE. | A deserialization flaw in the picklescan Python library could enable attackers to execute arbitrary code during ML model scanning—particularly concerning for AI-powered identity management and clinical applications. This highlights risks in AI supply chains that underpin digital public infrastructure. |
| 3 | 2 | CVE-2026-56229 | Relevant to Digital Identity due to API key and access control bypass in a SaaS platform used for mobile app builds. | A TIER 2 vulnerability in Capgo's cloud service allows attackers with limited API credentials to access build jobs from other applications. This highlights the importance of robust authorization checks in SaaS platforms handling sensitive mobile app development workflows. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2025-71351.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-71357.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12779.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12781.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12782.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12786.md` — heuristic TIER 3/4
