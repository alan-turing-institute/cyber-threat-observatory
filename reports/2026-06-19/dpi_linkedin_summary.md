# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-06-20 08:37:57Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-06-19`
- **Included count:** 4

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-45480 | Relevant to Digital Identity and Government sectors as it impacts Azure Active Directory's authentication mechanisms, potentially allowing unauthorized privilege escalation in enterprise and public sector identity management systems. | A critical vulnerability in Azure AD could allow attackers to escalate privileges through flawed authentication controls. This poses a significant risk for government agencies and enterprises relying on Microsoft’s cloud identity platform for secure access management. |
| 4 | 2 | CVE-2026-48582 | Relevant to Digital Identity as it affects authorization mechanisms in Microsoft Exchange Online, a core component of enterprise identity and access management systems. | A TIER 2 privilege escalation vulnerability in Microsoft Exchange Online highlights risks in cloud-based email services that are foundational to enterprise digital identity frameworks. Organizations using Microsoft 365 should review access controls and apply security updates to mitigate potential lateral movement risks. |
| 4 | 2 | CVE-2026-56081 | Affects Digital Identity infrastructure by enabling pre-account takeover and permanent lockout of legitimate users through flawed authentication logic. | A critical auth flaw in Capgo allows attackers to hijack accounts before verification, locking out real users with enforced 2FA. A stark reminder of how weak identity validation can undermine digital trust. |
| 4 | 2 | CVE-2026-56082 | Affects Digital Identity infrastructure by compromising authentication token management in app update systems, enabling cross-tenant billing manipulation. | A critical access control flaw in Capgo's Supabase backend allows unauthenticated attackers to manipulate billing records across organizations. This vulnerability impacts how identity and session-based credentials are managed in mobile application distribution ecosystems. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2016-20087.md` — heuristic TIER 3/4
- `TIER_3_CVE-2016-20088.md` — heuristic TIER 3/4
- `TIER_3_CVE-2016-20089.md` — heuristic TIER 3/4
- `TIER_3_CVE-2016-20090.md` — heuristic TIER 3/4
- `TIER_3_CVE-2016-20092.md` — heuristic TIER 3/4
- `TIER_3_CVE-2016-20093.md` — heuristic TIER 3/4
- `TIER_3_CVE-2016-20094.md` — heuristic TIER 3/4
- `TIER_3_CVE-2016-20095.md` — heuristic TIER 3/4
- `TIER_3_CVE-2017-20252.md` — heuristic TIER 3/4
- `TIER_3_CVE-2017-20253.md` — heuristic TIER 3/4
- `TIER_3_CVE-2017-20259.md` — heuristic TIER 3/4
- `TIER_3_CVE-2017-20262.md` — heuristic TIER 3/4
- `TIER_3_CVE-2017-20266.md` — heuristic TIER 3/4
- `TIER_3_CVE-2017-20267.md` — heuristic TIER 3/4
- `TIER_3_CVE-2017-20269.md` — heuristic TIER 3/4
- `TIER_3_CVE-2017-20270.md` — heuristic TIER 3/4
- `TIER_3_CVE-2017-20272.md` — heuristic TIER 3/4
- `TIER_3_CVE-2017-20273.md` — heuristic TIER 3/4
- `TIER_3_CVE-2017-20274.md` — heuristic TIER 3/4
- `TIER_3_CVE-2017-20275.md` — heuristic TIER 3/4
- `TIER_3_CVE-2017-20276.md` — heuristic TIER 3/4
- `TIER_3_CVE-2017-20277.md` — heuristic TIER 3/4
- `TIER_3_CVE-2017-20279.md` — heuristic TIER 3/4
- `TIER_3_CVE-2017-20281.md` — heuristic TIER 3/4
- `TIER_3_CVE-2019-25750.md` — heuristic TIER 3/4
- `TIER_3_CVE-2019-25756.md` — heuristic TIER 3/4
- `TIER_3_CVE-2019-25759.md` — heuristic TIER 3/4
- `TIER_3_CVE-2019-25762.md` — heuristic TIER 3/4
- `TIER_3_CVE-2020-37251.md` — heuristic TIER 3/4
- `TIER_3_CVE-2020-37253.md` — heuristic TIER 3/4
- `TIER_3_CVE-2020-37254.md` — heuristic TIER 3/4
- `TIER_3_CVE-2021-47985.md` — heuristic TIER 3/4
- `TIER_3_CVE-2022-50971.md` — heuristic TIER 3/4
- `TIER_3_CVE-2023-54353.md` — heuristic TIER 3/4
- `TIER_3_CVE-2023-54357.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-71326.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-7737.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-11576.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12104.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-3195.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-32208.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-4026.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-4027.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47645.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48089.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48138.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48139.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48140.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48715.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-49286.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-49293.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-49295.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-49346.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56142.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56208.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56209.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56210.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56211.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-8805.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-8806.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-9375.md` — heuristic TIER 3/4
