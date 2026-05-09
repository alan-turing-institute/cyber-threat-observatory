# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-05-09 07:43:39Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-05-08`
- **Included count:** 4

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-41574 | Directly impacts Digital Identity infrastructure by enabling full account takeover through OAuth email verification bypass, affecting authentication and session management systems. | A critical OAuth vulnerability in Nhost allows attackers to hijack user accounts by exploiting email verification bypasses. This poses a serious risk to digital identity systems that rely on secure authentication flows. |
| 5 | 2 | CVE-2026-42160 | Affects Digital Identity infrastructure in data space ecosystems by allowing unauthorized access to catalog and connector registration via pending user accounts. | A critical authorization flaw in the Data Space Portal allows PENDING users to bypass approval workflows and access restricted APIs. This undermines trust models in data exchange environments where only approved participants should have access. |
| 4 | 2 | CVE-2025-69691 | Affects general infrastructure (network security appliances) that may support digital public services and government operations. | pfSense firewalls with default admin credentials are at risk of full system compromise via authenticated RCE. This highlights the importance of securing internal network infrastructure, especially in environments where such appliances underpin critical digital services. |
| 4 | 2 | CVE-2026-44313 | Relevant to Digital Identity due to NextAuth usage, authentication management, and session handling in a self-hosted bookmark manager. | A SSRF flaw in Linkwarden could let authenticated users access internal services—especially concerning for deployments using IAM roles. This highlights the importance of secure URL validation in identity-managed applications. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2013-10075.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-41500.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-41584.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-41588.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-44125.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-8076.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-8153.md` — heuristic TIER 3/4
