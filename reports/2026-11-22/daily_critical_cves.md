# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-11-23 04:34:25Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-11-22`
- **Included count:** 4

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 4 | 2 | CVE-2026-134654 | Directly impacts Digital Identity by enabling unauthenticated account takeover via poisoned password-reset links in self-hosted email gateways, compromising credential recovery and session integrity. | Self-hosted email gateways are foundational to digital identity verification, but a default configuration flaw in Mailflare allows attackers to hijack password-reset flows. Organizations relying on email for MFA and account recovery should verify their APP_URL settings and patch immediately to prevent credential poisoning. |
| 4 | 2 | CVE-2026-134802 | Directly impacts self-hosted SSO/OIDC deployments by bypassing ProxyAuth domain restrictions, compromising authentication and authorization flows in the Digital Identity sector. | Self-hosted SSO providers like VoidAuth face a critical access control bypass that lets authenticated users evade domain restrictions. Organizations relying on OIDC for digital identity must patch immediately to protect authentication gateways. |
| 4 | 2 | CVE-2026-134819 | TIER 2 incorrect permission assignment in Delta Sharing server breaks data isolation for authenticated recipients, directly impacting Government inter-agency data exchange and regulated data governance. | Data sharing shouldn't mean data leakage. CVE-2026-134819 exposes a permission flaw in Delta Sharing that lets authenticated partners access unshared datasets, posing a direct risk to Government inter-agency exchanges and regulated data governance. Patch to v1.5.0+ immediately. |
| 3 | 2 | CVE-2026-134826 | Finance sector relevance due to unauthenticated manipulation of insurance contract templates and SSRF risks in CRM deployments. | Unauthenticated access to insurance CRM plugins can lead to contract tampering and internal network reconnaissance via SSRF. Organizations using erxes for financial workflows should verify plugin configurations and patch immediately. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-134624.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134803.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134804.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134808.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134814.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134816.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134821.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134827.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134830.md` — heuristic TIER 3/4
