# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-04-07 07:24:44Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-04-06`
- **Included count:** 1

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 4 | 2 | CVE-2026-35030 | Relevant to Digital Identity due to JWT authentication and OIDC userinfo caching flaws that enable user impersonation in identity-aware systems. | A TIER 2 vulnerability in LiteLLM allows attackers to bypass authentication via cache key collisions in JWT/OIDC setups. While not default, this impacts digital identity infrastructure used in enterprise AI gateways. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2025-54328.md` — heuristic TIER 3/4
