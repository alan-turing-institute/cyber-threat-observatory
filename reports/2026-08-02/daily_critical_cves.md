# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-08-03 05:04:45Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-08-02`
- **Included count:** 2

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2025-71400 | Directly impacts Digital Identity infrastructure by allowing authenticated users to delete other users' passkeys, disrupting access control and credential management. | A Tier 2 flaw in a popular TypeScript auth library lets compromised accounts delete other users' passkeys. For DPI and regulated services relying on passkeys for secure access, this IDOR vulnerability highlights the critical need for strict ownership validation in identity management endpoints. |
| 4 | 2 | CVE-2025-71399 | TIER 2 path normalization bypass in Better Auth undermines rate limiting and access controls on public-facing authentication endpoints, directly impacting Digital Identity assurance. | A trivial path normalization flaw in the popular Better Auth library allows attackers to bypass rate limits and disabled routes on login endpoints. For DPI and regulated web services, this means brute-force and credential stuffing defenses can be easily circumvented—patch to v1.4.5+ or enforce proxy-level URL normalization. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2025-71401.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-10848.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-3245.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65321.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67356.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68580.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68582.md` — heuristic TIER 3/4
