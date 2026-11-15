# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-11-15 06:46:31Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-11-14`
- **Included count:** 1

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 4 | 2 | CVE-2026-129456 | Foundational BGP routing software (FRRouting) widely deployed across ISP, government, finance, and healthcare networks; DoS/RCE potential disrupts critical internet routing infrastructure. | FRRouting's BGP daemon faces a high-impact use-after-free vulnerability that can crash routing sessions and disrupt critical infrastructure. While exploitation requires established peering, ISPs and regulated sectors relying on open-source routing should prioritize patching to maintain network stability. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-129429.md` — heuristic TIER 3/4
