# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-09-21 04:32:16Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-09-20`
- **Included count:** 3

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-90817 | Unauthenticated RCE in REDCap directly threatens Healthcare and Government research infrastructure by exposing clinical trial data and patient records on internet-facing deployments. | Critical unauthenticated RCE in REDCap (CVE-2026-90817) puts healthcare and government research data at immediate risk. With thousands of internet-facing instances collecting clinical trial data, prompt patching is essential to protect sensitive health research infrastructure. |
| 3 | 2 | CVE-2026-94083 | Foundational IDS/IPS infrastructure securing network fabric for critical sectors and DPI services; default-enabled DoH2 parser crash poses high availability risk. | A type confusion flaw in Suricata's default DoH2 parser can crash network security sensors, blinding critical infrastructure monitoring. Immediate patching is vital to maintain visibility across regulated and public-sector networks. |
| 3 | 2 | CVE-2026-94109 | Government sector: Authenticated RCE in openEQUELLA threatens public research institutions and national libraries managing critical digital assets and research outputs. | Public sector research institutions and national libraries should prioritize patching openEQUELLA to mitigate an authenticated RCE flaw that risks compromising sensitive research data and institutional operations. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-82842.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94112.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94113.md` — heuristic TIER 3/4
