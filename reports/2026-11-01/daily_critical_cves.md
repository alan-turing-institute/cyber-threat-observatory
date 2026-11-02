# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-11-02 02:34:36Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-11-01`
- **Included count:** 3

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 2 | 2 | CVE-2026-120232 | TIER 2 local privilege escalation in endpoint restoration software deployed on government kiosks and healthcare terminals, posing post-compromise risks to public-facing infrastructure. | A ready-to-use PoC for a TIER 2 kernel driver flaw in endpoint restoration software highlights the hidden risks in kiosk and public terminal management. Even without remote triggers, local privilege escalation on government and healthcare kiosks demands immediate patching and EDR monitoring. |
| 2 | 2 | CVE-2026-84170 | General-purpose Java web framework deployed in government and critical public services; unbounded uploads risk DoS for citizen-facing applications. | Public sector apps built on Apache Wicket face DoS risks from unbounded file uploads. Patch to 9.25.0/10.12.0 or enforce reverse-proxy limits to safeguard critical infrastructure. |
| 2 | 2 | CVE-2026-95863 | Tier 2 passive XSS in Apache Wicket, a foundational Java web framework deployed across enterprise and government-facing applications. | A configuration-triggered XSS flaw in Apache Wicket could silently compromise sessions on public-facing enterprise and government portals. Teams should audit markup IDs and patch to 8.20.0/9.25.0/10.12.0 to secure web infrastructure. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-120241.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120308.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82840.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82956.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83559.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84231.md` — heuristic TIER 3/4
