# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-05-29 07:38:15Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-05-28`
- **Included count:** 3

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 4 | 2 | CVE-2026-24444 | Affects Digital Identity and Government sectors by enabling unauthorized root access to ISP-provided cable modems, potentially compromising network infrastructure and user sessions. | A critical hardcoded credential in SDMC NE6037 routers could allow attackers to gain full administrative control over ISP-provisioned devices. This poses a significant risk to both Digital Identity and Government sectors where such equipment is deployed as part of public infrastructure. |
| 4 | 2 | CVE-2026-32999 | Affects Digital Identity systems through authentication and access control implications in backup management, where tenant admins can escalate privileges and execute arbitrary code. | A TIER 2 RCE vulnerability in Comet Backup allows authenticated tenant administrators to execute arbitrary code on backup infrastructure. This impacts digital identity systems by enabling privilege escalation within backup environments that manage sensitive user data and access controls. |
| 4 | 2 | CVE-2026-9645 | Affects SCADA systems in critical infrastructure, potentially relevant to Government and Healthcare sectors. | A TIER 2 RCE vulnerability in ScadaBR highlights risks in industrial control systems. While internal-only by design, this flaw could enable privilege escalation in connected environments—especially those supporting healthcare or government operations. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-38702.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-38703.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-38704.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-38707.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46839.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-8809.md` — heuristic TIER 3/4
