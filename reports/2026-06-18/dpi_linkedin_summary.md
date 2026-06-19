# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-06-19 08:14:39Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-06-18`
- **Included count:** 6

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-54103 | Affects Digital Identity and Government sectors by enabling unauthorized password changes in critical federal systems without authentication. | A TIER 2 vulnerability in U.S. government systems allows unauthenticated password resets via a missing auth check, highlighting risks to Digital Identity infrastructure. This could enable lateral movement within federal networks if exploited. |
| 4 | 2 | CVE-2025-10560 | Relevant to Digital Identity and Healthcare due to hardcoded AWS credentials in a time-tracking application that handles user authentication, access management, and potentially sensitive healthcare-related data. | A critical vulnerability in Worksnaps exposes hardcoded AWS root credentials, posing severe risks for organizations using this time-tracking tool. This highlights the importance of secure credential handling in digital identity systems—especially when managing sensitive healthcare or workforce data. |
| 4 | 2 | CVE-2026-40624 | Affects Government, Healthcare, and Finance sectors through networked security cameras used in regulated environments. | Critical RCE vulnerability in AVer surveillance cameras impacts government, healthcare, and finance sectors. While not internet-facing by default, internal network exposure poses serious risks for digital infrastructure security. |
| 4 | 2 | CVE-2026-54130 | Affects Digital Identity infrastructure by compromising authentication mechanisms in Microsoft 365 Copilot, an enterprise productivity tool handling sensitive user data. | Microsoft 365 Copilot suffers a critical missing auth vulnerability (CVE-2026-54130) that could expose sensitive data. While internal-only by design, this highlights risks in enterprise AI assistants and identity controls. |
| 4 | 2 | CVE-2026-8100 | Affects Digital Identity and Government sectors by enabling privilege escalation in enterprise automation platforms managing access control and compliance. | A critical path traversal flaw in Progress Chef 360 could let authenticated users bypass access controls, impacting digital identity management in government and enterprise environments. This highlights the need for secure configuration of internal infrastructure tools. |
| 3 | 2 | CVE-2026-55746 | Relevant to Digital Identity infrastructure as it affects Cotonti CMS user access control and session security through a stored XSS vulnerability in the PFS module. | A stored XSS flaw in Cotonti CMS's Personal File Storage module could compromise user sessions and enable phishing attacks within authenticated environments. This highlights the importance of input sanitization in identity-managed systems. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2025-15661.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-32392.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-32422.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-32424.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-32436.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-32437.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-53114.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-11958.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12390.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12505.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-38714.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-38715.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-38716.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-38717.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-38718.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-42487.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-42488.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-45696.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46580.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47647.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-49248.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50034.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-52866.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54104.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54220.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54223.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54224.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55204.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55237.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55742.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-8461.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-8811.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-9158.md` — heuristic TIER 3/4
