# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-10-19 02:18:25Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-10-18`
- **Included count:** 2

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 4 | 2 | CVE-2026-111990 | Unauthenticated SQLi in a Hospital Management System threatens patient data integrity and disrupts clinical scheduling operations. | Healthcare digital infrastructure faces critical risks from unpatched web apps. This TIER 2 SQLi in a hospital management system allows unauthenticated attackers to extract patient records or mass-cancel appointments, highlighting the need for strict input validation and WAF deployment in clinical environments. |
| 4 | 2 | CVE-2026-112002 | Directly impacts Digital Identity by allowing session hijackers to bypass Social/SSO provisioning, set local passwords, and enroll malicious 2FA, enabling persistent account takeover in self-hosted client portals. | Self-hosted client portals using Social/SSO login are vulnerable to permanent account takeover if sessions are compromised. This TIER 2 flaw bypasses password verification and 2FA enrollment, highlighting critical gaps in session management and identity lifecycle controls for public-facing services. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-112000.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112006.md` — heuristic TIER 3/4
