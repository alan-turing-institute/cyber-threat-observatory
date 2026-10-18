# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-10-18 21:26:47Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-10-16`
- **Included count:** 2

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 4 | 2 | CVE-2026-111882 | Bypasses TOTP 2FA in SSO/OIDC flows (Keycloak/Entra ID), directly impacting enterprise Digital Identity and access management controls. | Enterprise SSO integrations are only as strong as their callback validation. This TIER 2 flaw shows how easily TOTP 2FA can be skipped when OIDC redirects aren't properly checked, underscoring the need for rigorous IdAM hardening across public-facing services. |
| 2 | 2 | CVE-2026-111924 | Enterprise MDM platform deployed in public sector IT; unauthenticated DoS could disrupt government device management and security compliance workflows. | Unauthenticated DoS in Fleet MDM could knock out public sector device management. Patch to v4.83.0 or block gzip headers at the proxy to keep endpoint compliance running. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-111881.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111914.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111917.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111919.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111922.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111927.md` — heuristic TIER 3/4
