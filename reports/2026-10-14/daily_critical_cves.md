# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-10-18 15:46:00Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-10-14`
- **Included count:** 4

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 4 | 2 | CVE-2026-111882 | Directly impacts Digital Identity by bypassing TOTP 2FA in OIDC/SSO flows (Keycloak, Entra ID), risking account takeover in government and enterprise support portals. | A TOTP 2FA bypass in phpMyFAQ’s SSO callbacks shows how easily multi-factor protections can be circumvented when OIDC integrations skip local session checks. Organizations using Keycloak or Entra ID for public-facing portals should patch immediately to protect identity workflows. |
| 4 | 2 | CVE-2026-111911 | Directly compromises WebAuthn passkey registration and bypasses TOTP 2FA in public-facing knowledge bases, impacting Digital Identity and access controls for regulated customer portals. | A critical TIER 2 flaw in phpMyFAQ lets attackers silently inject WebAuthn passkeys into any account, completely bypassing 2FA. For organizations relying on public-facing portals, this underscores the need to audit default auth configurations and patch identity controls immediately. |
| 3 | 2 | CVE-2026-111880 | General infrastructure (FreeRDP) widely deployed in government and healthcare for remote access/VDI, impacting cross-sector availability. | FreeRDP's NTLM auth path has a heap overflow that could crash remote desktop services in government and healthcare VDI deployments. Patch to 3.32.0 or disable the niche callback to maintain availability. |
| 3 | 2 | CVE-2026-111924 | General infrastructure MDM platform deployed in government and healthcare; unauthenticated DoS halts endpoint management. | Endpoint management is critical infrastructure for government and healthcare device security. This TIER 2 DoS in Fleet highlights the need for reverse proxy controls to block trivial gzip-bomb attacks on agent APIs. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-111881.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111897.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111905.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111906.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111907.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111908.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111909.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111912.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111914.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111919.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111922.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111923.md` — heuristic TIER 3/4
