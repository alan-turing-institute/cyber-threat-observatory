# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-10-19 00:05:42Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-10-17`
- **Included count:** 6

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 4 | 2 | CVE-2026-111880 | Foundational remote access infrastructure (FreeRDP) widely deployed across government, healthcare, and finance VDI environments, with a high-impact NTLM authentication flaw. | FreeRDP’s NTLM authentication flaw (CVE-2026-111880) poses a Tier 2 risk to cross-sector remote access infrastructure. While gated by a niche configuration, government and healthcare VDI deployments should verify callback settings and patch to 3.32.0 to prevent potential RCE or service disruption. |
| 4 | 2 | CVE-2026-111881 | Foundational remote desktop client widely deployed across Government, Healthcare, and Finance sectors for secure workforce connectivity, making it critical general infrastructure for regulated environments. | FreeRDP's clipboard channel vulnerability highlights a subtle but high-impact risk for remote workforce infrastructure. With patches available and workarounds like disabling clipboard redirection, regulated sectors should prioritize updates to protect government, healthcare, and finance remote access pipelines. |
| 4 | 2 | CVE-2026-111895 | Directly impacts Digital Identity by exploiting Entra ID SSO/OAuth claim mapping, enabling session hijacking and admin account takeover in enterprise helpdesk deployments. | Enterprise SSO integrations can become attack vectors when mutable claims like preferred_username are used as identity anchors. This TIER 2 flaw shows how a single misconfigured OAuth callback can lead to full admin takeover, underscoring the need for immutable identifier mapping in all digital identity deployments. |
| 4 | 2 | CVE-2026-111898 | Directly compromises SSO trust boundaries and account linking in Keycloak-integrated deployments, impacting the Digital Identity sector. | A simple username collision in a Keycloak SSO setup can bypass authentication and hijack admin accounts. A critical reminder for teams integrating external IdPs to enforce strict subject mapping and email verification. |
| 4 | 2 | CVE-2026-111911 | Direct Digital Identity sector match due to critical WebAuthn/passkey authentication bypass enabling full account takeover in public-facing platforms. | Modern authentication isn't foolproof: a missing challenge validation in phpMyFAQ's WebAuthn implementation allows unauthenticated passkey injection and full admin takeover. This TIER 2 flaw underscores why strict credential validation and secure defaults remain critical for any digital identity deployment. |
| 3 | 2 | CVE-2026-111923 | Unauthenticated DoS in enterprise MDM platform impacts device management availability for government and financial institutions relying on centralized fleet controls. | Enterprise MDM platforms are critical backbone infrastructure for public sector and financial device fleets. This unauthenticated DoS highlights the need for strict network segmentation on enrollment endpoints to maintain operational continuity. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-111912.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111914.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111919.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111922.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111924.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111927.md` — heuristic TIER 3/4
