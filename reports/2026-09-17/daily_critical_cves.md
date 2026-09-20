# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-09-19 23:29:32Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-09-17`
- **Included count:** 11

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-62874 | Critical remote privilege escalation in Microsoft Azure Billing directly impacts financial transaction integrity and government cloud procurement systems. | A CVSS 10.0 flaw in Azure Billing could let attackers manipulate cloud invoices and subscriptions remotely. For finance and government sectors relying on cloud infrastructure, this underscores the need for strict billing anomaly monitoring and least-privilege access controls. |
| 5 | 2 | CVE-2026-85885 | Command injection in Microsoft 365 Copilot impacts Government, Finance, and Healthcare sectors relying on M365 as foundational infrastructure. | Microsoft 365 Copilot faces a critical command injection flaw (CVE-2026-85885) requiring authentication but enabling privilege escalation. This TIER 2 risk demands immediate attention from Government, Finance, and Healthcare sectors leveraging M365 for core digital services. |
| 5 | 2 | CVE-2026-90997 | Digital Identity sector: Core IdAM platform (Keycloak) authentication bypass impacting JWT/DPoP/TOTP replay protection, directly affecting digital identity infrastructure. | Keycloak deployments using MySQL/MariaDB in stateless mode face a high-severity auth bypass allowing replay of JWTs and TOTP codes. A simple JDBC config fix mitigates the risk, but public-facing IdPs should patch promptly to protect digital identity flows. |
| 4 | 2 | CVE-2026-14850 | TIER 2 IDOR in a municipal parking app enables mass account takeover, directly impacting government service delivery and citizen financial transactions. | A trivial password reset flaw in a city-run parking app allows attackers to hijack citizen accounts at scale. This TIER 2 vulnerability highlights how weak API validation in municipal digital services can quickly erode public trust and compromise financial data. |
| 4 | 2 | CVE-2026-54460 | Critical unauthenticated account takeover in healthcare appointment booking software, directly exposing patient data and clinic operations. | Healthcare clinics using OpenReception face immediate risk of full account takeover via a public API flaw. Patch to v1.1.1 immediately to safeguard patient appointment records and staff credentials. |
| 4 | 2 | CVE-2026-76949 | Core authentication library flaw enabling session hijacking and account takeover, directly impacting Digital Identity infrastructure. | A default configuration flaw in a widely used Elixir authentication library allows attackers to hijack active sessions via planted remember-me cookies. Public-facing services relying on this IdAM component should patch or adjust token validation settings immediately. |
| 4 | 2 | CVE-2026-77903 | Critical unauthenticated privilege escalation in Microsoft Dataverse, a foundational SaaS data platform explicitly underpinning Government, Finance, and Healthcare digital services. | Microsoft Dataverse faces a critical authentication bypass (CVE-2026-77903) that allows unauthenticated attackers to escalate privileges via spoofed tokens. As a foundational data layer for many regulated and public-sector applications, this TIER 2 flaw demands immediate monitoring and API access hardening. |
| 4 | 2 | CVE-2026-87701 | Foundational cloud database service explicitly tied to national digital infrastructure resilience, with privilege escalation risks impacting cross-tenant boundaries in regulated/public deployments. | Azure Cosmos DB’s critical injection flaw (CVE-2026-87701) underscores how foundational cloud databases underpin national digital infrastructure. Even with authentication barriers, privilege escalation risks demand strict IAM and private endpoint controls for public-sector and regulated workloads. |
| 3 | 2 | CVE-2026-63460 | Impacts the Finance/Payments sector by exposing headless commerce platforms handling digital transactions to unauthenticated DoS via public APIs. | A public-facing ReDoS flaw in a popular headless commerce platform could freeze payment and storefront APIs, highlighting the need for strict input validation in digital transaction infrastructure. Merchants should verify database configurations and patch promptly. |
| 3 | 2 | CVE-2026-78501 | General enterprise AI productivity layer widely deployed across government and regulated sectors; prompt injection risk threatens foundational public service data. | As public sector agencies scale AI assistants like Microsoft 365 Copilot, this TIER 2 prompt injection flaw highlights the critical need for robust guardrails against data exfiltration in foundational productivity tools. |
| 2 | 2 | CVE-2026-85878 | Tier 2 privilege escalation in Azure Database for PostgreSQL, a foundational cloud data service underpinning regulated Finance, Healthcare, and Government workloads. | A CVSS 9.9 authorization flaw in Azure Database for PostgreSQL highlights the risks of over-provisioned database roles in cloud environments. While it requires valid credentials, it underscores the need for strict RBAC and least-privilege controls in regulated digital infrastructure. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-15815.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-26950.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-28326.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48977.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50609.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50610.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-52727.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53557.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54520.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54524.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54596.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54597.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56795.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69843.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70009.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76154.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77615.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81442.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81445.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81446.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81516.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83946.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85719.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85887.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86688.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86862.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86864.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87742.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92942.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92943.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92950.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92952.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93014.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93292.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93393.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93435.md` — heuristic TIER 3/4
