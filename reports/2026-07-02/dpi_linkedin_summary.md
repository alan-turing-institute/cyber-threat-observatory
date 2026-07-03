# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-07-03 09:18:50Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-07-02`
- **Included count:** 9

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-57100 | This vulnerability affects Microsoft Entra Provisioning Service (SyncFabric), a core component of Digital Identity infrastructure, enabling privilege escalation in authenticated enterprise environments. | A critical SSRF flaw in Microsoft's Entra ID provisioning service could allow attackers to escalate privileges within identity management systems. This TIER 2 vulnerability highlights the importance of securing internal identity components, especially as enterprises increasingly rely on cloud-based IdAM platforms for access control and user authentication. |
| 5 | 2 | CVE-2026-59099 | Affects Digital Identity infrastructure by compromising authentication mechanisms and session security in Apereo CAS servers. | A critical cryptographic flaw in Apereo CAS allows attackers to recover plaintext conversation state from login pages, potentially leading to session hijacking. This impacts digital identity systems that rely on secure authentication flows. |
| 4 | 1 | CVE-2022-50973 | Affects Yonyou KSOA ERP systems, potentially used in Finance and Government sectors for enterprise operations. | A critical unauthenticated RCE vulnerability in Yonyou's ERP system could allow attackers to gain full control over enterprise servers. This poses a significant risk to financial and government deployments relying on such platforms. |
| 4 | 2 | CVE-2026-13383 | Affects network security infrastructure (firewalls) used in government and enterprise environments, falling under Government and General Infrastructure DPI categories. | A TIER 2 vulnerability in WatchGuard Fireware OS could allow authenticated attackers to gain full administrative control over critical firewall devices. This poses a significant risk to government and enterprise networks relying on these systems for perimeter protection. |
| 4 | 2 | CVE-2026-41106 | Relevant to Digital Identity due to integration with Microsoft 365's authentication and access control systems, enabling phishing attacks that could compromise user credentials. | A TIER 2 vulnerability in Microsoft 365 Copilot highlights a critical open redirect flaw that could be exploited for phishing attacks within enterprise environments. This underscores the importance of securing AI assistants integrated into identity management frameworks. |
| 4 | 2 | CVE-2026-45499 | Affects Microsoft's Azure OpenAI Service, which operates within enterprise digital identity ecosystems and can enable privilege escalation in authenticated access scenarios. | A critical SSRF vulnerability in Azure OpenAI could allow authenticated attackers to escalate privileges and access internal resources. This highlights the importance of securing AI infrastructure components integrated with identity management systems. |
| 4 | 2 | CVE-2026-54402 | Affects enterprise networking infrastructure (UniFi OS) that supports digital identity and healthcare networks through network management and control planes. | Ubiquiti UniFi OS devices used in enterprise networking are now vulnerable to a critical command injection flaw (CVE-2026-54402). This could allow attackers with low privileges to fully compromise affected systems, impacting the broader digital infrastructure that supports healthcare and identity services. |
| 4 | 2 | CVE-2026-54998 | Affects Microsoft 365's Digital Identity infrastructure through privilege escalation in Exchange Online, a core IdAM component. | Microsoft Exchange Online's authorization flaw (CVE-2026-54998) could let authenticated attackers escalate privileges—highlighting the need for robust identity management in cloud email services. This TIER 2 vulnerability underscores ongoing risks in Microsoft 365's digital identity stack. |
| 3 | 2 | CVE-2026-58467 | Relevant to Government and General Infrastructure sectors due to potential use in public-sector content management systems. | A path traversal flaw in Cockpit CMS could allow attackers to access sensitive files or execute code, particularly in internal deployments. This highlights the importance of securing content management platforms used by government agencies and other regulated environments. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2025-58902.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-69094.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-69152.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12167.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12168.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12413.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13050.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13053.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13054.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13079.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13084.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13131.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13132.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13251.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13384.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-27402.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-27404.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-27412.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-33592.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-39448.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-42382.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-44941.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50281.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50722.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54405.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54407.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54408.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54409.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55110.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55111.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55113.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55114.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55115.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55116.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55117.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55118.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55119.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55950.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56004.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56037.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56842.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57264.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57266.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57267.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57268.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57270.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57272.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57273.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57274.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57275.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57276.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57277.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57278.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57343.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57345.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57349.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57356.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57358.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57426.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57671.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57674.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57679.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57687.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57748.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57749.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57756.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57757.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57758.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57766.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-5821.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58465.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58652.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59098.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-8247.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-8699.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-9563.md` — heuristic TIER 3/4
