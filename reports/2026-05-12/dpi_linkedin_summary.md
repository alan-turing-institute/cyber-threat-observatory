# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-05-13 07:47:40Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-05-12`
- **Included count:** 6

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-40379 | Affects Azure Entra ID's core identity and access management infrastructure, specifically targeting authentication mechanisms and user impersonation capabilities. | Microsoft's Azure Entra ID faces a TIER 2 vulnerability (CVE-2026-40379) that could allow attackers to spoof users and bypass MFA/Conditional Access policies—critical for any organization relying on cloud identity services. This highlights the importance of securing pass-through authenticator systems. |
| 4 | 2 | CVE-2026-26083 | Affects Digital Identity infrastructure as FortiSandbox systems are integrated with identity management solutions for secure access control within enterprise environments. | A critical missing authorization flaw in Fortinet's FortiSandbox suite could allow unauthenticated RCE, impacting digital identity ecosystems where these platforms manage user access to security tools. Organizations must ensure proper network segmentation and apply patches immediately. |
| 4 | 2 | CVE-2026-33117 | Relevant to Digital Identity due to authentication bypass in Azure SDK for Java, which integrates with Microsoft Entra ID and impacts cloud identity management. | A critical auth bypass vulnerability (CVE-2026-33117) in Microsoft's Azure SDK for Java could undermine cloud identity systems. This TIER 2 flaw affects developers using the SDK to interact with Azure services, potentially enabling unauthorized access to sensitive cloud resources—especially concerning for organizations relying on Microsoft Entra ID for authentication. |
| 4 | 2 | CVE-2026-42288 | Affects Digital Identity and Government sectors, as ChurchCRM manages sensitive member records and financial data in religious and public sector deployments. | ChurchCRM's setup wizard vulnerability allows unauthenticated RCE, posing a risk to digital identity and government infrastructure. Organizations using ChurchCRM should ensure they're running patched versions or restrict access to the setup endpoint. |
| 4 | 2 | CVE-2026-43992 | Exposure of BIP-39 mnemonics in cleartext JSONs affects blockchain-based digital identity and authentication systems. | A critical credential exposure in an AI agent platform could compromise blockchain identities. This CVE highlights the importance of secure credential handling in decentralized systems. |
| 3 | 2 | CVE-2026-42300 | Affects DevGuard, a software supply chain security platform with Kratos identity integration, relevant to Digital Identity and Government sectors. | A TIER 2 vulnerability in DevGuard allows attackers to bypass authentication using a known Kratos UUID. This impacts software supply chain security tools used by government and healthcare organizations. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2025-40949.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20794.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-25786.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-25787.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-40402.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-41096.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-41551.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-42823.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-42854.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-44547.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-7428.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-8072.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-8430.md` — heuristic TIER 3/4
