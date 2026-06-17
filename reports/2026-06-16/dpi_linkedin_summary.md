# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-06-17 11:42:35Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-06-16`
- **Included count:** 9

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-35268 | Affects Oracle Identity Manager, a core component of enterprise Digital Identity infrastructure used for authentication and access control. | A critical RCE vulnerability in Oracle Identity Manager could compromise enterprise identity management systems. This highlights the importance of securing IdAM platforms that underpin digital identity infrastructure. |
| 4 | 2 | CVE-2026-35270 | Affects Oracle WebCenter Content, an enterprise content management system that integrates with Digital Identity infrastructure for secure document handling and collaboration. | A critical vulnerability in Oracle WebCenter Content (CVE-2026-35270) impacts enterprise digital identity systems by enabling privilege escalation within authenticated content management environments. This TIER 2 issue requires valid credentials to exploit but poses significant risks for post-compromise lateral movement in internal networks. |
| 4 | 2 | CVE-2026-46880 | Relevant to Government and Finance sectors as it affects Oracle's enterprise ERP system used in critical business operations. | A TIER 2 vulnerability in Oracle JD Edwards EnterpriseOne Tools could impact government and financial institutions relying on this ERP for core operations. Ensure your systems are patched and monitor internal access patterns. |
| 4 | 2 | CVE-2026-46976 | Affects Oracle Public Sector Payroll used by government entities, relevant to the Government DPI sector. | A TIER 2 vulnerability in Oracle's public sector payroll system highlights risks to government operations. While internal deployment limits exposure, it underscores the need for patch management and access controls in critical public infrastructure. |
| 4 | 2 | CVE-2026-49057 | Relevant to Digital Identity due to authorization bypass in WordPress plugin affecting user account and session management. | A TIER 2 vulnerability in the WordPress JobSearch plugin could allow unauthenticated attackers to gain administrative access, potentially compromising user accounts and session management — a key concern for digital identity systems. This highlights the importance of keeping web applications updated. |
| 3 | 2 | CVE-2026-35258 | Affects Oracle WebLogic Server, a key enterprise middleware platform used in general infrastructure deployments including government and commercial services. | Oracle WebLogic Server vulnerability (CVE-2026-35258) highlights risks in enterprise middleware—especially relevant for organizations relying on Fusion Middleware for critical digital services. Patch now available. |
| 3 | 2 | CVE-2026-46966 | Relevant to Government sector as an enterprise application used in public sector IT infrastructure for managing work processes and business operations. | A TIER 2 vulnerability in Oracle's Universal Work Queue impacts government digital services. This internal enterprise tool, part of Fusion Middleware, could allow low-privilege attackers with network access to compromise work queue systems—highlighting the need for secure deployment practices in public sector environments. |
| 3 | 2 | CVE-2026-49772 | Affects WordPress-based digital infrastructure, with potential DPI relevance in Digital Identity and General Infrastructure sectors due to unauthenticated SQLi in a widely-deployed plugin. | A critical blind SQL injection vulnerability in the popular 'The Events Calendar' WordPress plugin could allow attackers to access sensitive data without authentication. This poses risks for public-facing event systems, especially those integrated with identity or civic infrastructure. |
| 3 | 2 | CVE-2026-53849 | Relevant to Digital Identity due to authentication bypass through insecure Discord identity management (mutable display names vs. immutable user IDs). | A privilege escalation flaw in OpenClaw allows attackers to impersonate other Discord users by changing their display name, highlighting risks in AI agent access control systems that rely on mutable identity attributes. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2024-39575.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-11694.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-13036.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-14272.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-68045.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-69105.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-69107.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-69114.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-69159.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-69162.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-69163.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-69168.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-69177.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-71261.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-0646.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-10303.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-10649.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-10825.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-11317.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-11409.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12328.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12398.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12425.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-34894.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-34895.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-35262.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-35263.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-35269.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-35275.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-35279.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-35292.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-35296.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-35301.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-35306.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-35310.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-35313.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-35314.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-35317.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-35319.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-35325.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-35327.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-39437.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-39554.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-40754.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-40760.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-42089.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-44932.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46766.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46769.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46774.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46777.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46778.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46781.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46782.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46786.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46789.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46791.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46797.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46799.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46802.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46804.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46813.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46844.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46849.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46850.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46855.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46861.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46862.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46863.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46866.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46868.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46870.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46873.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46875.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46881.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46884.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46886.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46888.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46889.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46894.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46899.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46901.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46902.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46903.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46905.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46907.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46909.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46910.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46913.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46916.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46922.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46925.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46927.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46930.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46931.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46935.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46939.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46944.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46945.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46950.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46951.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46952.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46956.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46957.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46958.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46960.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46965.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46967.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46970.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46971.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47747.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47964.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48294.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48779.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48780.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53840.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53842.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53846.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53853.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53857.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53858.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53863.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-5416.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54191.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54198.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-6933.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-7273.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-8443.md` — heuristic TIER 3/4
