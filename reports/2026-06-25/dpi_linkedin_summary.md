# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-06-26 09:04:54Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-06-25`
- **Included count:** 6

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-11800 | High-impact JWT algorithm confusion in Keycloak affects Digital Identity systems through federated user impersonation and access control bypass. | A critical JWT vulnerability in Red Hat's Keycloak (CVE-2026-11800) allows attackers with valid client credentials to impersonate any federated user—highlighting the need for robust identity federation security. This TIER 2 flaw underscores risks in enterprise SSO environments where Keycloak serves as a central identity provider. |
| 5 | 2 | CVE-2026-9099 | High-impact privilege escalation in Keycloak IdAM system affects Digital Identity infrastructure and could lead to full realm takeover. | A TIER 2 vulnerability in Red Hat's Keycloak build allows low-privilege users to escalate privileges and take over entire identity realms. This highlights the critical need for robust authorization controls in digital identity systems. |
| 5 | 2 | CVE-2026-9800 | High-severity authorization bypass in Keycloak affects Digital Identity infrastructure by allowing authenticated users to bypass all RBAC, scope checks, and UMA permissions. | A critical authorization bypass vulnerability (CVE-2026-9800) in Red Hat's Keycloak Policy Enforcer could allow attackers with valid tokens to access protected resources without proper roles or permissions. This impacts Digital Identity systems that rely on Keycloak for centralized authentication and access control. |
| 4 | 2 | CVE-2026-40702 | Affects Energy infrastructure through EV charging station management systems, which are part of critical digital public infrastructure for transportation and smart grid operations. | A TIER 2 vulnerability in EVoke's Charging Station Management System could allow attackers to impersonate charging stations and compromise entire EV networks. This highlights the need for robust authentication in energy infrastructure deployments. |
| 4 | 2 | CVE-2026-55413 | Impacts Digital Identity as ToolJet is used for building internal tools involving user management, access control, and session handling. | A TIER 2 vulnerability in ToolJet allows authenticated users to execute RCE via malicious plugins, posing a risk to enterprise identity and access management systems. This highlights the importance of securing internal tooling platforms that handle sensitive workflows. |
| 4 | 2 | CVE-2026-9086 | Relevant to Digital Identity infrastructure as it affects Keycloak, an identity and access management (IAM) solution used in enterprise environments. | A TIER 2 XSS vulnerability in Red Hat's Keycloak IAM system could allow attackers with admin privileges to execute arbitrary code. While not internet-exposed by default, this highlights the importance of securing identity management platforms in enterprise and government deployments. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2021-47986.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-11310.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-11999.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12244.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12246.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12473.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12490.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12844.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12897.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12921.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13311.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13351.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-22879.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-2815.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-33612.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-41566.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-4526.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46606.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46733.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46734.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46735.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47145.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47146.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47147.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47148.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47149.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47150.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47151.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47152.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47153.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47154.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-4930.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-49839.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-5305.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54033.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54479.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54828.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54842.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54848.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55487.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55693.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55895.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55958.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55961.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56014.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56042.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56091.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56123.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56445.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56767.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56786.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56789.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56790.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57453.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57455.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57456.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57520.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57589.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-8592.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-8666.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-9219.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-9220.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-9221.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-9650.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-9716.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-9717.md` — heuristic TIER 3/4
