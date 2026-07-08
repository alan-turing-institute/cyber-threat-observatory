# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-07-08 08:24:51Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-07-07`
- **Included count:** 7

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 4 | 2 | CVE-2026-12375 | A supply chain compromise in a WordPress plugin that enables unauthenticated admin access, impacting Digital Identity through authentication and access control vulnerabilities. | A recent supply chain attack on the Uncanny Automator Pro WordPress plugin demonstrates how compromised update infrastructure can lead to full administrative control over websites. This highlights the critical need for secure software distribution practices in digital identity management systems. |
| 4 | 2 | CVE-2026-34044 | Affects Digital Identity systems through an IDOR vulnerability in Coolify that allows unauthorized access to team logs, potentially exposing credentials and tokens. | A Cross-team IDOR flaw in Coolify (self-hosted PaaS) could let authenticated users access sensitive logs from other teams—highlighting the importance of proper authorization controls in multi-tenant infrastructures. #DigitalIdentity #CyberSecurity |
| 4 | 2 | CVE-2026-54602 | A cross-team LLM request/response disclosure (IDOR) in FastGPT affects Digital Identity systems by enabling unauthorized access to sensitive AI-generated data across authenticated teams. | A TIER 2 IDOR vulnerability in FastGPT allows authenticated users to access prompts and completions from other teams, highlighting risks in multi-tenant AI platforms. This underscores the importance of proper authorization controls in digital identity systems managing LLM workloads. |
| 4 | 2 | CVE-2026-55075 | Impacts Digital Identity by enabling account takeover through flawed OIDC email-based user matching in a development platform used for remote environments. | A TIER 2 vulnerability in Coder's OIDC implementation could allow attackers to hijack developer accounts via email-based user matching. This impacts enterprise DevOps workflows and digital identity systems where secure authentication is critical. |
| 4 | 2 | CVE-2026-59708 | A missing authorization flaw in Ghostfolio's API allows unauthenticated access to private portfolio data, affecting Digital Identity due to its handling of user authentication and financial account information. | A critical auth bypass in Ghostfolio could expose sensitive personal finance data. This highlights the importance of proper access controls in digital identity systems managing user portfolios. |
| 3 | 2 | CVE-2026-49229 | Relevant to Digital Identity due to session management flaw in OpenID-authenticated personal finance application, allowing disabled users to retain access via stale tokens. | A session validation flaw in a popular personal finance app could allow disabled users to maintain access to sensitive financial data. This highlights the importance of proper session invalidation in identity management systems. |
| 3 | 2 | CVE-2026-53751 | Relevant to Digital Identity infrastructure as DataEase handles user access management and data security in enterprise environments where identity systems are critical. | A high-severity RCE vulnerability in DataEase (CVE-2026-53751) demonstrates how flawed database validation can bypass authentication controls, impacting enterprise BI platforms that manage sensitive data. This underscores the importance of securing identity-access management tools within regulated environments. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2011-10043.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-11348.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-11610.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14868.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14904.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-42953.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-42958.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48949.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48950.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48951.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48952.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48953.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-49471.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50007.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50529.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50530.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55631.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55633.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55635.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56811.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57172.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57871.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58384.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58469.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58583.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-8377.md` — heuristic TIER 3/4
