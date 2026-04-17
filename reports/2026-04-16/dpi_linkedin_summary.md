# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-04-17 07:19:05Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-04-16`
- **Included count:** 2

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 4 | 2 | CVE-2026-6270 | A critical authentication bypass in Fastify's middleware engine affects general infrastructure, with potential impact on digital identity, healthcare, finance, and government systems that use this framework. | A critical auth bypass in @fastify/middie (CVSS 9.1) silently skips security controls for protected routes in child plugin scopes—impacting backend services across digital identity, healthcare, finance, and government infrastructures. |
| 4 | 2 | CVE-2026-6350 | Affects Digital Identity infrastructure through email security products that protect authentication and access control in enterprise environments. | A critical stack-based buffer overflow in Openfind's MailGates/MailAudit email security systems could enable unauthenticated RCE, posing a significant risk to enterprise digital identity infrastructure. This TIER 2 vulnerability requires immediate attention from organizations relying on these products for internal email filtering and security. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-37338.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-37345.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-40504.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-6349.md` — heuristic TIER 3/4
