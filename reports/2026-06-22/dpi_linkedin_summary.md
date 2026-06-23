# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-06-23 08:35:01Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-06-22`
- **Included count:** 6

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-56422 | Impacts Digital Identity systems through authorization bypass via user-controlled keys in MISP threat intelligence platform. | A TIER 2 vulnerability in MISP allows authenticated users to manipulate object ownership and access controls, highlighting critical gaps in digital identity management within cybersecurity platforms. |
| 4 | 2 | CVE-2026-28381 | Relevant to Digital Identity and Government sectors due to unauthorized file access via Grafana's Snowflake plugin in enterprise environments with integrated identity management. | A TIER 2 vulnerability in Grafana's Snowflake datasource plugin could allow authenticated users to perform unauthorized file operations on the server, posing risks in government and enterprise monitoring systems where identity integration is critical. |
| 4 | 2 | CVE-2026-50170 | Affects web applications handling sensitive user data and could lead to credential leakage in digital identity contexts. | Angular apps using SSR and hydration may leak user-specific data through shared caching layers. This CVE impacts Digital Identity systems where authentication and session management are critical. |
| 3 | 2 | CVE-2026-42129 | Relevant to Digital Identity infrastructure as Grafana's role-based access control and authentication mechanisms are core components of identity management systems used for monitoring and observability. | A TIER 2 path traversal vulnerability in Grafana's Loki datasource plugin could allow authenticated users to access sensitive backend configuration data. While requiring Viewer-level credentials, this highlights risks in monitoring stacks that often integrate with digital identity frameworks. |
| 3 | 2 | CVE-2026-56323 | Affects Capgo's backend services used in mobile app deployment, potentially impacting Digital Identity if used in enterprise or healthcare apps. | Capgo vulnerability allows unauthenticated enumeration of app metadata—could aid attackers targeting enterprise mobile applications. A reminder to verify access controls on all backend endpoints. |
| 3 | 2 | CVE-2026-56324 | Affects Digital Identity systems by enabling DoS attacks on Capgo's device management and authentication flows for mobile applications. | Capgo's rate limit bypass vulnerability (CVE-2026-56324) could disrupt digital identity services managing Capacitor-based app updates. This TIER 2 issue highlights the importance of secure API design in regulated environments where device authentication and access control are critical. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2023-45795.md` — heuristic TIER 3/4
- `TIER_3_CVE-2023-45796.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-66389.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-10651.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-10658.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-10845.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-11373.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-11834.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12249.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12581.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12602.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-39904.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-41045.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-41048.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-42127.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-44271.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-44274.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-44914.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48502.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48506.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50171.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50178.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53539.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54100.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54267.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54268.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54273.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54277.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54278.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54290.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54293.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56104.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56109.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56423.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56425.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-6653.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-7166.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-8918.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-9071.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-9072.md` — heuristic TIER 3/4
