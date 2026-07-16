# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-07-16 09:22:36Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-07-15`
- **Included count:** 9

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-53516 | This vulnerability affects Digital Identity systems by enabling account takeover through flawed OAuth implicit linking, exploiting authentication and authorization mechanisms in web applications. | A critical OAuth flaw in the Better Auth library could let attackers hijack user accounts by pre-registering emails and linking them via verified OAuth identities. This impacts digital identity infrastructure where secure authentication is paramount. |
| 4 | 2 | CVE-2026-35152 | Affects Digital Identity sector as Apache Fineract is a financial platform with authentication, authorization, and session management features typical in digital identity systems. | A SQL injection flaw in Apache Fineract's reporting API could let authenticated users access sensitive financial data. This highlights the importance of securing backend services in digital identity infrastructure. |
| 4 | 2 | CVE-2026-47164 | This vulnerability impacts Digital Identity systems by enabling account takeover through SSO misconfiguration, allowing attackers to impersonate users via compromised identity assertions. | A TIER 2 vulnerability in Vaultwarden allows attackers to hijack user accounts via SSO misconfigurations. This highlights the importance of verifying email claims from IdPs and properly securing SSO integrations in enterprise environments. |
| 4 | 2 | CVE-2026-49279 | Affects Digital Identity systems through session hijacking and account takeover via WebSocket XSS, with secondary Healthcare relevance in telemedicine platforms. | A stored XSS flaw in AVideo's WebSocket messaging system can enable session hijacking and account takeovers—critical for digital identity integrity. This vulnerability impacts healthcare platforms used for telemedicine, making it a key concern for DPI stakeholders. |
| 4 | 2 | CVE-2026-52887 | Affects Digital Identity systems by compromising user credentials and session management through SQL injection in NocoBase's notification plugin. | A critical SQL injection vulnerability in NocoBase's default notification plugin could allow attackers to exfiltrate user password hashes and execute arbitrary commands as the database superuser. This impacts digital identity systems where authentication, authorization, and session handling are core components. |
| 4 | 2 | CVE-2026-52893 | Impacts Digital Identity by enabling unauthorized OIDC account takeover through unconditional credential merging, affecting authentication and identity management systems. | A critical OIDC vulnerability in Wekan allows attackers to silently take over user accounts by merging credentials—highlighting the importance of secure identity provider configurations. Organizations using OIDC-enabled platforms must ensure proper verification mechanisms are in place. |
| 4 | 2 | CVE-2026-53444 | Affects Digital Identity and Government sectors by enabling privilege escalation in OIDC-integrated Wekan deployments, compromising access control and authentication mechanisms. | A critical privilege escalation flaw in Wekan (v9.31 and earlier) allows authenticated users to bypass OIDC authorization checks and escalate privileges to global admin when PROPAGATE_OIDC_DATA is enabled—especially concerning for government agencies relying on self-hosted open-source tools. |
| 3 | 2 | CVE-2026-55723 | Affects Kubernetes ingress controllers used in healthcare, finance, and government systems; impacts control plane configuration but not direct authentication mechanisms. | A TIER 2 vulnerability in F5's NGINX Ingress Controller could disrupt Kubernetes-based digital infrastructure. While it requires authenticated access, it highlights risks in control-plane configurations that support critical services like healthcare, finance, and government systems. |
| 3 | 2 | CVE-2026-58658 | Affects AI infrastructure platform that could be used in government or healthcare sectors, with potential for exposure of sensitive prompts/completions from LLM inference. | A newly disclosed vulnerability in GPUStack allows unauthenticated access to sensitive AI model logs and configurations. While not directly an identity issue, it highlights risks in AI infrastructure deployments that may support critical public services like government or healthcare systems. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-12281.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12382.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12997.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13385.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13585.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14251.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15804.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20153.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20158.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20187.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-33443.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-33445.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-40633.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-40957.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-42936.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-43637.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46458.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46709.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-49445.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50124.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50144.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50562.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-52865.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-52869.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-52870.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53512.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54458.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55242.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56434.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56687.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58558.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58659.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58660.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59255.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59762.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59950.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60005.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61449.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61835.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61866.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62948.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-8919.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-8920.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-9770.md` — heuristic TIER 3/4
