# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-08-13 19:40:59Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-08-12`
- **Included count:** 9

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-11923 | Directly impacts enterprise IAM gateways and reverse proxies, enabling potential authentication bypass and token forgery in public-facing Digital Identity deployments. | IBM's Security Verify Access and Verify Identity Access gateways face a cryptographic validation flaw (CVE-2026-11923) that could allow attackers to bypass authentication controls. Organizations relying on these edge IAM proxies should prioritize patching to protect citizen and enterprise identity flows. |
| 5 | 2 | CVE-2026-12359 | Enterprise IAM reverse proxy flaw enabling unauthenticated sensitive data exposure, directly impacting the Digital Identity sector and public-facing authentication perimeters. | IBM’s Security Verify Access reverse proxy contains a high-impact parsing flaw that could bypass authentication checks on public-facing identity gateways. Organizations relying on enterprise IAM for citizen or customer access should prioritize patching to protect their digital identity perimeter. |
| 5 | 2 | CVE-2026-13267 | Directly impacts the Digital Identity sector by compromising core IAM gateways, enabling authenticated privilege escalation and bypassing authorization controls for public-facing services. | IBM’s Security Verify Access gateways face a critical authenticated privilege escalation flaw (CVE-2026-13267) that could allow attackers to hijack user privileges and bypass authorization controls. Organizations relying on this IAM infrastructure for public-facing or regulated services should prioritize patching and enforce strict MFA and monitoring. |
| 5 | 2 | CVE-2026-16860 | Foundational enterprise OS (IBM i) critical to Finance, Government, and Healthcare backend processing; RCE requires auth but impacts core transaction/record systems. | IBM i hosts mission-critical backend systems for finance, government, and healthcare. This TIER 2 RCE (CVE-2026-16860) requires authentication but demands prioritized patching for regulated sectors relying on AS/400 infrastructure. |
| 4 | 2 | CVE-2026-26035 | Critical WAF authentication bypass in foundational edge security infrastructure explicitly tied to protecting Digital Identity, Finance, Healthcare, and Government public-facing services. | A critical authentication bypass in Fortinet FortiWeb WAFs could grant attackers full administrative control over edge security controls protecting public-facing digital services. While requiring a specific non-default configuration, this flaw underscores the need to audit Radius/Wildcard settings across Finance, Healthcare, and Government deployments before patching. |
| 4 | 2 | CVE-2026-49473 | Authorization bypass in a widely used policy middleware undermines identity-aware access controls in public-facing web applications and APIs. | A trivial query-string manipulation can bypass Cedar policy enforcement in Express.js apps, granting unauthorized access to protected endpoints. Public services and regulated platforms relying on this middleware should patch to v0.3.0 immediately to safeguard identity-aware access controls. |
| 4 | 2 | CVE-2026-71193 | Cross-tenant DNS isolation bypass in OpenStack Designate threatens multi-tenant cloud deployments underpinning Government, Finance, and Healthcare DPI services. | A TIER 2 flaw in OpenStack Designate allows authenticated tenants to bypass DNS isolation and hijack co-located domains in multi-pool cloud setups. Public sector and regulated cloud operators should audit scheduler configurations and patch to maintain strict tenant separation. |
| 4 | 2 | CVE-2026-73289 | IAM policy evaluation flaw breaks JWT/OIDC group and role enforcement in distributed object storage, directly impacting Digital Identity and Government data sovereignty deployments. | A logic flaw in RustFS silently transposes IAM quantifiers, causing JWT-based allow/deny policies to fail. Critical for government and enterprise data lakes relying on OIDC/Keystone identity integration. |
| 4 | 2 | CVE-2026-73418 | Core Digital Identity/IdAM library (NextAuth.js) handling OAuth/OIDC sessions and tokens; trivial unauthenticated DoS impacts public-facing authentication endpoints. | A trivial malformed header can crash public-facing NextAuth.js endpoints, causing per-request DoS for widely deployed identity and session management flows. Patch or wrap getToken() in try/catch to keep citizen and enterprise auth services resilient. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2024-27253.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-59319.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-10534.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-10543.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12004.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12005.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12234.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12618.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13094.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13105.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13361.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13367.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13433.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13622.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14866.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15216.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15217.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15803.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16033.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16494.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16627.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16695.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16856.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16863.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16904.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16906.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16907.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16931.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17082.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17083.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17095.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17110.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17111.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17218.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17248.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17271.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17276.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17417.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17418.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17445.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17485.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17642.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18098.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18099.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18235.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18499.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18669.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18683.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18713.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18847.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18888.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18952.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19001.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19002.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19004.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19228.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19311.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19594.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19654.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19656.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-44741.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48551.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48553.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48554.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63293.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63294.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63296.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63297.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63299.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63300.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64639.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64826.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-6484.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64954.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65937.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65941.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66878.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66898.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67260.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70398.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70465.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70468.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71469.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71471.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71473.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72508.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72526.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73122.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73264.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73268.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73269.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73285.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73286.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73292.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73293.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73294.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73298.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73299.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73303.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73325.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73406.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73414.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73415.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73431.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73498.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73499.md` — heuristic TIER 3/4
