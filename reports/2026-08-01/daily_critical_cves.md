# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-08-02 06:59:32Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-08-01`
- **Included count:** 10

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2025-71403 | Digital Identity sector: enables token theft and account takeover via open redirect in a widely used authentication library. | A TIER 2 flaw in the popular better-auth library allows attackers to bypass origin checks and steal session tokens via phishing links. Organizations relying on this stack for public-facing identity services should patch to v1.1.21+ to prevent account takeovers. |
| 5 | 2 | CVE-2026-67328 | Directly impacts Digital Identity infrastructure via SSO/authentication framework flaws enabling account takeover, with broad applicability to regulated sectors relying on centralized IdAM. | A new TIER 2 vulnerability in a popular SSO framework exposes account takeover risks through SAML assertion bypasses and provider registration flaws. While configuration barriers limit mass exploitation, regulated sectors and public services relying on centralized identity management should prioritize patching and audit self-service SSO settings. |
| 5 | 2 | CVE-2026-67330 | Directly impacts Digital Identity infrastructure by enabling account takeover and session manipulation via SCIM/SAML/OIDC provider ID collisions. | A critical authorization bypass in a widely used identity management plugin allows attackers to hijack accounts and bypass SSO deprovisioning. Organizations relying on SCIM for enterprise identity lifecycle must patch immediately to prevent mass account takeover. |
| 5 | 2 | CVE-2026-67331 | TIER 2 authorization bypass in the @better-auth/scim plugin enables horizontal privilege escalation and hijacking of enterprise identity provisioning/SSO syncs, directly impacting Digital Identity infrastructure. | A default configuration flaw in a popular web auth framework's SCIM plugin allows any authenticated user to hijack enterprise identity provisioning flows. Organizations relying on SCIM for SSO syncs should enforce provider ownership immediately to prevent horizontal privilege escalation. |
| 5 | 2 | CVE-2026-67337 | Digital Identity sector: 2FA bypass in a widely adopted authentication library undermines MFA enforcement and session integrity for public-facing applications. | A 2FA bypass in the popular better-auth library highlights how performance optimizations like session caching can accidentally undermine multi-factor authentication. Security teams should audit auth configurations and patch immediately to safeguard digital identity assurance. |
| 4 | 2 | CVE-2026-55735 | Digital Identity sector: JWT authentication library flaw enables unauthenticated session revocation, impacting public-sector and enterprise access management. | A cryptographic bypass in a widely used JWT library could allow attackers to forcibly revoke user sessions. A critical patch for any Digital Identity or public service relying on token-based authentication. |
| 4 | 2 | CVE-2026-67327 | Core IdAM library flaw enabling persistent account takeover via flawed passwordless/magic-link verification, directly impacting Digital Identity infrastructure. | A logic flaw in the popular `better-auth` library allows attackers to hijack accounts before verification, granting persistent shared access. Critical for any public-facing service relying on magic-links or email-OTP for digital identity management. |
| 4 | 2 | CVE-2026-67329 | Authorization bypass in a core multi-tenant authentication framework exposes cross-organization financial data and billing controls, impacting Digital Identity and Finance sectors. | Multi-tenant SaaS platforms relying on modern auth frameworks face a critical authorization flaw that lets users bypass org boundaries to access Stripe billing data. Patching is essential for regulated identity and financial service deployments. |
| 4 | 2 | CVE-2026-67333 | Digital Identity sector: core OAuth/OIDC authentication framework flaw enabling session hijacking and account takeover. | A stored XSS vulnerability in the widely used better-auth framework could allow attackers to hijack sessions and take over accounts via malicious OAuth consent flows. Organizations deploying this stack for digital identity services should prioritize patching or migration to mitigate account takeover risks. |
| 4 | 2 | CVE-2026-67336 | Direct Digital Identity relevance: affects OIDC/JWT authentication flows and PKCE handling in an open-source IdAM library, enabling token forgery and auth bypass. | Modern web apps relying on open-source identity stacks like better-auth face critical auth bypass risks when legacy OIDC plugins default to insecure crypto. Patching or migrating to hardened OAuth providers is essential to protect digital identity flows. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-66402.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67288.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67289.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67290.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67291.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67292.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67294.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67297.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67299.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67300.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67301.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67305.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67307.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67320.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67340.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67341.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67342.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67343.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67344.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67354.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67355.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-67304.md` — heuristic TIER 3/4
