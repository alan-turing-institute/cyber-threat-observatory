# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-07-11 09:08:50Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-07-10`
- **Included count:** 13

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-55672 | Affects core OAuth2/OIDC authentication flows in ZITADEL, a digital identity platform used by enterprises for managing access control and user sessions. | ZITADEL's OAuth2/OIDC implementation allows token cross-use between clients due to missing client ID binding. This could enable unauthorized access if tokens are intercepted—highlighting the importance of secure authentication in enterprise identity infrastructure. |
| 5 | 2 | CVE-2026-56668 | This vulnerability impacts ZITADEL's core identity management platform, affecting authentication, authorization, and access control mechanisms in digital identity infrastructure. | A critical missing authorization flaw in ZITADEL's OAuth2 token exchange allows privilege escalation between applications. This highlights the importance of securing identity platforms that manage enterprise access controls. |
| 5 | 2 | CVE-2026-59151 | This CVE affects Digital Identity infrastructure by enabling cross-tenant account takeover through flawed SAML authentication, impacting identity management and access control in cloud security platforms. | A critical SAML vulnerability in Prowler allows attackers to hijack accounts across tenants by manipulating email domain assertions. This highlights the importance of secure identity federation in multi-tenant cloud environments. |
| 4 | 2 | CVE-2026-14480 | Affects industrial control systems (ICS) used in critical infrastructure, relevant to Government and Healthcare sectors as part of digital public infrastructure. | A TIER 2 vulnerability in OpenPLC Runtime v3 allows authenticated attackers to achieve arbitrary code execution in SCADA/IIoT environments. This impacts both government and healthcare sectors where industrial control systems are deployed. |
| 4 | 2 | CVE-2026-20744 | Affects public EV charging infrastructure (Transportation Systems) managed by a Canadian government utility, with potential for privilege escalation and DoS attacks. | A critical vulnerability in Hydro-Québec's EV charging network exposes backend systems to unauthenticated access. This highlights the need for secure communications in digital transportation infrastructure—especially as these systems become more integrated into public services. |
| 4 | 2 | CVE-2026-55377 | Impacts Digital Identity by compromising account security through improper authentication in Logto's step-up verification, allowing MFA factor takeover. | A TIER 2 vulnerability in Logto allows attackers with hijacked tokens to bypass step-up re-authentication and take over user MFA factors. This highlights the importance of secure identity management systems for SaaS and AI applications. |
| 4 | 2 | CVE-2026-55665 | Affects Digital Identity and Healthcare sectors by enabling session manipulation and privilege escalation in Grist Core, a collaborative spreadsheet tool used in regulated environments. | A cross-site scripting flaw in Grist Core allows attackers to escalate privileges and manipulate sensitive data within authenticated sessions. This impacts both digital identity management and healthcare data security—especially critical for organizations using Grist in clinical or health-related contexts. |
| 4 | 2 | CVE-2026-55789 | Affects Digital Identity infrastructure through SAML identity provider vulnerability enabling privilege escalation via forged assertions. | Logto's SAML IdP flaw allows low-privilege users to escalate privileges at relying SPs by injecting XML into profile attributes. A key issue for enterprise identity management systems. |
| 4 | 2 | CVE-2026-56667 | A stored XSS vulnerability in ZITADEL affects Digital Identity infrastructure, specifically OIDC/SAML authentication flows, making it relevant to the Digital Identity sector. | A stored XSS flaw in ZITADEL's identity management platform could allow attackers with admin access to hijack user sessions during login errors. This highlights the importance of securing identity infrastructure—especially in enterprise and government deployments where ZITADEL is commonly used. |
| 4 | 2 | CVE-2026-59796 | Affects Digital Identity systems through unauthorized CI/CD pipeline configuration modification, impacting secure software delivery processes. | A TIER 2 vulnerability in JetBrains TeamCity allows unauthorized modification of build configurations, highlighting risks to CI/CD integrity and access control in development environments. Organizations using TeamCity should prioritize patching to maintain secure software delivery pipelines. |
| 3 | 2 | CVE-2026-15330 | Affects Digital Identity infrastructure through CowAgent's web console, which can be used for authentication and authorization in agent-based systems. | A Server-Side Request Forgery (SSRF) vulnerability in the Vision Tool component of zhayujie CowAgent allows attackers to access internal services and loopback addresses. This poses a risk to Digital Identity infrastructure as the web console can be used for AI agent control with authentication/authorization functions. |
| 3 | 2 | CVE-2026-41482 | Relevant to Digital Identity as Frappe is often used for building identity management systems, though the specific context is not explicitly stated in the report. | A path traversal vulnerability in the Frappe web framework could expose sensitive files and credentials, particularly in enterprise applications that rely on it for digital identity management. This highlights the importance of keeping web frameworks updated to prevent information disclosure risks. |
| 3 | 2 | CVE-2026-55501 | Affects Digital Identity sector through AI development tool with vulnerable dashboard authentication that can bypass rate limiting for brute-force attacks. | A critical login bypass vulnerability in 9Router allows attackers to circumvent rate limits via spoofed headers, posing a risk to digital identity systems used in AI workflows. This TIER 2 flaw highlights the importance of secure authentication in developer tools that may handle sensitive credentials. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-12761.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13430.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15282.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15290.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15293.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15298.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15319.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-21042.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-21045.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-21046.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-21048.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-21049.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-21055.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-2397.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-39244.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-39903.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-40005.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-40007.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-40008.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-40452.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-40454.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-42952.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-44383.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-49394.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53448.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53450.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53653.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53657.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54000.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55213.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55233.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55659.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55687.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55827.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55880.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55881.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55882.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56335.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57214.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57217.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57220.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57584.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58492.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59161.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59792.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59793.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59795.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61455.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-6212.md` — heuristic TIER 3/4
