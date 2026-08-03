# **Infrastructure Daily Brief: 2026-08-02**

**Infrastructure Daily Report TLP:GREEN Alert Id: 46f30847 2026-08-03 05:04:45**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2025-71400 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2025-71399 (Tier 2)                                                          | 3.k      |
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.b      |
| Threats    | Device Code Phishing: Turning a Convenience Feature Into an MFA Bypass | Trend M | 1.b      |
| Threats    | When checking the URL isn’t enough: phishing via the Microsoft identity platform | 1.b      |
| Threats    | AI-enabled device code phishing campaign exploits OAuth flow for account takeove | 1.c      |
| Threats    | Hidden Infrastructure Exposed: ANY.RUN Reveals Hijacked Gov Websites Delivering  | 1.d      |
| Threats    | Hackers Hijack 20+ Government Websites to Deliver Malware Through Trusted Links  | 1.d      |
| Threats    | Attacks Tailored to Federal Workflows: Agency Insights from Abnormal’s 2026 Atta | 1.e      |
| Threats    | CVE-2026-67327                                                                   | 1.b      |
| Threats    | CVE-2026-18571                                                                   | 1.b      |
| Threats    | CVE-2026-18573                                                                   | 1.b      |
| Threats    | CVE-2026-18572                                                                   | 1.b      |
| Threats    | CVE-2026-67332                                                                   | 1.b      |
| Threats    | CVE-2026-67335                                                                   | 1.b      |
| Threats    | CVE-2026-18570                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.b**

Source: ketch Published: 2026-08-02

A new wave of device code phishing shows how threat actors are scaling account compromise using AI and end‑to‑end automation. This campaign goes beyond traditional phishing by generating live authentication codes on demand, enabling higher success rates and sustained post‑compromise access.

___________________________________


# **[Device Code Phishing: Turning a Convenience Feature Into an MFA Bypass | Trend Micro (US)](https://www.trendmicro.com/en_us/research/26/g/device-code-phishing.html)**

**PIR: 1.b**

Source: ketch Published: 2026-08-02

This analysis details how attackers exploit Microsoft's device code authentication flow to circumvent multi-factor authentication. By tricking users into entering codes on malicious portals, threat actors bypass traditional MFA controls. The report outlines detection signatures, mitigation strategies for identity administrators, and architectural recommendations to secure OAuth device flows in enterprise environments.

___________________________________


# **[When checking the URL isn’t enough: phishing via the Microsoft identity platform | Securelist](https://securelist.com/microsoft-device-code-phishing-attack/120350/)**

**PIR: 1.b**

Source: ketch Published: 2026-08-02

Kaspersky Securelist researchers dissect a sophisticated campaign leveraging legitimate Microsoft identity endpoints to host phishing infrastructure. Attackers manipulate OAuth device code flows, rendering traditional URL filtering ineffective. The article provides technical breakdowns of token interception, infrastructure mapping, and defensive configurations for identity platform administrators.

___________________________________


# **[AI-enabled device code phishing campaign exploits OAuth flow for account takeover - Help Net Security](https://www.helpnetsecurity.com/2026/04/07/microsoft-device-code-phishing-campaign/)**

**PIR: 1.c**

Source: ketch Published: 2026-08-02

This coverage examines how automated AI tools streamline the device code phishing process, targeting enterprise OAuth implementations. The report highlights the rapid scaling of credential harvesting operations and offers actionable guidance for security teams to monitor anomalous authentication patterns and harden identity access policies.

___________________________________


# **[Hidden Infrastructure Exposed: ANY.RUN Reveals Hijacked Gov Websites Delivering Malware](https://any.run/cybersecurity-blog/phantomenigma-research?utm_c%20target=)**

**PIR: 1.d**

Source: ketch Published: 2026-08-02

ANY.RUN researchers uncover a campaign where threat actors compromise government web servers to host malicious payloads and phishing lures. By leveraging trusted domains, attackers bypass reputation-based security controls. The analysis details infrastructure takedown procedures, DNS monitoring techniques, and web application firewall rules for infrastructure defenders.

___________________________________


# **[Hackers Hijack 20+ Government Websites to Deliver Malware Through Trusted Links](https://cybersecuritynews.com/government-websites-deliver-malware)**

**PIR: 1.d**

Source: ketch Published: 2026-08-02

A widespread infrastructure compromise sees attackers defacing and hijacking multiple government portals to distribute malware via seemingly legitimate links. The report emphasizes the risks of third-party hosting dependencies and provides network segmentation strategies, certificate pinning recommendations, and incident response playbooks for IT operations teams.

___________________________________


# **[Attacks Tailored to Federal Workflows: Agency Insights from Abnormal’s 2026 Attack Landscape Report](https://abnormal.ai/blog/federal-email-threats-2026-attack-landscape-report)**

**PIR: 1.e**

Source: ketch Published: 2026-08-02

Abnormal Security’s annual report analyzes phishing tactics specifically engineered for federal agency workflows and compliance requirements. The findings reveal increased use of AI-generated content and supply chain impersonation. IT defenders gain insights into email gateway tuning, user training metrics, and zero-trust identity validation frameworks.

___________________________________


# **[CVE-2026-67327](https://nvd.nist.gov/vuln/detail/CVE-2026-67327)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-01

better-auth versions >= 1.1.3 and < 1.6.22 (and pre-release versions >= 1.7.0-beta.0 and < 1.7.0-beta.10) are vulnerable to account takeover via pre-account hijacking on magic-link and email-OTP sign-in when open email/password registration is enabled. An attacker registers an account with the victim's email address and an attacker-chosen password; the account remains unverified. When the legitimate owner later signs in via the magic-link or email-OTP passwordless flow, the account is marked ver

___________________________________


# **[CVE-2026-18571](https://nvd.nist.gov/vuln/detail/CVE-2026-18571)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-02

A flaw was found in the user creation component of Keycloak when Fine-Grained Admin Permissions V2 (FGAP V2) is enabled. This issue allows a sub-administrator with permission to create users to add those users to any group, even groups the sub-administrator is not authorized to manage. This could lead to unauthorized access to sensitive information or elevated privileges for the newly created users.

___________________________________


# **[CVE-2026-18573](https://nvd.nist.gov/vuln/detail/CVE-2026-18573)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-02

A flaw was found in the keycloak-services component of Keycloak, which is used for managing authentication and authorization flows. The issue occurs when a realm administrator configures client policies to enforce specific authentication requirements on confidential clients. Due to improper evaluation of the client state during an update operation, an attacker with client management permissions can bypass these security policies by first creating a public client and then updating it to a confide

___________________________________


# **[CVE-2026-18572](https://nvd.nist.gov/vuln/detail/CVE-2026-18572)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-02

Keycloak provides authorization services that allow administrators to restrict access to resources based on time policies (for example, only allowing access during business hours). A flaw was discovered where a user can include a fake time value in their authorization request that overrides the actual server time. This allows the user to bypass these time-based restrictions and access protected resources at unauthorized times.

___________________________________


# **[CVE-2026-67332](https://nvd.nist.gov/vuln/detail/CVE-2026-67332)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-01

@better-auth/oauth-provider before 1.7.0-beta.4 fails to bind access-token audience to the authorization grant, allowing clients to request tokens for unrelated resources. Attackers can complete an OAuth flow and obtain access tokens whose audience targets resource servers the authorization never covered, bypassing intended authorization boundaries.

___________________________________


# **[CVE-2026-67335](https://nvd.nist.gov/vuln/detail/CVE-2026-67335)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-01

better-auth versions before 1.6.2 fail to validate the OAuth state parameter against the stored nonce when using cookie-backed state storage without PKCE. Attackers can forge the state parameter and supply an attacker-controlled authorization code to create authenticated sessions bound to the attacker's external identity or persistently link attacker accounts to victim profiles.

___________________________________


# **[CVE-2026-18570](https://nvd.nist.gov/vuln/detail/CVE-2026-18570)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-02

A flaw was found in the full-scope-disabled client-policy executor within the keycloak-services component. This component is responsible for enforcing security policies during client registration and configuration in Red Hat Build of Keycloak. The issue occurs because the executor only validates the fullScopeAllowed field when it is explicitly provided in a request. By omitting this field, a delegated user can bypass the policy, resulting in a client created with full scope access. This allows t

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2025-71400 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2025-71400)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-02

Directly impacts Digital Identity infrastructure by allowing authenticated users to delete other users' passkeys, disrupting access control and credential management.

*Deep dive: `TIER_2_CVE-2025-71400.md`*

___________________________________


# **[CVE-2025-71399 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2025-71399)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-02

TIER 2 path normalization bypass in Better Auth undermines rate limiting and access controls on public-facing authentication endpoints, directly impacting Digital Identity assurance.

*Deep dive: `TIER_2_CVE-2025-71399.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine