# **Infrastructure Daily Brief: 2026-08-26**

**Infrastructure Daily Report TLP:GREEN Alert Id: 0a2b16fd 2026-08-27 11:53:24**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-18664 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-54569 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-81036 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-77537 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-77546 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-77548 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-77550 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-80428 (Tier 2)                                                          | 3.k      |
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.b      |
| Threats    | When checking the URL isn’t enough: phishing via the Microsoft identity platform | 1.b      |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover                        | 1.b      |
| Threats    | Microsoft 365 device code phishing campaign bypasses password stealing | RL Blog | 1.b      |
| Threats    | EvilTokens abuses Microsoft device code flow for account takeovers | CSO Online  | 1.b      |
| Threats    | Three Active Microsoft 365 Phishing Campaigns Targeting Schools and Government A | 1.a      |
| Threats    | Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA                  | 1.c      |
| Threats    | Zero-click email attacks: What businesses need to know                           | 1.c      |
| Threats    | CVE-2026-65956                                                                   | 1.b      |
| Threats    | CVE-2026-80192                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.b**

Source: ketch Published: 2026-08-26

Microsoft researchers detail a sophisticated phishing campaign leveraging AI-generated prompts to trick users into entering device codes. This technique bypasses traditional password-based defenses and multi-factor authentication, granting attackers direct access to Microsoft 365 accounts. The report outlines detection strategies, telemetry indicators, and mitigation steps for infrastructure teams managing enterprise identity platforms.

___________________________________


# **[When checking the URL isn’t enough: phishing via the Microsoft identity platform | Securelist](https://securelist.com/microsoft-device-code-phishing-attack/120350/)**

**PIR: 1.b**

Source: ketch Published: 2026-08-26

Kaspersky Securelist reveals how threat actors exploit legitimate Microsoft identity endpoints to conduct phishing campaigns that evade traditional URL filtering. By leveraging authorized OAuth flows, attackers capture valid session tokens without stealing credentials. The analysis highlights infrastructure defense strategies, including token lifecycle monitoring and strict conditional access configurations.

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.b**

Source: ketch Published: 2026-08-26

Proofpoint analyzes how device code phishing has matured into a primary vector for enterprise identity takeover. Attackers now automate the generation of convincing login portals that harvest valid OAuth tokens, effectively neutralizing passwordless and MFA controls. The article provides actionable guidance for security operations centers to monitor token issuance anomalies and enforce conditional access policies.

___________________________________


# **[Microsoft 365 device code phishing campaign bypasses password stealing | RL Blog](https://www.reversinglabs.com/blog/device-code-phishing-campaign)**

**PIR: 1.b**

Source: ketch Published: 2026-08-26

ReversingLabs documents a widespread campaign targeting Microsoft 365 environments through device code phishing. Unlike traditional credential harvesting, this method captures valid authentication tokens directly, rendering password resets ineffective. The report details technical indicators, attack infrastructure, and recommended detection rules for identity protection platforms and SIEM systems.

___________________________________


# **[EvilTokens abuses Microsoft device code flow for account takeovers | CSO Online](https://www.csoonline.com/article/4153742/eviltokens-abuses-microsoft-device-code-flow-for-account-takeovers.html)**

**PIR: 1.b**

Source: ketch Published: 2026-08-26

CSO Online examines the EvilTokens malware family, which specifically targets the Microsoft device code authentication flow to facilitate account takeovers. The malware automates token theft and session hijacking, allowing persistent access to compromised environments. Infrastructure defenders are advised to implement token revocation workflows and monitor for anomalous device code requests.

___________________________________


# **[Three Active Microsoft 365 Phishing Campaigns Targeting Schools and Government Agencies](https://forsyteit.com/three-active-microsoft-365-phishing-campaigns-targeting-schools-and-government-agencies)**

**PIR: 1.a**

Source: ketch Published: 2026-08-26

Forsyte IT identifies three concurrent phishing campaigns specifically targeting educational and government Microsoft 365 tenants. Attackers deploy credential harvesting pages mimicking Microsoft login flows to steal administrative and user accounts. The article provides infrastructure-focused mitigation steps, including domain allowlisting, user awareness training, and enhanced sign-in risk policies.

___________________________________


# **[Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA](https://tempmail.ninja/blog/laundry-bear-zimbra-phishing)**

**PIR: 1.c**

Source: ketch Published: 2026-08-26

CISA warns of a zero-click phishing campaign by the Laundry Bear group exploiting vulnerabilities in Zimbra email servers. The attack requires no user interaction, automatically delivering malicious payloads or harvesting session data. Infrastructure teams are urged to patch Zimbra instances immediately, review server access logs, and isolate affected mail systems to prevent lateral movement.

___________________________________


# **[Zero-click email attacks: What businesses need to know](https://itpro.com/security/phishing/zero-click-email-attacks-what-businesses-need-to-know)**

**PIR: 1.c**

Source: ketch Published: 2026-08-26

ITPro provides a comprehensive overview of zero-click email attacks, explaining how threat actors exploit rendering engines and email client vulnerabilities to execute code without user interaction. The article outlines architectural defenses, including sandboxed email processing, strict content filtering, and endpoint detection strategies tailored for modern infrastructure environments.

___________________________________


# **[CVE-2026-65956](https://nvd.nist.gov/vuln/detail/CVE-2026-65956)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-26

KubePi is a Kubernetes multi-cluster management panel. In versions up to and including 1.6.15, the SSO configuration API endpoints are exposed on the same public routing boundary as the SSO login and callback endpoints, so SSO, OIDC, and SAML management operations can be reached without administrator authorization. Because reading, creating, and updating the global SSO configuration is not restricted to administrators, an unauthorized or low-privileged user can inspect or alter the authenticatio

___________________________________


# **[CVE-2026-80192](https://nvd.nist.gov/vuln/detail/CVE-2026-80192)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-25

@better-auth/sso before 1.6.27 (and before 1.4.8 in the 1.4.x line and before 1.7.0-rc.5 in the 1.7 prerelease line) contains two domain-ownership flaws. When domain verification is disabled, automatic organization assignment accepts unverified provider domains, allowing an authenticated organization owner/administrator to register an SSO provider for an arbitrary domain and have users with matching email domains added to the attacker's organization with default member permissions. When domain v

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-18664 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-18664)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-26

Foundational DNS infrastructure flaw enabling unauthorized zone transfers and data leakage across all regulated/public sectors relying on NSD.

*Deep dive: `TIER_2_CVE-2026-18664.md`*

___________________________________


# **[CVE-2026-54569 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-54569)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-26

Critical unauthenticated RCE in SENAITE LIMS, widely deployed in clinical diagnostics and public health laboratories, directly threatening patient data integrity and healthcare workflow continuity.

*Deep dive: `TIER_2_CVE-2026-54569.md`*

___________________________________


# **[CVE-2026-81036 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-81036)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-26

OAuth redirect bypass in widely deployed mail server enables account takeover, directly impacting Digital Identity and secure communications across Government, Finance, and Healthcare sectors.

*Deep dive: `TIER_2_CVE-2026-81036.md`*

___________________________________


# **[CVE-2026-77537 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-77537)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-26

Unauthenticated RCE in Ubiquiti surveillance hardware widely deployed across municipal and critical infrastructure networks.

*Deep dive: `TIER_2_CVE-2026-77537.md`*

___________________________________


# **[CVE-2026-77546 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-77546)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-26

Physical access control consoles manage civic and enterprise building security; authenticated RCE poses a direct risk to the physical-digital infrastructure bridge.

*Deep dive: `TIER_2_CVE-2026-77546.md`*

___________________________________


# **[CVE-2026-77548 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-77548)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-26

Critical command injection in Ubiquiti UniFi Protect surveillance software, explicitly tied to government facilities and public infrastructure security.

*Deep dive: `TIER_2_CVE-2026-77548.md`*

___________________________________


# **[CVE-2026-77550 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-77550)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-26

Critical unauthenticated auth-bypass in Ubiquiti UniFi OS networking controllers, explicitly deployed across government and enterprise infrastructure.

*Deep dive: `TIER_2_CVE-2026-77550.md`*

___________________________________


# **[CVE-2026-80428 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-80428)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-26

Unauthenticated RCE in ILIAS LMS impacts public education infrastructure, risking compromise of student/staff data and learning platforms.

*Deep dive: `TIER_2_CVE-2026-80428.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine