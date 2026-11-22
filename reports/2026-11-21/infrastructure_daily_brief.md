# **Infrastructure Daily Brief: 2026-11-21**

**Infrastructure Daily Report TLP:GREEN Alert Id: 58a81b73 2026-11-22 09:11:40**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-134311 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-134312 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-134315 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-134316 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-134459 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-134287 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-134313 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-134322 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-134370 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-134372 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-134404 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-134458 (Tier 2)                                                         | 3.k      |
| Threats    | Inside an AI‑enabled device code phishing campaign | Microsoft Security Blog     | 1.e      |
| Threats    | Device Code Phishing Hits 340+ Microsoft 365 Orgs Across Five Countries ...      | 1.d      |
| Threats    | Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Se | 1.d      |
| Threats    | High volume phishing campaign uses Microsoft 365 outage lures to target ...      | 1.g      |
| Threats    | Microsoft 365 device code phishing campaign bypasses password stealing | RL Blog | 1.d      |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US        | 1.d      |
| Threats    | Access granted: phishing with device code authorization for account takeover | P | 1.d      |
| Threats    | DHS: Spear Phishing Campaign Targeted 11 Energy Sector Firms                     | 1.h      |
| Threats    | CVE-2026-129073                                                                  | 3.k      |
| Threats    | CVE-2026-133659                                                                  | 1.b      |
| Threats    | CVE-2026-55216                                                                   | 1.b      |
| Threats    | CVE-2026-133652                                                                  | 1.b      |
| Threats    | CVE-2026-129074                                                                  | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Inside an AI‑enabled device code phishing campaign | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.e**

Source: ketch Published: 2026-11-21

Microsoft researchers detail an AI-enabled device code phishing campaign that dynamically generates convincing consent requests. Machine learning models tailor lures to specific organizational contexts, increasing success rates. Infrastructure teams must integrate AI-driven threat detection, monitor for anomalous OAuth activity, and restrict third-party app registrations to neutralize adaptive phishing tactics.

___________________________________


# **[Device Code Phishing Hits 340+ Microsoft 365 Orgs Across Five Countries ...](https://thehackernews.com/2026/03/device-code-phishing-hits-340-microsoft.html)**

**PIR: 1.d**

Source: ketch Published: 2026-11-21

A widespread device code phishing campaign has compromised over 340 Microsoft 365 organizations across five countries since February 2026. By abusing OAuth consent flows, threat actors bypass traditional password protections to hijack persistent access tokens. Defenders must audit delegated permissions, restrict device code authorization endpoints, and implement token lifecycle monitoring to prevent account takeover.

___________________________________


# **[Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/)**

**PIR: 1.d**

Source: ketch Published: 2026-11-21

This deep dive into EvilTokens reveals the underlying mechanics of device code phishing campaigns. Threat actors exploit legitimate Microsoft authentication flows to harvest long-lived tokens, effectively bypassing MFA. Defenders should implement token revocation strategies, monitor for suspicious device code usage patterns, and enforce zero-trust identity controls to limit lateral movement.

___________________________________


# **[High volume phishing campaign uses Microsoft 365 outage lures to target ...](https://www.microsoft.com/en-us/security/blog/2026/11/16/high-volume-phishing-campaign-uses-microsoft-365-outage-lures-target-multiple-industry-sectors-2/)**

**PIR: 1.g**

Source: ketch Published: 2026-11-21

Microsoft Threat Intelligence identified a coordinated, high-volume phishing campaign leveraging fake Microsoft 365 service-health notifications. Attackers exploit outage rumors to trick users into surrendering credentials. Infrastructure defenders should monitor for anomalous login spikes, validate service status via official channels, and enforce conditional access policies to mitigate credential theft.

___________________________________


# **[Microsoft 365 device code phishing campaign bypasses password stealing | RL Blog](https://www.reversinglabs.com/blog/device-code-phishing-campaign)**

**PIR: 1.d**

Source: ketch Published: 2026-11-21

ReversingLabs examines a Microsoft 365 campaign that circumvents traditional password-stealing techniques via device code authorization. By leveraging OAuth consent, attackers gain direct account access without credential harvesting. IT infrastructure teams must prioritize identity-centric defenses, audit consent grants, and deploy real-time alerting for unusual authentication method shifts.

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.d**

Source: ketch Published: 2026-11-21

Proofpoint analyzes how device code phishing has evolved into a sophisticated identity takeover vector. Attackers now combine social engineering with automated consent manipulation to maintain long-term access. Security teams should deploy advanced email filtering, educate users on OAuth prompts, and enforce strict application consent policies to block unauthorized token issuance.

___________________________________


# **[Access granted: phishing with device code authorization for account takeover | Proofpoint US](https://www.proofpoint.com/us/blog/threat-insight/access-granted-phishing-device-code-authorization-account-takeover)**

**PIR: 1.d**

Source: ketch Published: 2026-11-21

Proofpoint explores how device code authorization phishing enables seamless account takeover. Attackers manipulate users into approving malicious OAuth requests, granting persistent access. Security operations should enforce application consent workflows, restrict device code endpoints, and implement behavioral analytics to detect and block unauthorized identity delegation attempts.

___________________________________


# **[DHS: Spear Phishing Campaign Targeted 11 Energy Sector Firms](https://securityweek.com/dhs-spear-phishing-campaign-targeted-11-energy-sector-firms)**

**PIR: 1.h**

Source: ketch Published: 2026-11-21

DHS reports a targeted spear phishing campaign aimed at 11 energy sector firms, highlighting persistent threats to critical infrastructure. Attackers use tailored lures to compromise operational technology networks. Defenders must segment OT/IT environments, enforce strict email security gateways, and maintain incident response playbooks specific to sector-specific identity threats.

___________________________________


# **[CVE-2026-129073](https://nvd.nist.gov/vuln/detail/CVE-2026-129073)**

**PIR: 3.k**

Source: vulners/duckdb Published: 2026-11-20

Authentication Bypass Using an Alternate Path or Channel vulnerability in miniOrange miniorange otp verification miniorange-otp-verification allows Authentication Abuse.This issue affects miniorange otp verification: from n/a through 5.6.1.

___________________________________


# **[CVE-2026-133659](https://nvd.nist.gov/vuln/detail/CVE-2026-133659)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-20

Flowintel contains multiple SSO identity and organisation trust boundary violations that collectively allow account takeover, privilege escalation, and unauthorized access to private case data.

- Keycloak SSO accepted unverified email claims, and all SSO providers (Keycloak, Entra ID, SimpleSAML) could resolve a claimed email address to an existing account that was created via a different sign-in method, enabling cross-provider account collision and unauthorized access to another user's account

___________________________________


# **[CVE-2026-55216](https://nvd.nist.gov/vuln/detail/CVE-2026-55216)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-20

Logto is the modern, open-source auth infrastructure for SaaS and AI apps. Prior to 1.46.0, social account linking can use an unverified email returned by the standard OAuth 2.0 or Azure AD connector to select an existing local account. When findSocialRelatedUser matches a victim's email and a request to POST /api/experience/identification enables linkSocialIdentity, an attacker who controls that unverified provider email can link an attacker-controlled social identity to the victim account and 

___________________________________


# **[CVE-2026-133652](https://nvd.nist.gov/vuln/detail/CVE-2026-133652)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-20

Flowintel , contained a session management vulnerability in its browser authentication mechanism. The session identifier used a bare numeric user ID rather than a credential-bound token, resulting in several related weaknesses:

- Remembered logins (remember-me cookies) remained valid after a user changed their password, allowing an attacker holding a previously issued cookie to retain access indefinitely.
- Server-side session identifiers were not rotated upon login (local, SSO, or remembered),

___________________________________


# **[CVE-2026-129074](https://nvd.nist.gov/vuln/detail/CVE-2026-129074)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-20

Missing Authorization vulnerability in miniOrange miniOrange's Google Authenticator miniorange-2-factor-authentication allows Exploiting Incorrectly Configured Access Control Security Levels.This issue affects miniOrange's Google Authenticator: from n/a through 6.6.0.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-134311 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-134311)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-21

Core authentication library flaw enables account takeover via phone OTP, directly impacting Digital Identity and session management in regulated web applications.

*Deep dive: `TIER_2_CVE-2026-134311.md`*

___________________________________


# **[CVE-2026-134312 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-134312)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-21

Digital Identity sector: critical OAuth authentication flaw in a widely used Node.js library enables account takeover via improper email verification validation.

*Deep dive: `TIER_2_CVE-2026-134312.md`*

___________________________________


# **[CVE-2026-134315 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-134315)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-21

Core authentication library flaw enabling account takeover via email-change link abuse, directly impacting Digital Identity and session integrity.

*Deep dive: `TIER_2_CVE-2026-134315.md`*

___________________________________


# **[CVE-2026-134316 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-134316)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-21

Digital Identity sector: compromises core authentication infrastructure, enabling session forgery, 2FA bypass, and OAuth secret leakage in public-facing identity services.

*Deep dive: `TIER_2_CVE-2026-134316.md`*

___________________________________


# **[CVE-2026-134459 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-134459)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-21

Digital Identity: Timing side-channel in widely-used PHP JWT/JWE library enables CEK recovery, impacting authentication and session management in regulated sectors.

*Deep dive: `TIER_2_CVE-2026-134459.md`*

___________________________________


# **[CVE-2026-134287 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-134287)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-21

Critical authentication bypass in OpenRemote IoT platform used for smart cities and municipal energy grids, risking unauthorized control of civic actuators (Government/General Infrastructure sector).

*Deep dive: `TIER_2_CVE-2026-134287.md`*

___________________________________


# **[CVE-2026-134313 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-134313)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-21

Digital Identity: Race condition in Better Auth library causes session mix-up and account takeover in public-facing authentication endpoints.

*Deep dive: `TIER_2_CVE-2026-134313.md`*

___________________________________


# **[CVE-2026-134322 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-134322)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-21

Digital Identity: Improper authentication in a widely used Node.js IdAM library enables OTP session hijacking and account takeover via an opt-in phone plugin.

*Deep dive: `TIER_2_CVE-2026-134322.md`*

___________________________________


# **[CVE-2026-134370 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-134370)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-21

TIER 2 authenticated path traversal in Frappe/ERPNext directly impacts Government and Finance DPI deployments, risking exposure of citizen data and financial configurations in public-facing portals.

*Deep dive: `TIER_2_CVE-2026-134370.md`*

___________________________________


# **[CVE-2026-134372 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-134372)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-21

SQL injection in Frappe ERPNext enables admin session hijacking, directly impacting Finance and Government sectors using this ERP for procurement and financial operations.

*Deep dive: `TIER_2_CVE-2026-134372.md`*

___________________________________


# **[CVE-2026-134404 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-134404)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-21

Finance sector relevance: exposes sensitive procurement, valuation, and margin data in widely deployed ERPNext systems used by regulated and government workflows.

*Deep dive: `TIER_2_CVE-2026-134404.md`*

___________________________________


# **[CVE-2026-134458 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-134458)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-21

Breaks JWE token confidentiality in widely used PHP JWT libraries, directly impacting SSO, session management, and Digital Identity workflows.

*Deep dive: `TIER_2_CVE-2026-134458.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine