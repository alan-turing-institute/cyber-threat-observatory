# **Infrastructure Daily Brief: 2026-09-25**

**Infrastructure Daily Report TLP:GREEN Alert Id: 51f58eb3 2026-09-26 10:46:02**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-93641 (Tier 2)                                                          | 3.k      |
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.j.3    |
| Threats    | Microsoft 365: Block Device Code Flow Against GhostCode                          | 1.j.3    |
| Threats    | EvilTokens made phishing-as-a-service look easy. Then it got taken down          | 1.f      |
| Threats    | Microsoft Warns of EvilTokens AI Phishing Service Hijacking Thousands of Account | 1.k      |
| Threats    | AI-Enabled Device Code Phishing Campaign Abuses Device Code Sign-In Flow         | 1.j.3    |
| Threats    | Midnight Blizzard-Linked Actor GTG-20006 Automated Device Code Phishing With AI  | 1.j.3    |
| Threats    | PhantomEnigma: How a Malware Crew Turned Brazilian Government Sites Into Trusted | 1.g      |
| Threats    | Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA                  | 1.l      |
| Threats    | CVE-2026-94606                                                                   | 1.b      |
| Threats    | CVE-2026-94609                                                                   | 1.b      |
| Threats    | CVE-2026-85056                                                                   | 1.b      |
| Threats    | CVE-2026-94611                                                                   | 1.b      |
| Threats    | CVE-2026-57178                                                                   | 1.b      |
| Threats    | CVE-2026-94612                                                                   | 1.b      |
| Threats    | CVE-2026-97846                                                                   | 1.b      |
| Threats    | CVE-2026-96448                                                                   | 1.b      |
| Threats    | CVE-2026-97177                                                                   | 1.b      |
| Threats    | CVE-2026-57175                                                                   | 1.b      |
| Threats    | CVE-2026-97311                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.j.3**

Source: ketch Published: 2026-09-25

This campaign represents a major escalation in threat actor sophistication, shifting from static scripts to fully AI-driven infrastructure. Attackers automate the entire device code phishing workflow, enabling rapid credential harvesting and token theft at scale. Defenders should monitor for anomalous device code sign-in flows and implement conditional access policies to block suspicious authentications.

___________________________________


# **[Microsoft 365: Block Device Code Flow Against GhostCode](https://windowsforum.com/news/microsoft-365-block-device-code-flow-against-ghostcode.444973?amp=1)**

**PIR: 1.j.3**

Source: ketch Published: 2026-09-25

Guidance on mitigating GhostCode’s abuse of the Microsoft 365 device code authentication flow. The article outlines registry and Intune configuration steps to restrict device code sign-ins, reducing exposure to automated credential theft campaigns. Essential reading for administrators managing hybrid or cloud-only environments.

___________________________________


# **[EvilTokens made phishing-as-a-service look easy. Then it got taken down](https://securityaffairs.com/199593/cyber-crime/eviltokens-made-phishing-as-a-service-look-easy-then-it-got-taken-down.html)**

**PIR: 1.f**

Source: ketch Published: 2026-09-25

EvilTokens streamlined credential harvesting by offering an AI-powered phishing-as-a-service platform that auto-generated convincing login pages and managed token theft. Following its takedown, threat actors are migrating to decentralized alternatives. Defenders must update detection rules for emerging PaaS variants and enforce multi-factor authentication.

___________________________________


# **[Microsoft Warns of EvilTokens AI Phishing Service Hijacking Thousands of Accounts](https://gbhackers.com/eviltokens-ai-phishing/amp)**

**PIR: 1.k**

Source: ketch Published: 2026-09-25

Microsoft’s advisory details how EvilTokens leveraged generative AI to bypass traditional phishing filters, resulting in widespread account compromises. The report highlights indicators of compromise, affected tenants, and recommended remediation steps including token revocation and conditional access hardening.

___________________________________


# **[AI-Enabled Device Code Phishing Campaign Abuses Device Code Sign-In Flow](https://captechgroup.com/threat-intelligence-center/ai-enabled-device-code-phishing-campaign-abuses-de-81a334)**

**PIR: 1.j.3**

Source: ketch Published: 2026-09-25

An analysis of how attackers exploit the device code sign-in flow using AI to automate victim targeting and credential capture. The article provides technical breakdowns of the attack chain, detection queries for Sentinel, and mitigation strategies for enterprise identity administrators.

___________________________________


# **[Midnight Blizzard-Linked Actor GTG-20006 Automated Device Code Phishing With AI](https://aegisai.ai/blog/anthropic-midnight-blizzard-ai-device-code-phishing)**

**PIR: 1.j.3**

Source: ketch Published: 2026-09-25

Threat intelligence linking the GTG-20006 actor to automated device code phishing campaigns powered by AI. The report maps infrastructure overlaps with Midnight Blizzard, details TTPs, and offers IOCs for SOC teams to hunt for similar activity in their environments.

___________________________________


# **[PhantomEnigma: How a Malware Crew Turned Brazilian Government Sites Into Trusted Malware Hubs](https://securebulletin.com/phantomenigma-how-a-malware-crew-turned-brazilian-government-sites-into-trusted-malware-hubs)**

**PIR: 1.g**

Source: ketch Published: 2026-09-25

PhantomEnigma compromised official Brazilian government websites to host phishing pages and malware payloads, leveraging institutional trust to bypass user skepticism. The article details the supply chain compromise, persistence mechanisms, and defensive measures for web application firewalls and DNS filtering.

___________________________________


# **[Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA](https://tempmail.ninja/blog/laundry-bear-zimbra-phishing)**

**PIR: 1.l**

Source: ketch Published: 2026-09-25

CISA alerts on Laundry Bear’s exploitation of a zero-click vulnerability in Zimbra collaboration servers to deliver phishing payloads. The campaign targets Western government and critical infrastructure sectors. Defenders are urged to patch Zimbra instances immediately and monitor for anomalous email routing or credential exfiltration.

___________________________________


# **[CVE-2026-94606](https://nvd.nist.gov/vuln/detail/CVE-2026-94606)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-24

authentik is an open-source identity provider. Prior to 2026.2.7, 2026.5.7, and 2026.8.2, authentik email authenticator enrollment during an authentication or enrollment flow accepts a recipient address supplied in the setup request instead of using the address already established by the flow. An actor who knows a target user's password can substitute an attacker-controlled address, receive the one-time code, and finish enrolling the factor as the target. The target must not have enrolled the em

___________________________________


# **[CVE-2026-94609](https://nvd.nist.gov/vuln/detail/CVE-2026-94609)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-24

authentik is an open-source identity provider. Prior to 2026.2.7, 2026.5.7, and 2026.8.2, an account with delegated permission to manage a group, group membership, or a user can grant superuser status to an account or assign an existing role to a group without holding the permissions that gate those privileges. Group hierarchy checks do not consistently account for superuser status inherited from ancestor groups, and role assignment to a group lacks the required authorization check. Only deploym

___________________________________


# **[CVE-2026-85056](https://nvd.nist.gov/vuln/detail/CVE-2026-85056)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-24

ZITADEL is an open source identity management platform. From 4.0.0 until 4.16.1, ZITADEL Login V2 creates a browser session after password verification and can reuse that session for a later authentication request without verifying a user's enrolled TOTP, OTP, or U2F second factor. When the MFA step is abandoned and login starts again, session-validity checks require MFA only when the organization enables Force MFA or Force MFA for local users only, so a voluntarily enrolled factor can be skippe

___________________________________


# **[CVE-2026-94611](https://nvd.nist.gov/vuln/detail/CVE-2026-94611)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-24

authentik is an open-source identity provider. Prior to 2026.2.7, 2026.5.7, and 2026.8.2, authentik API serializers return stored credentials when an account has view permission on an affected configuration, even when that account is not authorized to change the configuration or read its secrets. Affected configurations include one-time code delivery by mail or SMS, outbound provisioning targets, device trust integrations, identity sources, the Kubernetes outpost integration, applications using 

___________________________________


# **[CVE-2026-57178](https://nvd.nist.gov/vuln/detail/CVE-2026-57178)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-24

Python Social Auth is a social authentication/registration mechanism. Prior to version 5.0.0, the `vk-app` backend accepted VK application callback data without verifying the callback signature when the `auth_key` parameter was omitted. Applications using this backend could treat unsigned attacker-controlled data as a verified VK identity. An attacker could choose callback fields such as `viewer_id`, `access_token`, `api_id`, and `api_result`, potentially allowing authentication as an arbitrary 

___________________________________


# **[CVE-2026-94612](https://nvd.nist.gov/vuln/detail/CVE-2026-94612)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-24

authentik is an open-source identity provider. Prior to 2026.2.7, 2026.5.7, and 2026.8.2, an authentik SAML Source verifies an assertion's signature and validity period but does not ensure that the identity provider issued the assertion for that Source or in response to a login request from that Source. The SAML Source also does not record already accepted assertions, allowing replay. An unauthenticated actor who possesses such a valid assertion can use an assertion intended for another service 

___________________________________


# **[CVE-2026-97846](https://nvd.nist.gov/vuln/detail/CVE-2026-97846)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-25

Keycloak provides a feature called mTLS holder-of-key binding which ensures that a token can only be used by the client that originally requested it by binding it to their digital certificate. A flaw was discovered where the new Standard Token Exchange V2 feature does not check for this certificate. This allows an attacker with stolen client credentials to obtain a standard, unrestricted token that bypasses these security protections.

___________________________________


# **[CVE-2026-96448](https://nvd.nist.gov/vuln/detail/CVE-2026-96448)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-25

A flaw was found in the Fine-Grained Admin Permissions (FGAP v2) feature of Keycloak, an identity and access management solution. The issue occurs when the system checks if a delegated administrator has permission to assign a specific role to a user. Because the check does not look inside composite roles to see what other permissions they contain, an administrator with limited rights can assign a role that secretly includes full administrative control. This allows the attacker to gain complete m

___________________________________


# **[CVE-2026-97177](https://nvd.nist.gov/vuln/detail/CVE-2026-97177)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-24

A flaw was found in the user update mechanism of the Keycloak Admin REST API. When Fine-Grained Admin Permissions are enabled, the system fails to check for specific password reset authorizations during a general user profile update. This allows a delegated administrator, who should be restricted from resetting passwords, to change a user's credentials and take over their account.

___________________________________


# **[CVE-2026-57175](https://nvd.nist.gov/vuln/detail/CVE-2026-57175)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-24

Python Social Auth is a social authentication/registration mechanism. Prior to version 5.0.0, the SAML backend accepted SAML responses on the Assertion Consumer Service endpoint without verifying that they matched a previously issued `AuthnRequest`. Applications using SAML account association could allow an attacker with a valid account on a trusted IdP to link the attacker's SAML identity to a logged-in victim's local account. The attacker could then authenticate through SAML and gain access to

___________________________________


# **[CVE-2026-97311](https://nvd.nist.gov/vuln/detail/CVE-2026-97311)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-24

A flaw was found in the Admin REST API of Keycloak, an identity and access management solution. The endpoints used to retrieve groups associated with a specific role do not properly check for individual group visibility permissions. This allows a delegated administrator with basic search privileges to view detailed information about all groups assigned to a role, bypassing intended security restrictions that should limit their view to specific groups.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-93641 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-93641)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-25

General infrastructure flaw in Zimbra webmail widely deployed across public-sector and enterprise environments, enabling session hijacking and email interception.

*Deep dive: `TIER_2_CVE-2026-93641.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine