# **Infrastructure Daily Brief: 2026-09-21**

**Infrastructure Daily Report TLP:GREEN Alert Id: 8af9db70 2026-09-22 15:02:46**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-77560 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-85751 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-73547 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-94412 (Tier 2)                                                          | 3.k      |
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.e      |
| Threats    | GhostCode Phishing Kit Bypasses Microsoft 365 MFA to Hijack Accounts in 78 Secon | 1.b      |
| Threats    | GhostCode Abuses Microsoft Device Codes to Steal M365 Tokens and Register Rogue  | 1.b      |
| Threats    | GhostCode Abuses Microsoft Entra Device Enrollment to Maintain Access After Toke | 1.f      |
| Threats    | Microsoft 365: Block Device Code Flow Against GhostCode                          | 1.e      |
| Threats    | GhostCode attackers abuse device codes to take over Microsoft 365 accounts       | 1.e      |
| Threats    | Operation HookedWing: 4-Year Phishing Campaign Hits 500+                         | 1.c      |
| Threats    | CVE-2026-94215                                                                   | 1.b      |
| Threats    | CVE-2026-94213                                                                   | 1.b      |
| Threats    | CVE-2026-94217                                                                   | 1.b      |
| Threats    | CVE-2026-94218                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.e**

Source: ketch Published: 2026-09-21

Threat actors leverage AI to automate device code phishing at scale, generating live authentication prompts on demand. This campaign bypasses traditional email filters by targeting users directly with dynamic codes, enabling rapid account takeover and persistent access. Defenders should monitor for anomalous device code requests and restrict OAuth consent flows.

___________________________________


# **[GhostCode Phishing Kit Bypasses Microsoft 365 MFA to Hijack Accounts in 78 Seconds](https://cybersecuritynews.com/ghostcode-phishing-kit/amp)**

**PIR: 1.b**

Source: ketch Published: 2026-09-21

A newly discovered GhostCode phishing kit bypasses Microsoft 365 MFA in under two minutes. The kit automates device code interception and token theft, enabling rapid account hijacking. Security operations should deploy MFA fatigue defenses, restrict interactive login flows, and implement behavioral analytics to detect automated credential harvesting campaigns.

___________________________________


# **[GhostCode Abuses Microsoft Device Codes to Steal M365 Tokens and Register Rogue Devices](https://cyberpress.org/ghostcode-m365-device-code)**

**PIR: 1.b**

Source: ketch Published: 2026-09-21

The GhostCode toolkit abuses Microsoft device codes to extract valid M365 access tokens and register unauthorized devices. This technique allows attackers to maintain persistence even after password resets. Defenders should monitor Entra ID sign-in logs for token theft indicators, restrict app registrations, and implement token lifetime policies.

___________________________________


# **[GhostCode Abuses Microsoft Entra Device Enrollment to Maintain Access After Token Revocation](https://gbhackers.com/ghostcode-abuses-microsoft-entra)**

**PIR: 1.f**

Source: ketch Published: 2026-09-21

Attackers leverage Microsoft Entra device enrollment to retain access after token revocation. By registering rogue devices during the initial compromise, GhostCode operators create persistent backdoors. IT teams must enforce device compliance policies, audit enrollment approvals, and monitor for unauthorized device additions in Entra ID.

___________________________________


# **[Microsoft 365: Block Device Code Flow Against GhostCode](https://windowsforum.com/news/microsoft-365-block-device-code-flow-against-ghostcode.444973)**

**PIR: 1.e**

Source: ketch Published: 2026-09-21

Administrators can mitigate GhostCode attacks by disabling the device code flow in Microsoft 365. This configuration change prevents threat actors from exploiting the interactive authentication mechanism to steal tokens. Implementing conditional access policies and restricting device enrollment scopes further reduces exposure to automated credential harvesting.

___________________________________


# **[GhostCode attackers abuse device codes to take over Microsoft 365 accounts](https://computerworld.com/article/4223889/ghostcode-attackers-abuse-device-codes-to-take-over-microsoft-365-accounts.html)**

**PIR: 1.e**

Source: ketch Published: 2026-09-21

GhostCode operators exploit Microsoft’s device code authentication to hijack M365 accounts. By tricking users into entering codes on malicious portals, attackers bypass standard MFA controls. Infrastructure teams must audit active device code sessions, enforce strict conditional access rules, and deploy real-time alerting for suspicious authentication patterns.

___________________________________


# **[Operation HookedWing: 4-Year Phishing Campaign Hits 500+](https://cipherssecurity.com/operation-hookedwing-phishing-500/)**

**PIR: 1.c**

Source: ketch Published: 2026-09-21

Operation HookedWing represents a sustained, four-year spear phishing campaign targeting over 500 organizations. Attackers use highly tailored lures to harvest credentials and deploy persistent access tools. Defenders should review historical email logs, enforce least-privilege access, and implement advanced phishing simulation and detection controls.

___________________________________


# **[CVE-2026-94215](https://nvd.nist.gov/vuln/detail/CVE-2026-94215)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-21

A flaw was found in the Admin REST API of Keycloak, an open-source identity and access management solution. The issue occurs because the API uses a per-request in-memory cache to resolve clients by their unique identifier without verifying if the client belongs to the realm specified in the request path. This allows an administrator with limited privileges to read or modify sensitive client configurations in the master realm by accessing them through a realm they control. Successful exploitation

___________________________________


# **[CVE-2026-94213](https://nvd.nist.gov/vuln/detail/CVE-2026-94213)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-21

A flaw was found in the Authorization Services component of Keycloak, an open-source identity and access management solution. The issue occurs in the policy evaluation endpoint, which is used by administrators to test how access policies apply to specific users. Due to missing authorization checks, a delegated administrator with limited viewing privileges can access the full profile and role information of any user in the realm, even if they are not permitted to view user details. This could lea

___________________________________


# **[CVE-2026-94217](https://nvd.nist.gov/vuln/detail/CVE-2026-94217)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-21

A flaw was found in the User-Managed Access (UMA) implementation of Keycloak. The issue occurs in the authorization token endpoint when processing permission tickets. If two different users own resources with the same name, the system incorrectly merges the permissions from both resources when one user requests an authorization token. This allows an attacker to gain access scopes on a victim's resource that were never intended to be shared.

___________________________________


# **[CVE-2026-94218](https://nvd.nist.gov/vuln/detail/CVE-2026-94218)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-21

A flaw was found in the authentication session management of Keycloak, an identity and access management solution. The issue occurs when an administrator enforces a stronger authentication flow, such as mandatory two-factor authentication (2FA) setup, through a client policy. A user can bypass this requirement by manually visiting a specific session restart web link during the login process. This action clears the internal markers that track the required security steps, allowing the user to log 

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-77560 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-77560)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-21

TIER 2 authorization bypass in Tinyauth forward-auth middleware directly impacts Digital Identity infrastructure by allowing authenticated users to bypass per-app access controls via Host header case manipulation.

*Deep dive: `TIER_2_CVE-2026-77560.md`*

___________________________________


# **[CVE-2026-85751 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-85751)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-21

Authentication bypass in internet-facing mail servers impacts foundational communications infrastructure across Government, Finance, Healthcare, and Digital Identity sectors.

*Deep dive: `TIER_2_CVE-2026-85751.md`*

___________________________________


# **[CVE-2026-73547 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-73547)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-21

Foundational cloud-native edge proxy and service mesh component underpinning regulated and public digital service architectures, though exploitation requires non-default configurations.

*Deep dive: `TIER_2_CVE-2026-73547.md`*

___________________________________


# **[CVE-2026-94412 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-94412)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-21

Finance sector relevance due to ERP system handling SME financial operations and procurement data.

*Deep dive: `TIER_2_CVE-2026-94412.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine