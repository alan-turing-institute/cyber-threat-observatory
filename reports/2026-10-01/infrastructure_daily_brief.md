# **Infrastructure Daily Brief: 2026-10-01**

**Infrastructure Daily Report TLP:GREEN Alert Id: 7c62095a 2026-10-02 10:29:09**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-76143 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-103264 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-73975 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-76142 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-76146 (Tier 2)                                                          | 3.k      |
| Threats    | Inside an AI‑enabled device code phishing campaign | Microsoft Security Blog     | 1.j      |
| Threats    | Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Se | 1.j      |
| Threats    | AI-Generated Lures Behind Microsoft Cloud Account Takeovers                      | 1.h      |
| Threats    | Midnight Blizzard-Linked Actor GTG-20006 Automated Device Code Phishing With AI  | 1.j      |
| Threats    | Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA      | 1.g      |
| Threats    | Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA                  | 1.i      |
| Threats    | Access granted: phishing with device code authorization for account takeover | P | 1.j      |
| Threats    | Passkey-themed social engineering leads to identity and cloud compromise         | 1.e      |
| Threats    | CVE-2026-76504                                                                   | 3.k      |
| Threats    | CVE-2026-102115                                                                  | 1.b      |
| Threats    | CVE-2026-88920                                                                   | 1.b      |
| Threats    | CVE-2026-97274                                                                   | 1.b      |
| Threats    | CVE-2026-102149                                                                  | 1.b      |
| Threats    | CVE-2026-102106                                                                  | 1.b      |
| Threats    | CVE-2026-103651                                                                  | 1.b      |
| Threats    | CVE-2026-102128                                                                  | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Inside an AI‑enabled device code phishing campaign | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.j**

Source: ketch Published: 2026-10-01

This campaign combines AI-driven reconnaissance with device code phishing to bypass multi-factor authentication. Attackers generate context-aware prompts that direct users to enter authorization codes on attacker-controlled endpoints. Once validated, threat actors gain persistent access to cloud identities. Defenders should monitor OAuth consent logs, restrict device code flows to approved applications, and implement real-time alerting for suspicious authorization requests.

___________________________________


# **[Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/)**

**PIR: 1.j**

Source: ketch Published: 2026-10-01

EvilTokens represents a sophisticated evolution of device code phishing, enabling attackers to silently harvest valid OAuth tokens without user interaction. By exploiting legitimate authentication flows, these tokens grant persistent access to Microsoft 365 and Azure resources. Infrastructure defenders must audit token issuance patterns, enforce short-lived token policies, and deploy identity threat detection tools to identify anomalous consent grants and token reuse.

___________________________________


# **[AI-Generated Lures Behind Microsoft Cloud Account Takeovers](https://labs.cloudsecurityalliance.org/research/csa-research-note-genai-passkey-phishing-msft-20260914-csa-s)**

**PIR: 1.h**

Source: ketch Published: 2026-10-01

Generative AI is being weaponized to create highly personalized phishing lures targeting Microsoft 365 administrators and high-privilege users. These AI-crafted messages bypass traditional spam filters by mimicking internal communication styles and referencing real project contexts. Infrastructure teams must prioritize behavioral analytics, deploy AI-aware email security gateways, and enforce strict least-privilege access to mitigate account takeover risks.

___________________________________


# **[Midnight Blizzard-Linked Actor GTG-20006 Automated Device Code Phishing With AI](https://aegisai.ai/blog/anthropic-midnight-blizzard-ai-device-code-phishing)**

**PIR: 1.j**

Source: ketch Published: 2026-10-01

A state-linked threat group has automated device code phishing operations using AI to scale targeting and adapt lures in real time. The campaign focuses on government and critical infrastructure accounts, leveraging stolen credentials and AI-generated prompts to bypass MFA. Defenders should implement automated threat hunting for OAuth anomalies, restrict device code authentication to managed devices, and integrate AI detection models into identity protection workflows.

___________________________________


# **[Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA](https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns)**

**PIR: 1.g**

Source: ketch Published: 2026-10-01

Threat actors increasingly leverage cloud-native services like serverless functions, object storage, and CDN networks to host phishing infrastructure. This approach bypasses traditional IP-based blocklists and complicates takedown efforts. Infrastructure defenders must monitor cloud provider abuse reports, implement DNS sinkholing for dynamic domains, and deploy cloud workload protection platforms to detect anomalous resource provisioning tied to credential harvesting campaigns.

___________________________________


# **[Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA](https://tempmail.ninja/blog/laundry-bear-zimbra-phishing)**

**PIR: 1.i**

Source: ketch Published: 2026-10-01

CISA has issued an alert regarding a zero-click phishing campaign exploiting a critical vulnerability in Zimbra collaboration suites. The attack requires no user interaction, automatically delivering malicious payloads that establish persistent backdoors. Infrastructure teams must immediately patch Zimbra instances, deploy network segmentation for email servers, and monitor for unauthorized outbound connections indicative of command-and-control activity.

___________________________________


# **[Access granted: phishing with device code authorization for account takeover | Proofpoint US](https://www.proofpoint.com/us/blog/threat-insight/access-granted-phishing-device-code-authorization-account-takeover)**

**PIR: 1.j**

Source: ketch Published: 2026-10-01

This analysis details how threat actors abuse device code authorization flows to harvest valid access tokens and bypass traditional MFA controls. By directing users to enter codes on compromised endpoints, attackers gain seamless access to cloud environments. Defenders should enforce strict OAuth consent policies, monitor for high-frequency device code requests, and implement user verification steps for sensitive authorization flows.

___________________________________


# **[Passkey-themed social engineering leads to identity and cloud compromise](https://www.microsoft.com/en-us/security/blog/2026/09/09/passkey-themed-social-engineering-leads-identity-cloud-compromise/)**

**PIR: 1.e**

Source: ketch Published: 2026-10-01

Attackers are deploying sophisticated social engineering tactics that mimic passkey authentication prompts to trick users into granting unauthorized access. These campaigns exploit trust in modern passwordless protocols, leading to rapid identity compromise and lateral movement across cloud environments. Defenders should enforce conditional access policies, monitor for anomalous authentication requests, and educate users on verifying legitimate passkey challenges versus spoofed interfaces.

___________________________________


# **[CVE-2026-76504](https://nvd.nist.gov/vuln/detail/CVE-2026-76504)**

**PIR: 3.k**

Source: vulners/duckdb Published: 2026-09-30

A vulnerability in the API session-based authentication management of Cisco Catalyst SD-WAN Manager could allow an unauthenticated, remote attacker to access an affected system with privileges of the admin user.

This vulnerability is due to improper handling of URI encoding in an HTTP request, which allows the request to bypass an authentication rule that is intended to restrict access to a specific API endpoint. An attacker could exploit this vulnerability by sending a crafted HTTP request t

___________________________________


# **[CVE-2026-102115](https://nvd.nist.gov/vuln/detail/CVE-2026-102115)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-30

Kiteworks Core did not correctly validate a parameter submitted to the password reset workflow. An unauthenticated attacker who knew the email address of a user with a locally stored password could potentially reset that account's password without access to the emailed reset link and then authenticate as that user, including where the account holds administrative privileges.

___________________________________


# **[CVE-2026-88920](https://nvd.nist.gov/vuln/detail/CVE-2026-88920)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-30

An authentication bypass in the DOM security processor in Apache WSS4J allows unauthenticated remote attackers to forge authenticated SOAP messages via a crafted unsigned SAML sender-vouches assertion containing an attacker-controlled key.

Users are recommended to upgrade to versions 4.0.2 or 3.0.6 or 2.4.4, which fix this issue.

___________________________________


# **[CVE-2026-97274](https://nvd.nist.gov/vuln/detail/CVE-2026-97274)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-30

Unauthenticated Bypass Vulnerability in OAuth Single Sign On – SSO (OAuth Client) <= 7.1.2 versions.

___________________________________


# **[CVE-2026-102149](https://nvd.nist.gov/vuln/detail/CVE-2026-102149)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-30

Kiteworks Email Protection Gateway did not sufficiently restrict which account a certificate could be assigned to. This could allow an attacker to associate a certificate with another user's account, affecting the confidentiality and integrity of that account's encrypted mail and, where certificate-based login is enabled, potentially permitting unauthorized access to the account.

___________________________________


# **[CVE-2026-102106](https://nvd.nist.gov/vuln/detail/CVE-2026-102106)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-30

Improper authentication in a Kiteworks Email Protection Gateway administrative service. An administrative service in Kiteworks Email Protection Gateway did not consistently enforce administrator authentication, so the required password check could be bypassed. An attacker who referenced a valid administrator account could potentially create, modify, or delete internal users and managed domains and change their security-feature configuration without authenticating; deleting a managed domain also 

___________________________________


# **[CVE-2026-103651](https://nvd.nist.gov/vuln/detail/CVE-2026-103651)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-01

MISP contains a vulnerability in its one-time password (OTP) authentication flow that allows replay of a consumed HOTP (paper) token and rewinding of the token counter.

The HOTP verification logic compared the submitted token against a counter value that was cached in the user's session at the time the password was entered, rather than against the authoritative counter stored in the database. Because the session-cached counter is not updated after a token is successfully consumed, an attacker w

___________________________________


# **[CVE-2026-102128](https://nvd.nist.gov/vuln/detail/CVE-2026-102128)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-30

An identity-verification weakness in Kiteworks Email Protection Gateway allowed the gateway to act on the Kiteworks platform on behalf of a user it had not authenticated, and to provision a platform account for an identity it did not already know. A remote, unauthenticated sender could potentially exploit this to obtain control of a platform account.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-76143 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-76143)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-01

TIER 2 MFA bypass in Genian SSL PNS/ZTNA gateways directly compromises public-facing authentication and identity verification infrastructure.

*Deep dive: `TIER_2_CVE-2026-76143.md`*

___________________________________


# **[CVE-2026-103264 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-103264)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-01

Authentication bypass in Fleet MDM exposes device management APIs in Government, Finance, and Healthcare sectors, risking unauthorized device control and data access.

*Deep dive: `TIER_2_CVE-2026-103264.md`*

___________________________________


# **[CVE-2026-73975 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-73975)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-01

Impacts national and institutional research data repositories (Government/Public Research Infrastructure), threatening metadata integrity and public data trust in critical scientific infrastructure.

*Deep dive: `TIER_2_CVE-2026-73975.md`*

___________________________________


# **[CVE-2026-76142 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-76142)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-01

Critical zero-trust policy server flaw undermines government and critical infrastructure access controls, though external exploitation requires explicit proxy misconfiguration.

*Deep dive: `TIER_2_CVE-2026-76142.md`*

___________________________________


# **[CVE-2026-76146 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-76146)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-01

TIER 2 RCE in Genian SSL PNS VPN/ZTNA gateway, a foundational perimeter access control explicitly tied to government and critical infrastructure deployments.

*Deep dive: `TIER_2_CVE-2026-76146.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine