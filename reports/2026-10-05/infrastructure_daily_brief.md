# **Infrastructure Daily Brief: 2026-10-05**

**Infrastructure Daily Report TLP:GREEN Alert Id: e28f5aa3 2026-10-06 22:50:04**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                      | PIR(s)   |
|------------|-----------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-105307 (Tier 2)                                                    | 3.k      |
| Cyber News | CVE-2026-105384 (Tier 2)                                                    | 3.k      |
| Cyber News | CVE-2026-104891 (Tier 2)                                                    | 3.k      |
| Cyber News | CVE-2026-105385 (Tier 2)                                                    | 3.k      |
| Cyber News | CVE-2026-105387 (Tier 2)                                                    | 3.k      |
| Cyber News | CVE-2026-105470 (Tier 2)                                                    | 3.k      |
| Cyber News | CVE-2026-105471 (Tier 2)                                                    | 3.k      |
| Cyber News | CVE-2026-21589 (Tier 2)                                                     | 3.k      |
| Cyber News | CVE-2026-105383 (Tier 2)                                                    | 3.k      |
| Cyber News | CVE-2026-55280 (Tier 2)                                                     | 3.k      |
| Cyber News | CVE-2026-79820 (Tier 2)                                                     | 3.k      |
| Cyber News | CVE-2026-49885 (Tier 2)                                                     | 3.k      |
| Threats    | The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations    | 1.e      |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover                   | 1.f      |
| Threats    | Inside an AI‑enabled device code phishing campaign                          | 1.f      |
| Threats    | Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA | 1.g      |
| Threats    | Microsoft 365 Device Code Phishing Campaign Bypasses Password Theft ...     | 1.f      |
| Threats    | AI-Generated Lures Behind Microsoft Cloud Account Takeovers                 | 1.d      |
| Threats    | Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA             | 1.i      |
| Threats    | Storm-2372 conducts device code phishing campaign                           | 1.b      |
| Threats    | CVE-2026-88779                                                              | 1.b      |
| Threats    | CVE-2026-105207                                                             | 1.b      |
| Threats    | CVE-2026-105213                                                             | 1.b      |
| Threats    | CVE-2026-105210                                                             | 1.b      |
| Threats    | CVE-2026-105212                                                             | 1.b      |
| Threats    | CVE-2026-59358                                                              | 1.b      |
| Threats    | CVE-2026-105306                                                             | 1.b      |
| Threats    | CVE-2026-105302                                                             | 1.b      |
| Threats    | CVE-2026-105305                                                             | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations](https://itsecurityguru.org/2026/05/27/the-ai-phishing-revolution-from-spray-and-pray-to-autonomous-operations)**

**PIR: 1.e**

Source: ketch Published: 2026-10-05

Generative AI is transforming phishing from broad, low-success campaigns into highly targeted, autonomous operations. Attackers now use LLMs to craft context-aware lures, automate victim interaction, and dynamically adapt payloads. Defenders must shift from signature-based detection to behavioral analytics and AI-driven threat hunting to protect identity perimeters.

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.f**

Source: ketch Published: 2026-10-05

Device code phishing is rapidly expanding as threat actors exploit OAuth 2.0 device authorization flows to bypass MFA. Publicly available toolkits and phishing-as-a-service platforms have lowered the barrier to entry. Defenders must implement strict OAuth consent policies, monitor device code grants, and educate users on authorization prompts.

___________________________________


# **[Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.f**

Source: ketch Published: 2026-10-05

This campaign demonstrates how AI automates device code phishing at scale, generating live authentication codes on demand. By combining AI-driven lure generation with end-to-end automation, attackers achieve higher success rates and maintain persistent access. Security teams should deploy real-time session monitoring and restrict device code grant scopes.

___________________________________


# **[Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA](https://www.cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns/)**

**PIR: 1.g**

Source: ketch Published: 2026-10-05

Threat actors increasingly leverage cloud-native services like serverless functions, object storage, and container registries to host phishing infrastructure. This approach bypasses traditional IP-based blocklists and complicates takedown efforts for defenders. Understanding these tactics is critical for securing modern cloud environments and implementing effective egress filtering.

___________________________________


# **[Microsoft 365 Device Code Phishing Campaign Bypasses Password Theft ...](https://cybersecuritynews.com/microsoft-365-device-code-phishing-campaign/)**

**PIR: 1.f**

Source: ketch Published: 2026-10-05

Analysts documented a campaign leveraging Microsoft’s Device Authorization Grant flow to execute near-invisible account takeovers. The attack uses realistic business-themed emails and polished phishing kits to trick users into authorizing malicious apps. Defenders must audit M365 app permissions and enforce strict consent workflows.

___________________________________


# **[AI-Generated Lures Behind Microsoft Cloud Account Takeovers](https://labs.cloudsecurityalliance.org/research/csa-research-note-genai-passkey-phishing-msft-20260914-csa-s)**

**PIR: 1.d**

Source: ketch Published: 2026-10-05

Recent Microsoft cloud account compromises exploit AI-generated passkey and authentication lures that mimic legitimate Microsoft branding. These sophisticated attacks bypass traditional MFA by tricking users into authorizing malicious sessions. Infrastructure teams should enforce conditional access policies and monitor for anomalous authentication patterns.

___________________________________


# **[Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA](https://tempmail.ninja/blog/laundry-bear-zimbra-phishing)**

**PIR: 1.i**

Source: ketch Published: 2026-10-05

CISA warned of a zero-click phishing campaign targeting Zimbra email servers, exploiting vulnerabilities to deliver malicious payloads without user interaction. This technique bypasses traditional email security gateways and user training programs. Infrastructure teams must prioritize patch management, network segmentation, and advanced threat detection for email platforms.

___________________________________


# **[Storm-2372 conducts device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/)**

**PIR: 1.b**

Source: ketch Published: 2026-10-05

Microsoft Threat Intelligence tracked Storm-2372’s campaign, which mimics messaging apps like WhatsApp, Signal, and Teams to deliver device code phishing lures. Active since August 2024, the campaign targets specific organizations with highly contextualized messages. Defenders should monitor for unauthorized messaging app integrations and enforce strict OAuth consent policies.

___________________________________


# **[CVE-2026-88779](https://nvd.nist.gov/vuln/detail/CVE-2026-88779)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-04

Vulnerability in NetScaler ADC and NetScaler Gateway.

This issue affects ADC: before 14.1-73.41, before 13.1-64.28, before 14.1-73.41 FIPS, and before 13.1-37.282; Gateway: before 14.1-73.41 and before 13.1-64.28.

___________________________________


# **[CVE-2026-105207](https://nvd.nist.gov/vuln/detail/CVE-2026-105207)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-04

ZITADEL 3.0.0 through 3.4.15 and 4.0.0 before 4.17.3 creates links between user accounts and external identity providers without verifying a primary factor or the caller's permission, including on identify-only Login V2 sessions and via the User Service V2 AddIDPLink endpoint. An unauthenticated attacker knowing a victim's login name can bind their own external IdP identity to the victim's account and then sign in as the victim.

___________________________________


# **[CVE-2026-105213](https://nvd.nist.gov/vuln/detail/CVE-2026-105213)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-04

ZITADEL 4.x before 4.17.1 does not check an organization's inactive state during Login V2 authentication, verifying only the individual user's status. Users of a deactivated organization who hold valid credentials, an existing session, or a refresh token can still sign in, create sessions, and obtain or refresh tokens.

___________________________________


# **[CVE-2026-105210](https://nvd.nist.gov/vuln/detail/CVE-2026-105210)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-04

ZITADEL 3.x before 3.4.15 and 4.x before 4.17.1 contains a missing authentication flaw in the hosted Login V1 UI, whose second-factor enrollment and initialization handlers act on an identify-only session before any primary factor is verified. Attackers knowing only a victim's login name can enroll attacker-controlled TOTP, OTP-SMS, OTP-Email, or U2F factors, overwrite the verified phone number, and enumerate users through discrepant errors.

___________________________________


# **[CVE-2026-105212](https://nvd.nist.gov/vuln/detail/CVE-2026-105212)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-04

ZITADEL 3.x before 3.4.14 and 4.x before 4.16.2 contains an authentication bypass in the hosted Login V1 and Login V2 UIs that accepts passkey or other authenticator enrollment on identify-only login sessions, before any primary factor is verified. Unauthenticated attackers knowing only a victim's login name can register an attacker-controlled authenticator and log in as that user, bypassing existing passwords and MFA.

___________________________________


# **[CVE-2026-59358](https://nvd.nist.gov/vuln/detail/CVE-2026-59358)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-06

Improper authentication (CWE-287) in the OAuth token endpoint in Cloud Foundry UAA allows a remote, authenticated attacker holding a valid user access token to obtain a fully-privileged client_credentials token for the OAuth client that issued it, by presenting the user token as an OAuth 2.0 Bearer credential on a client_credentials grant request in place of the client’s configured secret.



UAA’s client_credentials handling does not verify that the Bearer credential supplied for client authent

___________________________________


# **[CVE-2026-105306](https://nvd.nist.gov/vuln/detail/CVE-2026-105306)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-05

A flaw was found in the Dynamic Client Registration flow of the Keycloak identity and access management server. The issue occurs because the registration process fails to filter security-sensitive client attributes when a new client is created. An attacker with a valid Initial Access Token can register a client that bypasses audience checks during token introspection. This allows the attacker to view sensitive identity information, roles, and session details from access tokens belonging to other

___________________________________


# **[CVE-2026-105302](https://nvd.nist.gov/vuln/detail/CVE-2026-105302)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-05

A flaw was found in the User Session Note mapper of the Keycloak identity and access management solution. The issue occurs because the mapper does not validate whether a requested session note contains sensitive internal credentials, such as federated access tokens from external identity providers. This allows a delegated client administrator to leak a user's upstream bearer tokens into the tokens issued to their managed application, potentially leading to unauthorized access to the user's data 

___________________________________


# **[CVE-2026-105305](https://nvd.nist.gov/vuln/detail/CVE-2026-105305)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-06

A flaw was found in the OIDC implementation of Keycloak, specifically within the Device Authorization Grant flow. This component allows devices with limited input capabilities to obtain security tokens. The issue occurs because the flow fails to check the minimum authentication level required by a client configuration. This allows an attacker who has stolen a user's password to bypass mandatory multi-factor authentication and gain unauthorized access to the Keycloak Admin REST API.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-105307 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-105307)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-05

Unauthenticated authentication bypass in Casdoor, an open-source IAM/SSO platform, directly compromises Digital Identity infrastructure by enabling remote attackers to manipulate credential flows and access controls.

*Deep dive: `TIER_2_CVE-2026-105307.md`*

___________________________________


# **[CVE-2026-105384 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-105384)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-05

Unauthenticated SQLi in a Hospital Management System enables full extraction of patient PII and clinical records, directly impacting Healthcare DPI and triggering HIPAA/GDPR compliance risks.

*Deep dive: `TIER_2_CVE-2026-105384.md`*

___________________________________


# **[CVE-2026-104891 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-104891)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-05

Finance sector: payment verification bypass in crypto payment gateway middleware allows unauthenticated attackers to spoof wallet ownership and bypass financial controls.

*Deep dive: `TIER_2_CVE-2026-104891.md`*

___________________________________


# **[CVE-2026-105385 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-105385)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-05

Unauthenticated SQLi in a hospital management system risks patient data breaches and financial record corruption, directly impacting healthcare digital infrastructure.

*Deep dive: `TIER_2_CVE-2026-105385.md`*

___________________________________


# **[CVE-2026-105387 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-105387)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-05

Healthcare sector: Unauthenticated SQLi and auth bypass in a public-facing clinic appointment system exposes patient records and disrupts clinical scheduling.

*Deep dive: `TIER_2_CVE-2026-105387.md`*

___________________________________


# **[CVE-2026-105470 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-105470)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-05

Unauthenticated SQLi in a public-facing healthcare appointment booking system exposes patient PII and disrupts clinical administrative workflows.

*Deep dive: `TIER_2_CVE-2026-105470.md`*

___________________________________


# **[CVE-2026-105471 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-105471)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-05

Unauthenticated SQLi in a public-facing healthcare appointment system exposes patient records and credentials, posing direct HIPAA/GDPR compliance risks.

*Deep dive: `TIER_2_CVE-2026-105471.md`*

___________________________________


# **[CVE-2026-21589 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-21589)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-05

Impacts Atlassian Crowd (enterprise IdAM) and widely deployed collaboration suites across government, finance, and healthcare, posing a read-only file access risk to authentication and service infrastructure.

*Deep dive: `TIER_2_CVE-2026-21589.md`*

___________________________________


# **[CVE-2026-105383 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-105383)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-05

Unauthenticated SQLi in a hospital management system exposes patient records and clinical transaction data, directly impacting Healthcare DPI.

*Deep dive: `TIER_2_CVE-2026-105383.md`*

___________________________________


# **[CVE-2026-55280 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-55280)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-05

Remote privilege escalation in Android OS impacts enterprise and public-sector mobile deployments, threatening endpoint integrity and internal network access.

*Deep dive: `TIER_2_CVE-2026-55280.md`*

___________________________________


# **[CVE-2026-79820 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-79820)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-05

Critical server management firmware (HPE iLO 7) underpins data center infrastructure hosting regulated and public digital services; authentication bypass risks full host compromise.

*Deep dive: `TIER_2_CVE-2026-79820.md`*

___________________________________


# **[CVE-2026-49885 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-49885)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-05

Tier 2 local privilege escalation in Android OS, foundational mobile infrastructure explicitly deployed across enterprise and government sectors.

*Deep dive: `TIER_2_CVE-2026-49885.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine