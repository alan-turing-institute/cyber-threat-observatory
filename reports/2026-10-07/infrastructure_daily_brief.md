# **Infrastructure Daily Brief: 2026-10-07**

**Infrastructure Daily Report TLP:GREEN Alert Id: a0405d84 2026-10-08 12:23:05**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-102256 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-103416 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-107102 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-107104 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-107162 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-97716 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-76268 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-76468 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-76471 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-77214 (Tier 2)                                                          | 3.k      |
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.j      |
| Threats    | OAuth Device Code Phishing: M365 Defense Guide                                   | 1.j      |
| Threats    | AI-Enabled Device Code Phishing Campaign Abuses Device Code Sign-In Flow         | 1.j      |
| Threats    | Device Code Phishing: The MFA Bypass That Uses Microsoft's Own Login Page        | 1.e      |
| Threats    | Midnight Blizzard-Linked Actor GTG-20006 Automated Device Code Phishing With AI  | 1.i      |
| Threats    | The Device Code Phishing Tsunami: What We’re Seeing in the Wild                  | 1.j      |
| Threats    | GhostCode attackers abuse device codes to take over Microsoft 365 accounts       | 1.a      |
| Threats    | PhantomEnigma: How a Malware Crew Turned Brazilian Government Sites Into Trusted | 1.f      |
| Threats    | CVE-2026-92414                                                                   | 1.b      |
| Threats    | CVE-2026-76483                                                                   | 1.b      |
| Threats    | CVE-2026-106488                                                                  | 1.b      |
| Threats    | CVE-2026-83540                                                                   | 1.b      |
| Threats    | CVE-2026-59358                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.j**

Source: ketch Published: 2026-10-07

Microsoft details a sophisticated phishing campaign leveraging AI-driven infrastructure to automate the OAuth device code flow. Unlike previous manual scripts, this operation uses end-to-end automation to bypass multi-factor authentication by redirecting victims to legitimate Microsoft login pages. The campaign represents a significant escalation in threat actor sophistication, building on techniques first observed in the Storm-2372 campaign. Defenders are advised to monitor for anomalous device

___________________________________


# **[OAuth Device Code Phishing: M365 Defense Guide](https://protego.me/blog/oauth-device-code-phishing-mfa-bypass-microsoft-365)**

**PIR: 1.j**

Source: ketch Published: 2026-10-07

Protego provides a comprehensive defense guide for mitigating OAuth device code phishing in Microsoft 365 tenants. The resource details step-by-step configurations for Azure AD Conditional Access, including blocking device code flows for guest users and enforcing risk-based authentication. It also covers PowerShell scripts for hunting historical device code grants and integrating detection rules with Microsoft Sentinel for automated incident response.

___________________________________


# **[AI-Enabled Device Code Phishing Campaign Abuses Device Code Sign-In Flow](https://captechgroup.com/threat-intelligence-center/ai-enabled-device-code-phishing-campaign-abuses-de-81a334)**

**PIR: 1.j**

Source: ketch Published: 2026-10-07

CapTech Group analyzes how threat actors exploit the OAuth device code sign-in flow to circumvent MFA protections. The report breaks down the technical mechanics of the attack, highlighting how attackers automate the pairing process to harvest valid access tokens. Infrastructure defenders can use these insights to configure Azure AD sign-in risk policies, detect suspicious device code requests, and deploy real-time alerting for unauthorized token issuance.

___________________________________


# **[Device Code Phishing: The MFA Bypass That Uses Microsoft's Own Login Page](https://phishingtackle.com/blog/device-code-phishing-mfa-bypass)**

**PIR: 1.e**

Source: ketch Published: 2026-10-07

This guide explains how device code phishing effectively bypasses MFA by leveraging Microsoft’s official authentication portal. Attackers trick users into entering a verification code on a compromised device, granting the threat actor full account access without triggering traditional phishing alerts. The article outlines defensive measures, including user awareness training, conditional access restrictions for device code flows, and monitoring for impossible travel or concurrent session anomali

___________________________________


# **[Midnight Blizzard-Linked Actor GTG-20006 Automated Device Code Phishing With AI](https://aegisai.ai/blog/anthropic-midnight-blizzard-ai-device-code-phishing)**

**PIR: 1.i**

Source: ketch Published: 2026-10-07

AegisAI attributes an AI-automated device code phishing campaign to GTG-20006, a threat actor linked to Midnight Blizzard. The report highlights how machine learning models optimize phishing lures and automate victim interaction to accelerate token theft. Infrastructure teams are advised to deploy AI-driven threat detection, monitor for rapid sequential device code validations, and restrict OAuth app permissions to minimize blast radius during identity breaches.

___________________________________


# **[The Device Code Phishing Tsunami: What We’re Seeing in the Wild](https://www.levelblue.com/blogs/spiderlabs-blog/the-device-code-phishing-tsunami-what-were-seeing-in-the-wild)**

**PIR: 1.j**

Source: ketch Published: 2026-10-07

LevelBlue’s SpiderLabs team documents a surge in device code phishing attacks targeting enterprise environments. The analysis covers observed TTPs, including the use of legitimate Microsoft authentication endpoints to validate stolen codes. The article provides actionable detection strategies for SIEM and EDR platforms, emphasizing log correlation for OAuth 2.0 device authorization grants and recommendations for hardening identity perimeters against automated token theft.

___________________________________


# **[GhostCode attackers abuse device codes to take over Microsoft 365 accounts](https://computerworld.com/article/4223889/ghostcode-attackers-abuse-device-codes-to-take-over-microsoft-365-accounts.html)**

**PIR: 1.a**

Source: ketch Published: 2026-10-07

Computerworld reports on the GhostCode threat group leveraging device code phishing to compromise Microsoft 365 environments. The campaign targets high-value accounts by combining social engineering with automated token harvesting. Defenders are urged to review audit logs for unusual device code sign-ins, enforce phishing-resistant MFA methods like FIDO2, and implement zero-trust network access controls to limit lateral movement post-compromise.

___________________________________


# **[PhantomEnigma: How a Malware Crew Turned Brazilian Government Sites Into Trusted Malware Hubs](https://securebulletin.com/phantomenigma-how-a-malware-crew-turned-brazilian-government-sites-into-trusted-malware-hubs)**

**PIR: 1.f**

Source: ketch Published: 2026-10-07

SecureBulletin investigates PhantomEnigma’s campaign compromising Brazilian government websites to host malware and phishing infrastructure. By leveraging trusted domains, attackers bypass reputation-based security controls and distribute malicious payloads to unsuspecting users. Defenders should implement strict DNS filtering, monitor for domain hijacking indicators, and validate certificate transparency logs to detect unauthorized subdomain usage in critical infrastructure environments.

___________________________________


# **[CVE-2026-92414](https://nvd.nist.gov/vuln/detail/CVE-2026-92414)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-07

: Session Fixation / Session Reuse across Users vulnerability in Apache Jackrabbit.



Jackrabbit WebDAV server attaches a cached authenticated session on any Lock-Token/TransactionId/SubscriptionId/If-header field token match with

no credential check.



This issue affects Apache Jackrabbit: from 2.23.0 through 2.23.5, from 2.22.0 through 2.22.4, from 2.20.0 through 2.20.17.












Users are recommended to upgrade to versions 2.23.6, 2.22.5, or 2.20.18 which fix the issue.

___________________________________


# **[CVE-2026-76483](https://nvd.nist.gov/vuln/detail/CVE-2026-76483)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-07

As part of Cisco's ongoing commitment to proactive security and product quality, the engineering team for Cisco License On-Prem, formerly Cisco Smart Software Manager On-Prem (SSM On-Prem), has conducted a comprehensive internal security review. This review resulted in software hardening releases that address multiple internally discovered vulnerabilities. &nbsp;

The vulnerabilities tracked by CVE-2026-76483 are related to issues with insufficiently protected credentials that are grouped unde

___________________________________


# **[CVE-2026-106488](https://nvd.nist.gov/vuln/detail/CVE-2026-106488)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-06

Backstage is an open framework for building developer portals. Prior to 0.4.20, the @backstage/plugin-auth-backend-module-oidc-provider package is affected by improper authentication in the oidc provider. Deployments using OIDC email-based identity resolution with a provider that permits unverified email addresses may allow an authenticated provider user to assume another catalog identity. This may grant access and permissions associated with that user. No direct availability impact is demonstra

___________________________________


# **[CVE-2026-83540](https://nvd.nist.gov/vuln/detail/CVE-2026-83540)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-07

When password or public key authentication is used with the Windows port of wolfSSHd, the Windows logon token acquired for one authenticated connection is not released before a token is acquired for a subsequent connection, resulting in user login poisoning between connections. A less privileged user with a valid account on the server can exploit this to force a login as a more privileged user. The vulnerability was introduced with the initial Windows port of wolfSSHd in wolfSSH version 1.4.15 a

___________________________________


# **[CVE-2026-59358](https://nvd.nist.gov/vuln/detail/CVE-2026-59358)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-06

Improper authentication (CWE-287) in the OAuth token endpoint in Cloud Foundry UAA allows a remote, authenticated attacker holding a valid user access token to obtain a fully-privileged client_credentials token for the OAuth client that issued it, by presenting the user token as an OAuth 2.0 Bearer credential on a client_credentials grant request in place of the client’s configured secret.



UAA’s client_credentials handling does not verify that the Bearer credential supplied for client authent

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-102256 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-102256)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-07

Foundational SSL-VPN gateway flaw impacting Government, Finance, and Healthcare remote access infrastructure; enables full OS compromise and network pivoting post-authentication.

*Deep dive: `TIER_2_CVE-2026-102256.md`*

___________________________________


# **[CVE-2026-103416 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-103416)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-07

Foundational embedded TLS stack explicitly tied to healthcare monitoring and government IoT deployments, where pre-authentication RCE threatens critical public infrastructure.

*Deep dive: `TIER_2_CVE-2026-103416.md`*

___________________________________


# **[CVE-2026-107102 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-107102)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-07

Finance sector relevance due to unauthenticated payment callback manipulation enabling account takeover in multi-tenant ERP systems handling financial records.

*Deep dive: `TIER_2_CVE-2026-107102.md`*

___________________________________


# **[CVE-2026-107104 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-107104)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-07

Unauthenticated RCE in a multi-tenant ERP widely deployed by municipal governments and pharma/finance sectors, risking citizen data and public service operations.

*Deep dive: `TIER_2_CVE-2026-107104.md`*

___________________________________


# **[CVE-2026-107162 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-107162)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-07

Directly impacts OAuth 2.0 token validation in public-facing API gateways, enabling API impersonation and threatening Digital Identity and general infrastructure for regulated/public services.

*Deep dive: `TIER_2_CVE-2026-107162.md`*

___________________________________


# **[CVE-2026-97716 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-97716)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-07

Critical ZTNA/remote access gateway DoS impacting distributed workforces across government, finance, and healthcare deployments.

*Deep dive: `TIER_2_CVE-2026-97716.md`*

___________________________________


# **[CVE-2026-76268 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-76268)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-07

Critical unauthenticated RCE in Splunk Enterprise SIEM, a foundational security/observability stack explicitly tied to government, finance, and healthcare deployments.

*Deep dive: `TIER_2_CVE-2026-76268.md`*

___________________________________


# **[CVE-2026-76468 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-76468)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-07

Foundational Cisco Meraki networking hardware underpins edge and LAN infrastructure across regulated and public-sector digital services.

*Deep dive: `TIER_2_CVE-2026-76468.md`*

___________________________________


# **[CVE-2026-76471 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-76471)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-07

Critical unauthenticated RCE in Cisco NX-OS data center switches, foundational networking infrastructure supporting regulated and public digital services.

*Deep dive: `TIER_2_CVE-2026-76471.md`*

___________________________________


# **[CVE-2026-77214 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-77214)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-07

Foundational XML parsing library with broad transitive use across enterprise and public-sector software stacks, impacting general infrastructure security.

*Deep dive: `TIER_2_CVE-2026-77214.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine