# **Infrastructure Daily Brief: 2026-10-28**

**Infrastructure Daily Report TLP:GREEN Alert Id: 1e12af5c 2026-10-29 13:23:19**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2025-14260 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-104383 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-118669 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-59185 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-59979 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-118264 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-118377 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-118665 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-76418 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-84725 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-86400 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-103409 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-104895 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-110879 (Tier 2)                                                         | 3.k      |
| Threats    | Unmasking EvilTokens: Getting to the root of device code phishing                | 1.e      |
| Threats    | Breaking the code: Multi-stage ‘code of conduct’ phishing campaign leads to AiTM | 1.d      |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover                        | 1.e      |
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.g      |
| Threats    | The ‘code of conduct’ phishing campaign: What MSPs need to know right now        | 1.h      |
| Threats    | Storm-2372 conducts device code phishing campaign                                | 1.a      |
| Threats    | Microsoft 365 Device Code Phishing Campaign Bypasses Password Theft ...          | 1.e      |
| Threats    | Device Code Phishing Drives Identity Takeover Risks                              | 1.e      |
| Threats    | CVE-2026-104384                                                                  | 1.b      |
| Threats    | CVE-2026-101034                                                                  | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Unmasking EvilTokens: Getting to the root of device code phishing](https://aka.ms/EvilTokens-PhaaS)**

**PIR: 1.e**

Source: ketch Published: 2026-10-28

This report dissects the EvilTokens campaign, revealing how threat actors exploit Microsoft’s device code authorization flow to bypass traditional MFA. By analyzing the underlying PhaaS infrastructure, defenders gain actionable insights into detecting and blocking device code phishing at the network and identity layers. Essential for teams managing cloud identity platforms.

___________________________________


# **[Breaking the code: Multi-stage ‘code of conduct’ phishing campaign leads to AiTM token compromise](https://microsoft.com/en-us/security/blog/2026/05/04/breaking-the-code-multi-stage-code-of-conduct-phishing-campaign-leads-to-aitm)**

**PIR: 1.d**

Source: ketch Published: 2026-10-28

A detailed breakdown of a multi-stage phishing operation leveraging fake corporate compliance portals to harvest live authentication tokens. The campaign demonstrates how attackers chain social engineering with Adversary-in-the-Middle proxies to defeat step-up authentication. Infrastructure defenders can use the provided IOCs and detection logic to harden identity gateways.

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.e**

Source: ketch Published: 2026-10-28

Proofpoint analyzes the rapid proliferation of device code phishing, linking the surge to open-source criminal toolkits and PhaaS platforms. The report details how attackers manipulate OAuth consent flows to silently acquire valid tokens, effectively neutralizing MFA. Defenders are advised to implement conditional access policies, monitor for unusual device code requests, and deploy token revocation workflows.

___________________________________


# **[Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.g**

Source: ketch Published: 2026-10-28

Microsoft Threat Intelligence reveals how AI automation is scaling device code phishing operations. Attackers use generative AI to craft highly contextual lures and automate token harvesting in real time, significantly increasing compromise rates. The post provides detection signatures for AI-driven phishing infrastructure and recommends identity-centric controls to limit lateral movement post-compromise.

___________________________________


# **[The ‘code of conduct’ phishing campaign: What MSPs need to know right now](https://blog.barracuda.com/2026/05/07/code-of-conduct-phishing-campaign-msp-response)**

**PIR: 1.h**

Source: ketch Published: 2026-10-28

This advisory outlines how managed service providers are being specifically targeted by the ‘code of conduct’ phishing wave. Attackers exploit MSP trust relationships and delegated admin access to pivot across multiple client environments. The article provides mitigation strategies for MSPs and enterprise IT teams to restrict delegated permissions and monitor anomalous admin activity.

___________________________________


# **[Storm-2372 conducts device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/)**

**PIR: 1.a**

Source: ketch Published: 2026-10-28

Tracking the Storm-2372 threat actor, this report documents a persistent device code phishing campaign mimicking popular messaging platforms. The group targets enterprise users with realistic lures to capture OAuth tokens. Infrastructure teams can leverage the shared TTPs and network indicators to update proxy filters, block malicious authorization endpoints, and enforce stricter consent policies.

___________________________________


# **[Microsoft 365 Device Code Phishing Campaign Bypasses Password Theft ...](https://cybersecuritynews.com/microsoft-365-device-code-phishing-campaign/)**

**PIR: 1.e**

Source: ketch Published: 2026-10-28

ReversingLabs researchers document a sophisticated campaign that leverages Microsoft 365’s device authorization grant to bypass traditional credential theft. By combining polished phishing kits with legitimate OAuth flows, attackers achieve near-invisible account takeovers. The analysis highlights critical detection gaps and offers practical steps for securing identity providers against consent-based abuse.

___________________________________


# **[Device Code Phishing Drives Identity Takeover Risks](https://gurucul.com/latest-threats/device-code-phishing-is-an-evolution-in-identity-takeover/)**

**PIR: 1.e**

Source: ketch Published: 2026-10-28

This threat intelligence brief examines how device code phishing has become a primary vector for enterprise identity takeover. Attackers exploit corporate validation workflows to circumvent MFA controls, targeting high-value accounts. The report emphasizes the need for continuous identity monitoring, automated token lifecycle management, and user awareness training focused on OAuth consent prompts.

___________________________________


# **[CVE-2026-104384](https://nvd.nist.gov/vuln/detail/CVE-2026-104384)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-28

Insufficiently Protected Credentials in tunnel gateway and provisioning interfaces in EagleCloud Aquila versions through 2.6.7.2 on on-premises platforms allows unauthenticated remote attackers to escalate privileges via authentication abuse to access the access keys, secret keys, and deployment secrets

___________________________________


# **[CVE-2026-101034](https://nvd.nist.gov/vuln/detail/CVE-2026-101034)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-27

An attacker who obtained the hardcoded key could decrypt domain/service account passwords, task run-as credentials, and sysprep passwords stored in or transmitted by GSS Deployment Server installation.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2025-14260 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2025-14260)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-28

Unauthenticated SSRF in WSO2 middleware directly impacts Digital Identity and Finance sectors by compromising SSO gateways, open banking APIs, and government citizen portals.

*Deep dive: `TIER_2_CVE-2025-14260.md`*

___________________________________


# **[CVE-2026-104383 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-104383)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-28

Critical code injection in an enterprise MFA/IAM platform enables container root RCE, directly threatening digital identity infrastructure and zero-trust access controls across government, finance, and healthcare.

*Deep dive: `TIER_2_CVE-2026-104383.md`*

___________________________________


# **[CVE-2026-118669 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-118669)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-28

TIER 2 authorization bypass in Python oauthlib enables privilege escalation in OAuth2/OIDC token endpoints, directly impacting Digital Identity infrastructure and public/enterprise identity federation.

*Deep dive: `TIER_2_CVE-2026-118669.md`*

___________________________________


# **[CVE-2026-59185 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-59185)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-28

Cross-tenant IDOR in a machine identity/OIDC platform breaks multi-tenant authorization boundaries, directly impacting Digital Identity infrastructure.

*Deep dive: `TIER_2_CVE-2026-59185.md`*

___________________________________


# **[CVE-2026-59979 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-59979)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-28

Healthcare sector: missing authorization in FHIR-based clinical service and task management APIs enables cross-tenant data manipulation and disrupts national digital health booking/billing workflows.

*Deep dive: `TIER_2_CVE-2026-59979.md`*

___________________________________


# **[CVE-2026-118264 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-118264)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-28

Critical authentication bypass in the Echo Go framework directly impacts Digital Identity infrastructure, allowing attackers to circumvent IAM, OAuth/OIDC, and session validation middleware in public-facing services.

*Deep dive: `TIER_2_CVE-2026-118264.md`*

___________________________________


# **[CVE-2026-118377 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-118377)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-28

Finance sector: bypasses cryptographic verification in public-facing payment gateway callbacks, enabling unauthenticated order completion without actual fund transfer.

*Deep dive: `TIER_2_CVE-2026-118377.md`*

___________________________________


# **[CVE-2026-118665 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-118665)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-28

TIER 2 authentication bypass in a GraphQL gateway library that retains session tokens across connections, directly impacting the Digital Identity sector and API security in regulated/public services.

*Deep dive: `TIER_2_CVE-2026-118665.md`*

___________________________________


# **[CVE-2026-76418 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-76418)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-28

Critical general infrastructure vulnerability affecting Cisco ASA/FTD VPN gateways that secure Government, Finance, and Healthcare network perimeters, with confirmed in-wild exploitation causing service disruption.

*Deep dive: `TIER_2_CVE-2026-76418.md`*

___________________________________


# **[CVE-2026-84725 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-84725)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-28

Foundational enterprise Java middleware underpinning Government, Finance, and Healthcare digital services; requires patching despite non-default exploitation prerequisites.

*Deep dive: `TIER_2_CVE-2026-84725.md`*

___________________________________


# **[CVE-2026-86400 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-86400)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-28

Unauthenticated root RCE in Dell enterprise backup appliances threatens data integrity and recovery capabilities across Government, Finance, and Healthcare sectors.

*Deep dive: `TIER_2_CVE-2026-86400.md`*

___________________________________


# **[CVE-2026-103409 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-103409)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-28

Tier 2 SD-WAN edge router flaw grants unauthenticated root access during pre-onboarding, impacting government and critical infrastructure networking deployments.

*Deep dive: `TIER_2_CVE-2026-103409.md`*

___________________________________


# **[CVE-2026-104895 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-104895)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-28

Foundational Java backend library underpinning APIs across Finance, Healthcare, and Government; async parser DoS threatens service availability in regulated digital infrastructure.

*Deep dive: `TIER_2_CVE-2026-104895.md`*

___________________________________


# **[CVE-2026-110879 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-110879)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-28

Critical RCE in jackson-databind, a foundational Java serialization framework powering public-facing APIs and backend services across regulated and public-sector digital infrastructure.

*Deep dive: `TIER_2_CVE-2026-110879.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine