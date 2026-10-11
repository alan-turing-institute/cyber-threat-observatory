# **Infrastructure Daily Brief: 2026-10-10**

**Infrastructure Daily Report TLP:GREEN Alert Id: e52bd24c 2026-10-11 03:28:54**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-104759 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-106608 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-96765 (Tier 2)                                                          | 3.k      |
| Threats    | Inside an AI‑enabled device code phishing campaign | Microsoft Security Blog     | 1.f      |
| Threats    | Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA      | 1.g      |
| Threats    | Fake IT Help Desk Phishing Campaign Hits Blackstone, Bridgewater, KKR: Detecting | 1.a      |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US        | 1.f      |
| Threats    | n8n Weaponized for Phishing and Device Fingerprinting                            | 1.h      |
| Threats    | SideWinder APT Credential Harvesting Campaign — PaaS Platform Abuse at Scale     | 1.g      |
| Threats    | We Need to Talk About Device Code Phishing | Huntress                            | 1.f      |
| Threats    | Three Active Microsoft 365 Phishing Campaigns Targeting Schools and Government A | 1.b      |
| Threats    | CVE-2026-78025                                                                   | 1.b      |
| Threats    | CVE-2026-108108                                                                  | 1.b      |
| Threats    | CVE-2026-107889                                                                  | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Inside an AI‑enabled device code phishing campaign | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.f**

Source: ketch Published: 2026-10-10

Microsoft researchers detail a sophisticated campaign combining AI-generated landing pages with OAuth device code flows to bypass traditional email security. The post explains how attackers automate victim interaction and token exchange, providing defenders with telemetry data, detection queries for Microsoft 365 Defender, and guidance on restricting device code authorization scopes.

___________________________________


# **[Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA](https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns)**

**PIR: 1.g**

Source: ketch Published: 2026-10-10

Threat actors increasingly leverage cloud-native services like serverless functions, object storage, and CDN networks to host phishing infrastructure. This report details how attackers bypass traditional domain reputation filters by utilizing legitimate cloud providers, offering defenders actionable detection strategies for cloud-hosted credential harvesting sites and infrastructure abuse patterns.

___________________________________


# **[Fake IT Help Desk Phishing Campaign Hits Blackstone, Bridgewater, KKR: Detecting and Defeating MFA Credential Theft](https://securityarsenal.com/blog/fake-it-help-desk-phishing-campaign-hits-blackstone-bridgewater-kkr-detecting-and-defeating-mfa-credential-theft)**

**PIR: 1.a**

Source: ketch Published: 2026-10-10

A highly targeted campaign impersonating internal IT support teams successfully harvested MFA credentials from major financial firms. The article breaks down the social engineering tactics, proxy server configurations used to bypass MFA, and provides infrastructure defenders with specific email header indicators, URL patterns, and conditional access policy recommendations to mitigate similar attacks.

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.f**

Source: ketch Published: 2026-10-10

This threat insight explores how device code phishing has matured into a primary vector for identity takeover, exploiting legitimate OAuth mechanisms to steal valid access tokens. The report outlines campaign trends, technical indicators of compromise, and defensive controls including monitoring for suspicious device code requests and implementing stricter consent policies.

___________________________________


# **[n8n Weaponized for Phishing and Device Fingerprinting](https://labs.cloudsecurityalliance.org/research/csa-research-note-n8n-ai-workflow-phishing-20260416-csa-styl)**

**PIR: 1.h**

Source: ketch Published: 2026-10-10

Open-source workflow automation tools like n8n are being repurposed by threat groups to orchestrate large-scale phishing operations and collect detailed device fingerprints. This analysis covers the technical architecture of these automated campaigns, highlighting how defenders can monitor for anomalous workflow executions and block fingerprinting endpoints in proxy and DNS logs.

___________________________________


# **[SideWinder APT Credential Harvesting Campaign — PaaS Platform Abuse at Scale](https://intel.breakglass.tech/post/sidewinder-mhil-zeabur)**

**PIR: 1.g**

Source: ketch Published: 2026-10-10

The SideWinder APT group is abusing Platform-as-a-Service (PaaS) environments to deploy scalable credential harvesting infrastructure. This technical breakdown reveals how attackers automate phishing site deployment, evade takedown requests, and harvest enterprise credentials. Defenders gain visibility into PaaS abuse patterns and network-level blocking strategies.

___________________________________


# **[We Need to Talk About Device Code Phishing | Huntress](https://www.huntress.com/blog/tradecraft-tuesday-device-code-phishing-explained)**

**PIR: 1.f**

Source: ketch Published: 2026-10-10

Huntress provides a comprehensive primer on device code phishing, explaining the underlying OAuth mechanics that make it effective against modern identity stacks. The article offers practical detection methods for SIEM and EDR platforms, emphasizes the importance of user training, and outlines architectural changes to reduce attack surface exposure.

___________________________________


# **[Three Active Microsoft 365 Phishing Campaigns Targeting Schools and Government Agencies](https://forsyteit.com/three-active-microsoft-365-phishing-campaigns-targeting-schools-and-government-agencies)**

**PIR: 1.b**

Source: ketch Published: 2026-10-10

This report catalogs three concurrent phishing campaigns specifically engineered to compromise Microsoft 365 accounts in educational and public sector environments. It details the malicious payloads, credential harvesting techniques, and provides infrastructure defenders with actionable IOCs, email filtering rules, and M365 security posture recommendations.

___________________________________


# **[CVE-2026-78025](https://nvd.nist.gov/vuln/detail/CVE-2026-78025)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-09

Dell Secure Connect Gateway (SCG) Policy Manager, versions prior to 5.34.00.16, contains a Missing Authentication for Critical Function vulnerability. An unauthenticated attacker with remote access could potentially exploit this vulnerability, leading to Information disclosure, Protection mechanism bypass, and Unauthorized access.

___________________________________


# **[CVE-2026-108108](https://nvd.nist.gov/vuln/detail/CVE-2026-108108)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-09

PHPNuxBill through 2025.3.20 contains an authentication bypass vulnerability in RADIUS CHAP verification because Password::chap_verify() returns true when the supplied response does not match. Attackers who know a valid customer or PPPoE username can log in through MikroTik hotspot or PPPoE CHAP with any incorrect password to obtain network access and consume that customer's plan.

___________________________________


# **[CVE-2026-107889](https://nvd.nist.gov/vuln/detail/CVE-2026-107889)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-09

A flaw was found in the login theme rendering component of Keycloak. The issue occurs because the security filter responsible for cleaning user input can be bypassed, allowing a realm administrator to store malicious scripts in display fields. This could result in unauthorized JavaScript execution in the browsers of users visiting the login page, potentially leading to data exposure or session interference.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-104759 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-104759)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-10

Authentication bypass in a widely deployed WordPress OIDC/SSO plugin enables full account takeover, directly impacting Digital Identity and access control infrastructure.

*Deep dive: `TIER_2_CVE-2026-104759.md`*

___________________________________


# **[CVE-2026-106608 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-106608)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-10

Finance sector relevance: authenticated privilege escalation in WooCommerce enables full admin takeover, risking payment data, customer accounts, and transaction integrity.

*Deep dive: `TIER_2_CVE-2026-106608.md`*

___________________________________


# **[CVE-2026-96765 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-96765)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-10

Unauthenticated stored XSS in an enterprise SSO/OIDC plugin risks admin session hijacking and credential theft in Digital Identity workflows.

*Deep dive: `TIER_2_CVE-2026-96765.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine