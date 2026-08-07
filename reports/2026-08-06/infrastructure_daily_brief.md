# **Infrastructure Daily Brief: 2026-08-06**

**Infrastructure Daily Report TLP:GREEN Alert Id: d33cfe1a 2026-08-07 14:25:26**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2025-15039 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-48088 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-50481 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-5430 (Tier 2)                                                           | 3.k      |
| Cyber News | CVE-2026-59115 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-61466 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-62873 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-63687 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-45414 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-48080 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-48081 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-48084 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-48085 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-48086 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-48087 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-62918 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-65583 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-65667 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-65668 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-68823 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-70332 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-50515 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-62896 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-63508 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-67261 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-70646 (Tier 2)                                                          | 3.k      |
| Threats    | The Device Code Phishing Tsunami: What We’re Seeing in the Wild                  | 1.b      |
| Threats    | The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations         | 1.d      |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US        | 1.b      |
| Threats    | Device Code Phishing — The Attack That Makes MFA Irrelevant                      | 1.b      |
| Threats    | Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA      | 1.c      |
| Threats    | The Illicit Consent Grant Part 2: Device-Code Phishing and the AI PhaaS Wave | S | 1.f      |
| Threats    | Tycoon2FA Returns: PhaaS Platform Survives Law Enforcement Disruption            | 1.e      |
| Threats    | Three Active Microsoft 365 Phishing Campaigns Targeting Schools and Government A | 1.a      |
| Threats    | CVE-2026-15572                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[The Device Code Phishing Tsunami: What We’re Seeing in the Wild](https://www.levelblue.com/blogs/spiderlabs-blog/the-device-code-phishing-tsunami-what-were-seeing-in-the-wild)**

**PIR: 1.b**

Source: ketch Published: 2026-08-06

Device code phishing has surged as attackers exploit OAuth 2.0 device authorization flows to bypass multi-factor authentication. Victims are tricked into entering short alphanumeric codes on malicious sites, granting attackers direct access to corporate accounts without passwords or MFA prompts. Defenders must monitor for anomalous device code grant requests, restrict OAuth app registrations, and educate users on recognizing device flow prompts. Network visibility into authentication traffic is 

___________________________________


# **[The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations](https://itsecurityguru.org/2026/05/27/the-ai-phishing-revolution-from-spray-and-pray-to-autonomous-operations)**

**PIR: 1.d**

Source: ketch Published: 2026-08-06

Generative AI has transformed phishing from broad, low-success campaigns into highly targeted, autonomous operations. Attackers now use LLMs to craft context-aware emails, dynamically generate landing pages, and automate follow-up sequences based on victim behavior. For infrastructure defenders, this means traditional signature-based email filtering is insufficient. Defenses must shift toward behavioral analytics, AI-driven email authentication validation, and continuous user training to detect 

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.b**

Source: ketch Published: 2026-08-06

This analysis details how device code phishing has evolved from niche exploits to a primary identity takeover vector. Attackers now automate the generation of fake device code portals that mirror legitimate SSO providers, capturing tokens in real-time. IT infrastructure teams should implement OAuth monitoring, enforce app consent policies, and deploy identity threat detection solutions that flag unusual device flow activity. Proactive configuration of identity providers remains the most effectiv

___________________________________


# **[Device Code Phishing — The Attack That Makes MFA Irrelevant](https://cybergrind.org/blog/2026-06-02-device-code-phishing)**

**PIR: 1.b**

Source: ketch Published: 2026-08-06

By leveraging the device authorization grant, threat actors completely circumvent traditional MFA mechanisms, rendering passwordless and hardware key protections ineffective if users are socially engineered. This article outlines detection strategies for infrastructure defenders, including logging OAuth token issuance, analyzing user-agent strings for automation, and implementing step-up authentication for sensitive actions. Securing the identity perimeter now requires shifting focus from authen

___________________________________


# **[Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA](https://www.cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns/)**

**PIR: 1.c**

Source: ketch Published: 2026-08-06

Attackers increasingly leverage cloud-native services like serverless functions, object storage, and managed DNS to host phishing pages and credential harvesters. This infrastructure abuse bypasses traditional IP-based blocklists and complicates takedown efforts. IT defenders must monitor cloud provider APIs, implement strict egress controls, and deploy cloud workload protection platforms to detect anomalous resource provisioning. Understanding these tactics is critical for securing hybrid envir

___________________________________


# **[The Illicit Consent Grant Part 2: Device-Code Phishing and the AI PhaaS Wave | SlashID Blog](https://slashid.com/blog/illicit-consent-grant-part-2)**

**PIR: 1.f**

Source: ketch Published: 2026-08-06

Combining illicit consent grants with device-code phishing and AI-driven PhaaS platforms, attackers are orchestrating highly scalable identity compromises. This report examines how malicious apps request excessive permissions while using AI to personalize phishing prompts. Defenders must audit registered enterprise applications, enforce least-privilege consent policies, and deploy machine learning models to detect anomalous OAuth flows. Integrating identity telemetry with cloud security posture 

___________________________________


# **[Tycoon2FA Returns: PhaaS Platform Survives Law Enforcement Disruption](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/03/CSA_research_note_Tycoon2FA-PhaaS-resurrection-MaaS-resilience-20260326-csa-styled.pdf)**

**PIR: 1.e**

Source: ketch Published: 2026-08-06

Despite coordinated law enforcement takedowns, the Tycoon2FA Phishing-as-a-Service platform has rapidly re-emerged using decentralized hosting and modular codebases. This resilience highlights the operational maturity of cybercriminal ecosystems. Infrastructure teams should prioritize threat intelligence sharing, monitor for known PhaaS branding and infrastructure patterns, and enforce strict conditional access policies. Detecting PhaaS indicators early can prevent large-scale credential harvest

___________________________________


# **[Three Active Microsoft 365 Phishing Campaigns Targeting Schools and Government Agencies](https://forsyteit.com/three-active-microsoft-365-phishing-campaigns-targeting-schools-and-government-agencies)**

**PIR: 1.a**

Source: ketch Published: 2026-08-06

Recent campaigns exploit Microsoft 365 login pages and calendar invitation templates to harvest credentials from educational and public sector networks. Attackers leverage trusted Microsoft domains and spoofed internal senders to increase click-through rates. Infrastructure defenders should validate SPF/DKIM/DMARC records, monitor for suspicious OAuth token requests, and enforce multi-factor authentication with phishing-resistant methods. Regular log analysis of Azure AD sign-ins can reveal earl

___________________________________


# **[CVE-2026-15572](https://nvd.nist.gov/vuln/detail/CVE-2026-15572)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-05

A flaw was found in Keycloak's Dynamic Client Registration (DCR) security policy management. The "Allowed Protocol Mapper Types" policy, which restricts which types of data mappers a client can use, fails to re-validate the mapper type during a client update if the mapper's configuration remains unchanged. An attacker with client registration privileges can exploit this by first registering an allowed mapper type with a malicious configuration and then swapping it for a restricted, high-privileg

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2025-15039 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2025-15039)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-06

Authentication bypass in WSO2 Identity Server enables account takeover, directly impacting digital identity, open banking, and government citizen service platforms.

*Deep dive: `TIER_2_CVE-2025-15039.md`*

___________________________________


# **[CVE-2026-48088 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-48088)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-06

Healthcare sector: Unauthenticated cryptographic bypass in a public-facing medical appointment SaaS breaks end-to-end encryption and exposes sensitive patient health data.

*Deep dive: `TIER_2_CVE-2026-48088.md`*

___________________________________


# **[CVE-2026-50481 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-50481)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-06

Critical privilege escalation in Azure AD impacts core Digital Identity infrastructure and enterprise access control.

*Deep dive: `TIER_2_CVE-2026-50481.md`*

___________________________________


# **[CVE-2026-5430 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-5430)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-06

Critical JWT authentication bypass in widely deployed API gateways directly compromises digital identity, government citizen services, and financial transaction APIs.

*Deep dive: `TIER_2_CVE-2026-5430.md`*

___________________________________


# **[CVE-2026-59115 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-59115)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-06

Critical path traversal in Microsoft Entra Provisioning Service compromises hybrid identity synchronization, directly impacting authentication and authorization for government and enterprise Digital Identity infrastructure.

*Deep dive: `TIER_2_CVE-2026-59115.md`*

___________________________________


# **[CVE-2026-61466 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-61466)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-06

Compromises OAuth2 authorization servers, a foundational Digital Identity component, by allowing attackers to self-assign privileged scopes and bypass access controls.

*Deep dive: `TIER_2_CVE-2026-61466.md`*

___________________________________


# **[CVE-2026-62873 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-62873)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-06

Critical privilege escalation in Microsoft 365 Admin Center compromises core cloud identity and access management controls, directly impacting Digital Identity infrastructure.

*Deep dive: `TIER_2_CVE-2026-62873.md`*

___________________________________


# **[CVE-2026-63687 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-63687)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-06

Directly compromises OAuth/OIDC PKCE and replay protections in Apache CXF, impacting foundational Digital Identity and federated authentication infrastructure.

*Deep dive: `TIER_2_CVE-2026-63687.md`*

___________________________________


# **[CVE-2026-45414 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-45414)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-06

Cross-tenant JWT bypass in Decidim participatory democracy framework exposes citizen data and proposal integrity across government deployments.

*Deep dive: `TIER_2_CVE-2026-45414.md`*

___________________________________


# **[CVE-2026-48080 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-48080)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-06

Healthcare sector: clinic appointment booking SaaS leaks plaintext DB credentials, breaking multi-tenant isolation and exposing patient data.

*Deep dive: `TIER_2_CVE-2026-48080.md`*

___________________________________


# **[CVE-2026-48081 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-48081)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-06

Healthcare sector: stored XSS in patient-facing appointment booking software compromises sensitive medical scheduling data and PINs before client-side encryption.

*Deep dive: `TIER_2_CVE-2026-48081.md`*

___________________________________


# **[CVE-2026-48084 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-48084)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-06

Healthcare sector relevance due to public-facing appointment booking platform exposing patient records and admin accounts to brute-force attacks.

*Deep dive: `TIER_2_CVE-2026-48084.md`*

___________________________________


# **[CVE-2026-48085 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-48085)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-06

Directly impacts healthcare operational infrastructure by allowing unauthenticated admin takeover of patient appointment scheduling systems used by medical practices.

*Deep dive: `TIER_2_CVE-2026-48085.md`*

___________________________________


# **[CVE-2026-48086 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-48086)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-06

Matches Healthcare sector; privilege escalation in a SaaS appointment platform used by medical practices exposes clinical practice management data and staff records.

*Deep dive: `TIER_2_CVE-2026-48086.md`*

___________________________________


# **[CVE-2026-48087 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-48087)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-06

Critical WebAuthn passkey bypass in public-facing healthcare appointment SaaS enables full account takeover, directly impacting Healthcare workflows and Digital Identity security.

*Deep dive: `TIER_2_CVE-2026-48087.md`*

___________________________________


# **[CVE-2026-62918 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-62918)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-06

Identity spoofing in Microsoft Teams impacts Government and Finance collaboration infrastructure by undermining trust signals and enabling social engineering in regulated environments.

*Deep dive: `TIER_2_CVE-2026-62918.md`*

___________________________________


# **[CVE-2026-65583 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-65583)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-06

Directly impacts OIDC token validation in Apache CXF, a foundational component for enterprise federated authentication and digital identity infrastructure.

*Deep dive: `TIER_2_CVE-2026-65583.md`*

___________________________________


# **[CVE-2026-65667 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-65667)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-06

Critical missing authorization flaw in Microsoft Teams, a widely deployed collaboration platform explicitly tied to Government, Finance, and Healthcare operations.

*Deep dive: `TIER_2_CVE-2026-65667.md`*

___________________________________


# **[CVE-2026-65668 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-65668)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-06

Privilege escalation in Microsoft Purview eDiscovery impacts Government, Finance, and Healthcare compliance workflows handling regulated legal and audit data.

*Deep dive: `TIER_2_CVE-2026-65668.md`*

___________________________________


# **[CVE-2026-68823 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-68823)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-06

Foundational cloud audit/compliance infrastructure (Azure Confidential Ledger) with RCE risk impacting Finance, Government, and Healthcare regulatory reporting and data integrity.

*Deep dive: `TIER_2_CVE-2026-68823.md`*

___________________________________


# **[CVE-2026-70332 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-70332)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-06

Unauthenticated SSRF in Microsoft SharePoint Online, a foundational collaboration platform widely deployed across Government, Finance, and Healthcare digital operations.

*Deep dive: `TIER_2_CVE-2026-70332.md`*

___________________________________


# **[CVE-2026-50515 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-50515)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-06

Foundational cloud messaging infrastructure explicitly tied to public-sector workloads, requiring strict identity governance and private endpoints to secure government digital services.

*Deep dive: `TIER_2_CVE-2026-50515.md`*

___________________________________


# **[CVE-2026-62896 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-62896)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-06

General infrastructure relevance: Microsoft Teams is a foundational collaboration platform widely deployed in government and regulated enterprise environments, where privilege escalation impacts secure communications and administrative controls.

*Deep dive: `TIER_2_CVE-2026-62896.md`*

___________________________________


# **[CVE-2026-63508 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-63508)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-06

Government / General Infrastructure: Unauthenticated privilege escalation in a default-public Azure geospatial PaaS service supporting civic and public-sector data platforms.

*Deep dive: `TIER_2_CVE-2026-63508.md`*

___________________________________


# **[CVE-2026-67261 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-67261)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-06

Unauthenticated RCE in VMware vCenter storage plugin compromises foundational virtualization infrastructure hosting government, finance, and healthcare DPI workloads.

*Deep dive: `TIER_2_CVE-2026-67261.md`*

___________________________________


# **[CVE-2026-70646 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-70646)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-06

Targets public-facing cryptocurrency payment webhooks, risking denial-of-service that disrupts digital transaction processing and fintech infrastructure availability.

*Deep dive: `TIER_2_CVE-2026-70646.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine