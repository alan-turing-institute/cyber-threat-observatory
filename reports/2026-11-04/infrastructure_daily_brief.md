# **Infrastructure Daily Brief: 2026-11-04**

**Infrastructure Daily Report TLP:GREEN Alert Id: 9c0a1682 2026-11-05 12:35:38**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-111036 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-114425 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-115770 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-11749 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-121639 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-121802 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-62662 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-114421 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-118513 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-121956 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-121966 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-121971 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-54381 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-82029 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-122019 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-54378 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-54383 (Tier 2)                                                          | 3.k      |
| Threats    | The hidden network: Inside the phishing infrastructure ecosystem powering global | 1.a      |
| Threats    | Inside Wazza: A Newly Observed Device Code Phishing Kit Targeting Microsoft 365  | 1.e      |
| Threats    | Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Se | 1.e      |
| Threats    | Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA      | 1.f      |
| Threats    | Inside an AI‑enabled device code phishing campaign | Microsoft Security Blog     | 1.g      |
| Threats    | Microsoft 365 device code phishing campaign bypasses password stealing | RL Blog | 1.e      |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US        | 1.e      |
| Threats    | Pro-Russian hackers pose as Ukraine's cyber agency to target government, busines | 1.j.3    |
| Threats    | CVE-2026-118527                                                                  | 3.k      |
| Threats    | CVE-2026-113373                                                                  | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime/)**

**PIR: 1.a**

Source: ketch Published: 2026-11-04

Microsoft researchers dissect the sprawling phishing infrastructure ecosystem fueling global cybercrime. The report details how threat actors leverage compromised domains, bulletproof hosting, and automated domain generation algorithms to evade takedowns. Infrastructure defenders gain actionable IOCs, architectural breakdowns of phishing-as-a-service platforms, and mitigation strategies for DNS sinkholing and certificate transparency monitoring.

___________________________________


# **[Inside Wazza: A Newly Observed Device Code Phishing Kit Targeting Microsoft 365 Accounts](https://www.levelblue.com/blogs/spiderlabs-blog/inside-wazza-a-newly-observed-device-code-phishing-kit-targeting-microsoft-365-accounts)**

**PIR: 1.e**

Source: ketch Published: 2026-11-04

Level Blue analyzes the Wazza phishing kit, a newly observed tool exploiting Microsoft 365 device code authorization flows. The kit bypasses traditional MFA by prompting users to approve sign-ins on secondary devices. The report provides technical breakdowns of the kit’s deployment mechanisms, proxy infrastructure, and detection signatures for SIEM and email security gateways.

___________________________________


# **[Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/)**

**PIR: 1.e**

Source: ketch Published: 2026-11-04

Microsoft Security researchers expose EvilTokens, a sophisticated device code phishing operation targeting enterprise identity providers. The campaign uses custom proxy servers to intercept authorization codes and issue valid OAuth tokens. Defenders receive guidance on monitoring conditional access policies, detecting token theft patterns, and implementing phishing-resistant MFA.

___________________________________


# **[Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA](https://www.cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns/)**

**PIR: 1.f**

Source: ketch Published: 2026-11-04

CYFIRMA examines how modern phishing campaigns abuse cloud-native services like serverless functions, object storage, and CDN providers to host malicious payloads and landing pages. The analysis highlights evasion techniques, cost-effective infrastructure scaling, and defensive recommendations for cloud workload protection and traffic anomaly detection.

___________________________________


# **[Inside an AI‑enabled device code phishing campaign | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.g**

Source: ketch Published: 2026-11-04

Microsoft details an AI-driven phishing campaign that dynamically generates realistic login pages and contextual prompts to trick users into authorizing device code sign-ins. The report covers LLM-assisted content generation, infrastructure pivoting, and identity protection controls to block suspicious consent grants and anomalous device approvals.

___________________________________


# **[Microsoft 365 device code phishing campaign bypasses password stealing | RL Blog](https://www.reversinglabs.com/blog/device-code-phishing-campaign)**

**PIR: 1.e**

Source: ketch Published: 2026-11-04

ReversingLabs investigates a targeted campaign exploiting Microsoft 365 device code flows to circumvent password-based security controls. The report details the attack chain, infrastructure hosting on legitimate cloud platforms, and mitigation strategies including conditional access restrictions, user training, and real-time identity threat monitoring.

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.e**

Source: ketch Published: 2026-11-04

Proofpoint explores how device code phishing has matured from a niche tactic to a primary identity takeover vector. The article outlines campaign lifecycles, infrastructure reuse patterns, and behavioral indicators. It provides actionable detection rules for email filters, identity governance platforms, and network telemetry to disrupt credential harvesting pipelines.

___________________________________


# **[Pro-Russian hackers pose as Ukraine's cyber agency to target government, businesses | The Record from Recorded Future News](https://therecord.media/pro-russian-hackers-posing-as-ukrainian-cyber-agency)**

**PIR: 1.j.3**

Source: ketch Published: 2026-11-04

Recorded Future tracks a geopolitical spear-phishing operation where threat actors impersonate Ukraine’s cyber agency to target government and business entities. The campaign leverages tailored lures, compromised credentials, and infrastructure mimicking official domains. Defenders gain insights into attribution indicators, domain reputation analysis, and email authentication hardening.

___________________________________


# **[CVE-2026-118527](https://nvd.nist.gov/vuln/detail/CVE-2026-118527)**

**PIR: 3.k**

Source: vulners/duckdb Published: 2026-11-03

Use of predictable filenames in Ivanti Connect Secure before versions 25.1.1.3 and 22.8R2.6 allows a remote authenticated attacker to upload files with attacker-controlled content to a known location on disk.

___________________________________


# **[CVE-2026-113373](https://nvd.nist.gov/vuln/detail/CVE-2026-113373)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-04

Sonatype Nexus Repository 3 Pro does not check the local account status when a user signs in through a configured SAML or OAuth2/OpenID Connect identity provider. A user whose account was disabled or locked by an administrator in Nexus Repository can sign in again with valid identity provider credentials for the same account, and then receives a new session with the roles of that account. The attacker needs no Nexus Repository session and no Nexus Repository privilege. The attacker needs a named

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-111036 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-111036)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-04

SSRF in Coupa Supplier Portal SaaS impacts Finance and Government sectors via procurement and spend management workflows.

*Deep dive: `TIER_2_CVE-2026-111036.md`*

___________________________________


# **[CVE-2026-114425 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-114425)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-04

Unauthenticated root file manipulation on public-facing secure email gateways widely deployed in government, healthcare, and finance sectors for compliant communications.

*Deep dive: `TIER_2_CVE-2026-114425.md`*

___________________________________


# **[CVE-2026-115770 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-115770)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-04

Core OIDC/OAuth identity provider flaw enabling email verification forgery and cross-application account takeover, directly impacting Digital Identity infrastructure.

*Deep dive: `TIER_2_CVE-2026-115770.md`*

___________________________________


# **[CVE-2026-11749 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-11749)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-04

Directly impacts SAML-based identity federation and session integrity, a core component of enterprise and government Digital Identity infrastructure.

*Deep dive: `TIER_2_CVE-2026-11749.md`*

___________________________________


# **[CVE-2026-121639 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-121639)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-04

Directly impacts enterprise and public-sector identity infrastructure by allowing unauthenticated disruption of SSO/VPN authentication and LDAP/Active Directory synchronization.

*Deep dive: `TIER_2_CVE-2026-121639.md`*

___________________________________


# **[CVE-2026-121802 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-121802)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-04

Critical origin validation flaw in a widely used authentication framework enabling unauthenticated account takeover and session hijacking, directly impacting Digital Identity infrastructure.

*Deep dive: `TIER_2_CVE-2026-121802.md`*

___________________________________


# **[CVE-2026-62662 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-62662)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-04

Directly impacts the Digital Identity sector by enabling authorization bypass and JWT token forgery in self-hosted OIDC providers used for regulated service-to-service access.

*Deep dive: `TIER_2_CVE-2026-62662.md`*

___________________________________


# **[CVE-2026-114421 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-114421)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-04

Government sector: Dominant secure email gateway for German public administration; unauthenticated account takeover risks inter-agency communications and citizen services.

*Deep dive: `TIER_2_CVE-2026-114421.md`*

___________________________________


# **[CVE-2026-118513 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-118513)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-04

High-severity X509/mTLS authentication bypass in Symfony enables full identity spoofing, directly impacting digital identity verification in enterprise and public-sector portals.

*Deep dive: `TIER_2_CVE-2026-118513.md`*

___________________________________


# **[CVE-2026-121956 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-121956)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-04

Impacts Kerberos-based authentication in FreeRDP remote access gateways, directly affecting Digital Identity infrastructure across government, healthcare, and finance sectors.

*Deep dive: `TIER_2_CVE-2026-121956.md`*

___________________________________


# **[CVE-2026-121966 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-121966)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-04

TIER 2 authentication bypass in Traefik reverse proxy enables identity hijacking via NTLM/Negotiate ForwardAuth, directly impacting Digital Identity and foundational routing infrastructure.

*Deep dive: `TIER_2_CVE-2026-121966.md`*

___________________________________


# **[CVE-2026-121971 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-121971)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-04

Core PHP framework flaw risking credential leakage in authenticated outbound calls across Digital Identity, Healthcare, Finance, and Government web services.

*Deep dive: `TIER_2_CVE-2026-121971.md`*

___________________________________


# **[CVE-2026-54381 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-54381)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-04

Healthcare sector impact: unauthenticated cloud bucket exposure leaks ~129k user health profiles and clinical-adjacent metrics, threatening digital health infrastructure privacy and compliance.

*Deep dive: `TIER_2_CVE-2026-54381.md`*

___________________________________


# **[CVE-2026-82029 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-82029)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-04

Finance sector: Broken access control in Invoice Ninja allows authenticated vendor contacts to exfiltrate sensitive financial documents (invoices, contracts, receipts), impacting financial data confidentiality.

*Deep dive: `TIER_2_CVE-2026-82029.md`*

___________________________________


# **[CVE-2026-122019 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-122019)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-04

Unauthenticated social login bypass enables full account takeover and wallet drainage on a widely deployed e-commerce platform, impacting digital payment processing and consumer financial data.

*Deep dive: `TIER_2_CVE-2026-122019.md`*

___________________________________


# **[CVE-2026-54378 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-54378)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-04

Broken access control in a public-facing health tracking API enables cross-user leakage of personal health records, impacting healthcare data privacy and compliance.

*Deep dive: `TIER_2_CVE-2026-54378.md`*

___________________________________


# **[CVE-2026-54383 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-54383)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-04

TIER 2 Healthcare relevance: internet-facing API flaw exposes PII and sensitive health metrics, highlighting data privacy risks in consumer wellness and digital public health ecosystems.

*Deep dive: `TIER_2_CVE-2026-54383.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine