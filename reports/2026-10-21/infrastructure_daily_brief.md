# **Infrastructure Daily Brief: 2026-10-21**

**Infrastructure Daily Report TLP:GREEN Alert Id: ab341438 2026-10-22 23:53:04**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-103090 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-109618 (Tier 1)                                                         | 3.k      |
| Cyber News | CVE-2026-109619 (Tier 1)                                                         | 3.k      |
| Cyber News | CVE-2026-112212 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-91403 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-94300 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-111811 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-111814 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-111815 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-114045 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-114108 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-114123 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-89035 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-96888 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2025-55702 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-110803 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-111813 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-114106 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-114489 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-19630 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-76290 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-82819 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-96640 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-97206 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-114243 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-114245 (Tier 2)                                                         | 3.k      |
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.c      |
| Threats    | GhostCode attackers abuse device codes to take over Microsoft 365 accounts       | 1.b      |
| Threats    | Device Code Phishing: How EvilTokens Hit 12,000+ Inboxes                         | 1.b      |
| Threats    | SideWinder APT Credential Harvesting Campaign — PaaS Platform Abuse at Scale     | 1.f      |
| Threats    | Microsoft Teams Phishing via Fake IT Helpdesk Impersonation (External Chat, Vish | 1.e      |
| Threats    | Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA      | 1.a      |
| Threats    | As phishing-as-a-service goes industrial, Microsoft takes down a marketplace beh | 1.d      |
| Threats    | Capacity Enhancement Guide: Counter-Phishing Recommendations for Federal Agencie | 1.g      |
| Threats    | CVE-2026-87251                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Inside an AI‑enabled device code phishing campaign](https://microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026)**

**PIR: 1.c**

Source: ketch Published: 2026-10-21

Microsoft’s threat intelligence team details a sophisticated campaign leveraging generative AI to dynamically generate convincing device code phishing pages. Attackers use AI to adapt language, branding, and layout in real-time, evading static URL and content filters. The campaign targets enterprise users by exploiting the device code flow’s inherent trust model. Defenders must implement behavioral analytics for authentication endpoints, restrict device code usage to approved networks, and educa

___________________________________


# **[GhostCode attackers abuse device codes to take over Microsoft 365 accounts](https://computerworld.com/article/4223889/ghostcode-attackers-abuse-device-codes-to-take-over-microsoft-365-accounts.html)**

**PIR: 1.b**

Source: ketch Published: 2026-10-21

Threat actors behind the GhostCode campaign are exploiting Microsoft 365 device code authentication flows to bypass traditional email filters and multi-factor authentication. By directing users to malicious login portals that mimic Microsoft’s OAuth consent screens, attackers harvest valid access tokens for persistent account takeover. Infrastructure defenders should monitor for anomalous device code authorization requests, enforce conditional access policies that restrict token issuance, and de

___________________________________


# **[Device Code Phishing: How EvilTokens Hit 12,000+ Inboxes](https://ctiacademy.io/blog/device-code-phishing)**

**PIR: 1.b**

Source: ketch Published: 2026-10-21

The EvilTokens threat group has successfully compromised over 12,000 inboxes by weaponizing device code phishing techniques. By distributing malicious links via compromised accounts and spam campaigns, attackers trick users into entering device codes on fake Microsoft login pages. This grants threat actors long-lived access tokens, enabling lateral movement and data exfiltration. IT infrastructure teams should audit OAuth app permissions, implement token lifetime restrictions, and deploy identit

___________________________________


# **[SideWinder APT Credential Harvesting Campaign — PaaS Platform Abuse at Scale](https://intel.breakglass.tech/post/sidewinder-mhil-zeabur)**

**PIR: 1.f**

Source: ketch Published: 2026-10-21

The SideWinder APT group is leveraging Platform-as-a-Service environments to host credential harvesting infrastructure at scale, dynamically provisioning phishing sites and data exfiltration endpoints. By abusing legitimate PaaS APIs, attackers evade traditional perimeter defenses and maintain persistent access even after initial domains are blocked. Infrastructure teams should monitor for anomalous PaaS API usage, enforce strict egress filtering, and deploy identity-aware proxies to validate au

___________________________________


# **[Microsoft Teams Phishing via Fake IT Helpdesk Impersonation (External Chat, Vishing, Screen Sharing, RMM](https://intel.threadlinqs.com/threat/TL-2026-3778)**

**PIR: 1.e**

Source: ketch Published: 2026-10-21

Attackers are increasingly using Microsoft Teams to impersonate IT helpdesk personnel, combining external chat, vishing, and screen-sharing requests to harvest credentials and deploy remote monitoring tools. By exploiting trust in internal support channels, threat actors bypass email security controls entirely. Infrastructure defenders should enforce strict external messaging policies, disable unnecessary screen-sharing capabilities for guest users, and implement call recording or verification p

___________________________________


# **[Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA](https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns)**

**PIR: 1.a**

Source: ketch Published: 2026-10-21

Modern phishing operations are rapidly migrating to cloud-native platforms like serverless functions, object storage, and containerized environments to host malicious payloads and landing pages. This infrastructure abuse provides attackers with high availability, geographic distribution, and resilience against takedown efforts. Defenders must shift from static blocklists to behavioral monitoring of cloud resource deployments, implement DNS sinkholing for newly registered cloud domains, and integ

___________________________________


# **[As phishing-as-a-service goes industrial, Microsoft takes down a marketplace behind 1 billion messages](https://computerworld.com/article/4235537/as-phishing-as-a-service-goes-industrial-microsoft-takes-down-a-marketplace-behind-1-billion-messages-2.html)**

**PIR: 1.d**

Source: ketch Published: 2026-10-21

The industrialization of phishing-as-a-service has enabled threat actors to distribute over one billion malicious messages through automated marketplaces offering customizable templates, infrastructure hosting, and credential harvesting dashboards. Microsoft’s recent takedown operation disrupted a major hub, but the underlying ecosystem remains resilient. Infrastructure defenders must prioritize threat intelligence sharing, implement automated domain reputation scoring, and deploy machine learni

___________________________________


# **[Capacity Enhancement Guide: Counter-Phishing Recommendations for Federal Agencies](https://cisa.gov/sites/default/files/publications/Capacity_Enhancement_Guide-Counter-Phishing_Recommendations_for_Federal_Agencies.pdf)**

**PIR: 1.g**

Source: ketch Published: 2026-10-21

This CISA-published guide provides actionable counter-phishing strategies tailored for federal IT infrastructure, emphasizing zero-trust identity validation, automated takedown workflows, and continuous user awareness training. It outlines technical controls for email authentication enforcement, OAuth token lifecycle management, and incident response playbooks for credential compromise. Defenders should align their security architectures with these recommendations to harden identity perimeters a

___________________________________


# **[CVE-2026-87251](https://nvd.nist.gov/vuln/detail/CVE-2026-87251)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-20

Vulnerability in the Oracle Access Manager product of Oracle Fusion Middleware (component: Authentication Engine).  Supported versions that are affected are 12.2.1.4.0 and  14.1.2.1.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via SAML to compromise Oracle Access Manager.  Successful attacks of this vulnerability can result in takeover of Oracle Access Manager. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: 

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-103090 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-103090)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-21

Directly compromises Zero Trust identity infrastructure by enabling unauthenticated theft of Biscuit tokens and OIDC enrollment credentials, impacting Digital Identity management.

*Deep dive: `TIER_2_CVE-2026-103090.md`*

___________________________________


# **[CVE-2026-109618 (Tier 1)](https://nvd.nist.gov/vuln/detail/CVE-2026-109618)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-21

Foundational web runtime (PHP) with active wild exploitation underpins government, finance, healthcare, and digital identity services globally.

*Deep dive: `TIER_1_CVE-2026-109618.md`*

___________________________________


# **[CVE-2026-109619 (Tier 1)](https://nvd.nist.gov/vuln/detail/CVE-2026-109619)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-21

Foundational PHP runtime vulnerability enabling unauthenticated RCE across government portals, financial services, and identity management systems.

*Deep dive: `TIER_1_CVE-2026-109619.md`*

___________________________________


# **[CVE-2026-112212 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-112212)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-21

Directly compromises OAuth/OIDC discovery endpoints in GitLab, a widely deployed IdP for enterprise and government digital identity federation.

*Deep dive: `TIER_2_CVE-2026-112212.md`*

___________________________________


# **[CVE-2026-91403 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-91403)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-21

Foundational Java SE runtime flaw in TLS/SSL handling poses systemic risk to Finance, Government, Healthcare, and Digital Identity services globally.

*Deep dive: `TIER_2_CVE-2026-91403.md`*

___________________________________


# **[CVE-2026-94300 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-94300)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-21

Foundational DNS infrastructure (BIND 9) with RCE impacts availability and integrity across Government, Finance, Healthcare, and Digital Identity sectors.

*Deep dive: `TIER_2_CVE-2026-94300.md`*

___________________________________


# **[CVE-2026-111811 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-111811)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-21

Foundational CDN/reverse proxy infrastructure widely deployed across government and finance edge services; unauthenticated cache manipulation poses high impact if misconfigured.

*Deep dive: `TIER_2_CVE-2026-111811.md`*

___________________________________


# **[CVE-2026-111814 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-111814)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-21

Critical mTLS authentication bypass in Apache Traffic Server, a foundational API gateway widely deployed across Finance, Government, and Healthcare digital services.

*Deep dive: `TIER_2_CVE-2026-111814.md`*

___________________________________


# **[CVE-2026-111815 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-111815)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-21

Foundational edge proxy flaw impacting mTLS authentication across Digital Identity, Finance, Healthcare, and Government deployments.

*Deep dive: `TIER_2_CVE-2026-111815.md`*

___________________________________


# **[CVE-2026-114045 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-114045)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-21

Foundational remote desktop/VDI infrastructure (FreeRDP) with RCE impact, explicitly relevant to Government and General Infrastructure sectors for secure administrative access.

*Deep dive: `TIER_2_CVE-2026-114045.md`*

___________________________________


# **[CVE-2026-114108 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-114108)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-21

Finance sector relevance: unauthenticated RCE in an AI trading agent exposes broker tokens, trading strategies, and financial automation infrastructure.

*Deep dive: `TIER_2_CVE-2026-114108.md`*

___________________________________


# **[CVE-2026-114123 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-114123)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-21

Default public Azure deployments of the D365 Finance & Operations MCP server leak security roles and business logic without authentication, directly impacting enterprise financial systems.

*Deep dive: `TIER_2_CVE-2026-114123.md`*

___________________________________


# **[CVE-2026-89035 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-89035)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-21

TIER 2 session token replay in MikroTik RouterOS WebFig undermines foundational edge networking infrastructure widely deployed in government and ISP environments, threatening the availability of dependent digital public services.

*Deep dive: `TIER_2_CVE-2026-89035.md`*

___________________________________


# **[CVE-2026-96888 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-96888)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-21

Foundational DNS infrastructure (BIND 9) underpinning all DPI sectors; DoS risk to public-facing resolvers used by government, finance, and healthcare services.

*Deep dive: `TIER_2_CVE-2026-96888.md`*

___________________________________


# **[CVE-2025-55702 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2025-55702)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-21

Tier 2 HTTP request smuggling in Apache Traffic Server bypasses front-end proxy security controls, impacting foundational infrastructure that underpins regulated enterprise and public services.

*Deep dive: `TIER_2_CVE-2025-55702.md`*

___________________________________


# **[CVE-2026-110803 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-110803)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-21

Tier 2 unauthenticated DoS in a foundational Java web framework widely deployed for public-facing portals across government, healthcare, and finance sectors.

*Deep dive: `TIER_2_CVE-2026-110803.md`*

___________________________________


# **[CVE-2026-111813 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-111813)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-21

TIER 2 critical RCE in core reverse proxy infrastructure, relevant to DPI as it underpins public-facing and regulated digital services.

*Deep dive: `TIER_2_CVE-2026-111813.md`*

___________________________________


# **[CVE-2026-114106 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-114106)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-21

Finance sector relevance: unauthenticated path traversal in an algorithmic trading agent exposes trading credentials and API keys, directly impacting quantitative finance operations.

*Deep dive: `TIER_2_CVE-2026-114106.md`*

___________________________________


# **[CVE-2026-114489 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-114489)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-21

Tier 2 missing authorization in hMailServer admin APIs breaks multi-tenant email isolation, impacting foundational communication infrastructure across regulated sectors.

*Deep dive: `TIER_2_CVE-2026-114489.md`*

___________________________________


# **[CVE-2026-19630 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-19630)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-21

Foundational DNS infrastructure supporting all regulated/public digital services; unauthenticated DoS risks widespread disruption across government, finance, and healthcare networks.

*Deep dive: `TIER_2_CVE-2026-19630.md`*

___________________________________


# **[CVE-2026-76290 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-76290)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-21

General infrastructure (security analytics/log management) widely deployed in government and regulated sectors; DoS could disrupt critical compliance monitoring and security operations.

*Deep dive: `TIER_2_CVE-2026-76290.md`*

___________________________________


# **[CVE-2026-82819 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-82819)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-21

Enterprise FTP platform explicitly deployed across Finance, Healthcare, and Government for compliant document exchange, making credential leakage a cross-sector regulated infrastructure risk.

*Deep dive: `TIER_2_CVE-2026-82819.md`*

___________________________________


# **[CVE-2026-96640 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-96640)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-21

Foundational Python imaging library used across regulated web/document pipelines; DoS risk to public-facing services processing untrusted PDFs.

*Deep dive: `TIER_2_CVE-2026-96640.md`*

___________________________________


# **[CVE-2026-97206 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-97206)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-21

Core DNS naming infrastructure underpinning all digital sectors; DoS risk to recursive resolvers requires patching or disabling non-default DoQ.

*Deep dive: `TIER_2_CVE-2026-97206.md`*

___________________________________


# **[CVE-2026-114243 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-114243)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-21

Unauthenticated SQLi in an insurance management system exposes policyholder PII and financial records, aligning with the Finance sector.

*Deep dive: `TIER_2_CVE-2026-114243.md`*

___________________________________


# **[CVE-2026-114245 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-114245)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-21

Unauthenticated admin creation in an open-source insurance management system exposes financial and policy data, aligning with the Finance sector.

*Deep dive: `TIER_2_CVE-2026-114245.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine