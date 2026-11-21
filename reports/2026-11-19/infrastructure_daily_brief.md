# **Infrastructure Daily Brief: 2026-11-19**

**Infrastructure Daily Report TLP:GREEN Alert Id: 4ebb1084 2026-11-21 11:03:15**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-123890 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-130235 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-130236 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-84236 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-103026 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-131914 (Tier 1)                                                         | 3.k      |
| Cyber News | CVE-2026-132286 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-133172 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-133323 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-19609 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-76535 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-87977 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-116439 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-123058 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-125060 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-131192 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-132131 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-133303 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-82342 (Tier 2)                                                          | 3.k      |
| Threats    | Crafty Microsoft Teams Booking Flow Disguises Device Code Phishing | Huntress    | 1.b      |
| Threats    | Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Se | 1.h      |
| Threats    | Inside an AI‑enabled device code phishing campaign | Microsoft Security Blog     | 1.e      |
| Threats    | The hidden network: Inside the phishing infrastructure ecosystem powering global | 1.d      |
| Threats    | Tracking BigBear 2.0 Evilginx2 Phishing Campaign | CloudSEK                      | 1.f      |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US        | 1.b      |
| Threats    | Microsoft 365 device code phishing campaign bypasses password stealing | RL Blog | 1.b      |
| Threats    | Joint advisory: state-sponsored spear-phishing campaigns targeting critical infr | 1.c      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Crafty Microsoft Teams Booking Flow Disguises Device Code Phishing | Huntress](https://www.huntress.com/blog/crafty-microsoft-teams-booking-flow-disguises-device-code-phishing)**

**PIR: 1.b**

Source: ketch Published: 2026-11-19

Huntress researchers uncover a novel tactic where attackers abuse Microsoft Teams meeting booking flows to deliver device code phishing prompts. By embedding malicious verification requests within legitimate calendar invites, threat actors achieve higher user compliance. The article provides detection queries for Teams audit logs, guidance on restricting external booking permissions, and user awareness strategies to identify spoofed scheduling workflows.

___________________________________


# **[Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/)**

**PIR: 1.h**

Source: ketch Published: 2026-11-19

This analysis exposes EvilTokens, a sophisticated framework enabling device code phishing that bypasses traditional MFA by hijacking OAuth consent flows. Defenders learn how attackers trick users into entering verification codes on malicious portals, granting them persistent access tokens. The article provides detection rules for Azure AD sign-in logs, conditional access policy hardening, and user education tactics to mitigate this evolving identity threat.

___________________________________


# **[Inside an AI‑enabled device code phishing campaign | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.e**

Source: ketch Published: 2026-11-19

Microsoft details a campaign leveraging generative AI to craft highly personalized device code phishing emails that dynamically adapt to target industries and internal communication styles. The report highlights how AI reduces attacker setup time and increases click-through rates. Defenders are advised to deploy AI-driven email classification, monitor for unnatural linguistic patterns, and enforce strict OAuth consent policies to block automated token theft.

___________________________________


# **[The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime/)**

**PIR: 1.d**

Source: ketch Published: 2026-11-19

Microsoft researchers dissect the underground infrastructure supporting modern phishing campaigns, revealing how threat actors leverage bulletproof hosting, fast-flux DNS, and compromised legitimate domains to evade takedowns. The report details defensive strategies for infrastructure teams, including passive DNS monitoring, certificate transparency log analysis, and automated sinkholing techniques to disrupt attacker supply chains before credentials are compromised.

___________________________________


# **[Tracking BigBear 2.0 Evilginx2 Phishing Campaign | CloudSEK](https://www.cloudsek.com/blog/tracking-bigbear-2-0-evilginx2-phishing-campaign)**

**PIR: 1.f**

Source: ketch Published: 2026-11-19

CloudSEK tracks the BigBear 2.0 campaign utilizing Evilginx2 to perform advanced proxy-based phishing attacks that capture session cookies and bypass multi-factor authentication. The report outlines network-level indicators, proxy configuration patterns, and behavioral anomalies defenders can monitor. It emphasizes the importance of certificate pinning, session timeout policies, and endpoint detection to neutralize cookie-stealing infrastructure.

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.b**

Source: ketch Published: 2026-11-19

Proofpoint examines how device code phishing has matured from opportunistic scams into a structured identity takeover methodology. Attackers now automate consent requests and deploy realistic landing pages mimicking enterprise SSO portals. The article guides security teams on implementing token revocation workflows, monitoring for anomalous OAuth app registrations, and deploying email filtering rules to block device code prompts.

___________________________________


# **[Microsoft 365 device code phishing campaign bypasses password stealing | RL Blog](https://www.reversinglabs.com/blog/device-code-phishing-campaign)**

**PIR: 1.b**

Source: ketch Published: 2026-11-19

ReversingLabs analyzes a targeted campaign exploiting Microsoft 365 device code flows to bypass traditional credential harvesting. By redirecting users to legitimate Microsoft login pages that prompt for verification codes, attackers obtain valid access tokens without ever capturing passwords. The post provides forensic indicators, proxy detection techniques, and recommendations for restricting device code usage in high-security environments.

___________________________________


# **[Joint advisory: state-sponsored spear-phishing campaigns targeting critical infrastructure - SUVAT](https://suvat.uk/blog/five-eyes-advisory.html)**

**PIR: 1.c**

Source: ketch Published: 2026-11-19

A Five Eyes joint advisory details coordinated spear-phishing operations targeting critical infrastructure sectors with highly tailored lures and malicious RDP attachments. The report emphasizes threat intelligence sharing, email gateway hardening, and endpoint isolation protocols. Defenders are urged to monitor for anomalous lateral movement post-delivery and implement strict macro execution policies to mitigate initial access risks.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-123890 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-123890)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-19

Foundational virtualization management platform underpinning Government, Finance, and Healthcare infrastructure, with active in-wild exploitation and no workaround.

*Deep dive: `TIER_2_CVE-2026-123890.md`*

___________________________________


# **[CVE-2026-130235 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-130235)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-19

Digital Identity: SSRF in Okta .NET SDK leaks SSWS API tokens, compromising foundational identity infrastructure.

*Deep dive: `TIER_2_CVE-2026-130235.md`*

___________________________________


# **[CVE-2026-130236 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-130236)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-19

TIER 2 flaw in Auth0 Authorization Extension allows authenticated users to bypass access controls and inject malicious logic into tenant login rules, directly compromising Digital Identity infrastructure and authentication integrity.

*Deep dive: `TIER_2_CVE-2026-130236.md`*

___________________________________


# **[CVE-2026-84236 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-84236)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-19

Critical unauthenticated RCE in IBM Guardium compliance appliances directly impacts regulated Finance, Government, and Healthcare database monitoring and audit integrity.

*Deep dive: `TIER_2_CVE-2026-84236.md`*

___________________________________


# **[CVE-2026-103026 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-103026)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-19

Finance sector relevance: unauthenticated authorization bypass in a public-facing hosting billing platform allows arbitrary state modification of payment and account records.

*Deep dive: `TIER_2_CVE-2026-103026.md`*

___________________________________


# **[CVE-2026-131914 (Tier 1)](https://nvd.nist.gov/vuln/detail/CVE-2026-131914)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-19

Actively exploited unauthenticated RCE in a legacy ASP.NET CSRF library widely deployed across government, financial, and healthcare web portals.

*Deep dive: `TIER_1_CVE-2026-131914.md`*

___________________________________


# **[CVE-2026-132286 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-132286)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-19

Impacts identity and account provisioning in RuoYi, a framework widely deployed in Chinese government and enterprise internal management portals.

*Deep dive: `TIER_2_CVE-2026-132286.md`*

___________________________________


# **[CVE-2026-133172 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-133172)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-19

Cross-tenant authorization bypass in Cozy Cloud threatens sensitive municipal and healthcare data hosted on shared European public-sector infrastructure.

*Deep dive: `TIER_2_CVE-2026-133172.md`*

___________________________________


# **[CVE-2026-133323 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-133323)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-19

Unauthenticated remote code execution in an internet-facing enterprise UC platform widely deployed across government, finance, and healthcare sectors, posing a direct pivot risk to regulated networks.

*Deep dive: `TIER_2_CVE-2026-133323.md`*

___________________________________


# **[CVE-2026-19609 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-19609)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-19

XSS in Unblu co-browsing bridges public-facing customer portals to internal agent sessions, directly impacting regulated Finance, Government, and Healthcare digital service desks.

*Deep dive: `TIER_2_CVE-2026-19609.md`*

___________________________________


# **[CVE-2026-76535 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-76535)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-19

Critical authentication bypass in Splunk Enterprise SIEM, a foundational security platform widely deployed across Government, Finance, and Healthcare for compliance logging and threat detection.

*Deep dive: `TIER_2_CVE-2026-76535.md`*

___________________________________


# **[CVE-2026-87977 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-87977)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-19

Critical SQLi in IBM Guardium Data Protection, a core compliance and data security platform widely deployed across Finance, Healthcare, and Government sectors for regulatory adherence.

*Deep dive: `TIER_2_CVE-2026-87977.md`*

___________________________________


# **[CVE-2026-116439 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-116439)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-19

Unauthenticated path traversal in foundational enterprise storage (Dell PowerStore) risks data integrity and availability across regulated Finance, Healthcare, and Government deployments.

*Deep dive: `TIER_2_CVE-2026-116439.md`*

___________________________________


# **[CVE-2026-123058 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-123058)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-19

Unauthenticated installer RCE in a widely deployed e-commerce platform directly impacts digital commerce infrastructure and financial transaction processing (Finance sector).

*Deep dive: `TIER_2_CVE-2026-123058.md`*

___________________________________


# **[CVE-2026-125060 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-125060)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-19

TIER 2 IDOR in JTL-Shop checkout exposes customer PII and payment/transaction data, impacting digital commerce and Finance sector compliance.

*Deep dive: `TIER_2_CVE-2026-125060.md`*

___________________________________


# **[CVE-2026-131192 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-131192)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-19

Foundational SIEM/log management infrastructure supporting compliance and security monitoring across regulated sectors (Finance, Healthcare, Government, Digital Identity).

*Deep dive: `TIER_2_CVE-2026-131192.md`*

___________________________________


# **[CVE-2026-132131 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-132131)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-19

General infrastructure (Node.js web framework) explicitly noted as used in government and public services; allows auth bypass.

*Deep dive: `TIER_2_CVE-2026-132131.md`*

___________________________________


# **[CVE-2026-133303 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-133303)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-19

Enterprise unified communications platform widely deployed across government, finance, and healthcare; unauthenticated RCE in internet-facing web conferencing poses systemic risk to regulated operations.

*Deep dive: `TIER_2_CVE-2026-133303.md`*

___________________________________


# **[CVE-2026-82342 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-82342)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-19

Tier 2 RCE in IBM Guardium compliance monitoring appliance risks audit log integrity, directly impacting regulated Finance, Healthcare, and Government environments reliant on PCI-DSS/HIPAA/GDPR monitoring.

*Deep dive: `TIER_2_CVE-2026-82342.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine