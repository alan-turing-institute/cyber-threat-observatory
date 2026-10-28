# **Infrastructure Daily Brief: 2026-10-27**

**Infrastructure Daily Report TLP:GREEN Alert Id: 88d1862e 2026-10-28 12:28:06**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-116672 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-104189 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-111107 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-112352 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-112353 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-77167 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-57190 (Tier 2)                                                          | 3.k      |
| Threats    | The hidden network: Inside the phishing infrastructure ecosystem powering global | 1.a      |
| Threats    | Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Se | 1.c      |
| Threats    | AI-powered phishkit arms criminals with account-hijacking tools in 10 minutes |  | 1.d      |
| Threats    | Inside an AI‑enabled device code phishing campaign | Microsoft Security Blog     | 1.c      |
| Threats    | Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale | Microsoft  | 1.b      |
| Threats    | Joint advisory: state-sponsored spear-phishing campaigns targeting critical infr | 1.e      |
| Threats    | Foreign Threat Actor Conducting Large-Scale Spearphishing Campaign with RDP Atta | 1.f      |
| Threats    | Midnight Blizzard conducts large-scale spear-phishing campaign using RDP files | | 1.f      |
| Threats    | CVE-2026-94380                                                                   | 1.b      |
| Threats    | CVE-2026-101034                                                                  | 1.b      |
| Threats    | CVE-2026-89209                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime/)**

**PIR: 1.a**

Source: ketch Published: 2026-10-27

Details the underground infrastructure ecosystem enabling global phishing campaigns, highlighting shared hosting, domain generation algorithms, and proxy networks. Defenders can leverage these IOCs to block malicious infrastructure at the network perimeter and enhance DNS filtering policies.

___________________________________


# **[Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/)**

**PIR: 1.c**

Source: ketch Published: 2026-10-27

Analyzes the EvilTokens campaign exploiting Microsoft device code authentication flows to bypass MFA. The report outlines attacker infrastructure, token theft mechanisms, and detection strategies for identity protection teams to monitor anomalous device code approvals.

___________________________________


# **[AI-powered phishkit arms criminals with account-hijacking tools in 10 minutes | Malwarebytes](https://www.malwarebytes.com/blog/threat-intel/2026/10/ai-powered-phishkit-arms-criminals-with-account-hijacking-tools-in-10-minutes)**

**PIR: 1.d**

Source: ketch Published: 2026-10-27

Examines an AI-driven phishing kit that automates credential harvesting and account takeover in under ten minutes. Highlights rapid deployment capabilities, dynamic page generation, and evasion techniques. Recommends implementing adaptive MFA, user training, and behavioral analytics to mitigate automated identity theft.

___________________________________


# **[Inside an AI‑enabled device code phishing campaign | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.c**

Source: ketch Published: 2026-10-27

Explores a campaign leveraging AI to craft highly personalized device code phishing prompts, increasing success rates against enterprise users. Provides technical breakdowns of prompt engineering, infrastructure patterns, and detection rules for SIEM and identity governance platforms.

___________________________________


# **[Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale/)**

**PIR: 1.b**

Source: ketch Published: 2026-10-27

Dissects the Tycoon2FA Adversary-in-the-Middle (AiTM) phishing kit, detailing its real-time session hijacking capabilities and proxy architecture. Offers actionable guidance for infrastructure teams to deploy certificate pinning, monitor for suspicious proxy traffic, and enforce phishing-resistant MFA.

___________________________________


# **[Joint advisory: state-sponsored spear-phishing campaigns targeting critical infrastructure - SUVAT](https://suvat.uk/blog/five-eyes-advisory.html)**

**PIR: 1.e**

Source: ketch Published: 2026-10-27

Covers coordinated state-sponsored spear-phishing operations targeting critical infrastructure sectors. Details TTPs, malicious attachments, and initial access vectors. Advises defenders to harden email gateways, segment OT/IT networks, and monitor for lateral movement indicators.

___________________________________


# **[Foreign Threat Actor Conducting Large-Scale Spearphishing Campaign with RDP Attachments | CISA](https://www.cisa.gov/news-events/alerts/2024/10/31/foreign-threat-actor-conducting-large-scale-spearphishing-campaign-rdp-attachments)**

**PIR: 1.f**

Source: ketch Published: 2026-10-27

Alerts on large-scale spear-phishing campaigns distributing malicious RDP files to compromise remote access infrastructure. Provides mitigation steps including disabling RDP where unnecessary, enforcing network-level authentication, and monitoring for unauthorized remote connections.

___________________________________


# **[Midnight Blizzard conducts large-scale spear-phishing campaign using RDP files | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2024/10/29/midnight-blizzard-conducts-large-scale-spear-phishing-campaign-using-rdp-files/)**

**PIR: 1.f**

Source: ketch Published: 2026-10-27

Analyzes a state-sponsored campaign using spear-phished RDP files to gain initial access to government and enterprise networks. Highlights persistence mechanisms, credential dumping techniques, and defensive strategies for securing remote access and identity management systems.

___________________________________


# **[CVE-2026-94380](https://nvd.nist.gov/vuln/detail/CVE-2026-94380)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-26

Weak Password Recovery Mechanism for Forgotten Password vulnerability in HAVELSAN Inc. Liman MYS allows Password Recovery Exploitation.

This issue affects Liman MYS: from 2.3.4-1124 before 2.3.5-1131.

___________________________________


# **[CVE-2026-101034](https://nvd.nist.gov/vuln/detail/CVE-2026-101034)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-27

An attacker who obtained the hardcoded key could decrypt domain/service account passwords, task run-as credentials, and sysprep passwords stored in or transmitted by GSS Deployment Server installation.

___________________________________


# **[CVE-2026-89209](https://nvd.nist.gov/vuln/detail/CVE-2026-89209)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-26

A vulnerability has been identified in Mendix SAML (Mendix 10 compatible) (All versions < V4.2.4), Mendix SAML (Mendix 11 compatible) (All versions < V4.2.4), Mendix SAML (Mendix 9 compatible) (All versions < V3.6.29). Affected versions of the module do not properly protect against SAML assertion replay in IdP-initiated authentication flows. This could allow unauthenticated remote attackers to gain unauthorized access to the application by replaying a valid SAML response.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-116672 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-116672)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-27

Directly compromises OAuth/OIDC authorization servers, enabling token interception and client takeover in core Digital Identity infrastructure.

*Deep dive: `TIER_2_CVE-2026-116672.md`*

___________________________________


# **[CVE-2026-104189 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-104189)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-27

Authorization bypass in Nextcloud 3D Viewer exposes password-protected shared files, impacting secure document exchange in Government, Healthcare, and Finance sectors.

*Deep dive: `TIER_2_CVE-2026-104189.md`*

___________________________________


# **[CVE-2026-111107 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-111107)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-27

Unauthenticated management-plane DoS in widely deployed enterprise firewalls, directly impacting government, healthcare, and financial network perimeters and administrative control.

*Deep dive: `TIER_2_CVE-2026-111107.md`*

___________________________________


# **[CVE-2026-112352 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-112352)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-27

Critical authentication bypass in Sunhillo SureLine surveillance gateways deployed across FAA, defense, and utility networks, posing severe risks to Government and national security infrastructure.

*Deep dive: `TIER_2_CVE-2026-112352.md`*

___________________________________


# **[CVE-2026-112353 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-112353)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-27

Actively exploited stored XSS in enterprise webmail enables direct credential and session theft, directly impacting Digital Identity and regulated sector communications.

*Deep dive: `TIER_2_CVE-2026-112353.md`*

___________________________________


# **[CVE-2026-77167 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-77167)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-27

Persistent unauthenticated DoS on Nextcloud Server, a widely deployed digital sovereignty platform critical for government and healthcare collaboration and data availability.

*Deep dive: `TIER_2_CVE-2026-77167.md`*

___________________________________


# **[CVE-2026-57190 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-57190)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-27

SQL injection in Asterisk PBX logging backends impacts Government and enterprise telecommunications infrastructure.

*Deep dive: `TIER_2_CVE-2026-57190.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine