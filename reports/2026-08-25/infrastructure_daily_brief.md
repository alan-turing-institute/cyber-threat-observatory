# **Infrastructure Daily Brief: 2026-08-25**

**Infrastructure Daily Report TLP:GREEN Alert Id: eafe8cc9 2026-08-26 19:34:38**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-65633 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-77998 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-80192 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-63072 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-77136 (Tier 2)                                                          | 3.k      |
| Threats    | OAuth Device Code Phishing: 37x Surge in Enterprise ATO                          | 1.c.2    |
| Threats    | Device Code Phishing — The Attack That Makes MFA Irrelevant                      | 1.c.1    |
| Threats    | Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA      | 1.d.1    |
| Threats    | The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations         | 1.e.1    |
| Threats    | Tycoon2FA Returns: PhaaS Platform Survives Law Enforcement Disruption            | 1.f.1    |
| Threats    | The Procurement Trap: Inside an AiTM Campaign Targeting Global Institutions      | 1.g.1    |
| Threats    | Spearphishing Campaign Abuses npm Registry to Target Critical Infrastructure Sal | 1.g.2    |
| Threats    | CISA and partners publish joint advisory on Russia- ...                          | 1.h.1    |
| Threats    | CVE-2026-55640                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[OAuth Device Code Phishing: 37x Surge in Enterprise ATO](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/04/CSA_research_note_oauth-device-code-phishing-surge_20260405-csa-styled.pdf)**

**PIR: 1.c.2**

Source: ketch Published: 2026-08-25

Enterprise account takeover campaigns leveraging OAuth device code flows have surged 37x, exploiting legitimate authentication mechanisms to bypass traditional MFA controls. Attackers deploy convincing login portals that prompt users to enter device codes, granting threat actors direct session tokens without credential theft. Infrastructure defenders must monitor for anomalous OAuth consent grants, enforce conditional access policies, and deploy real-time alerting for device code authentication 

___________________________________


# **[Device Code Phishing — The Attack That Makes MFA Irrelevant](https://cybergrind.org/blog/2026-06-02-device-code-phishing)**

**PIR: 1.c.1**

Source: ketch Published: 2026-08-25

Device code phishing represents a critical evolution in identity compromise, effectively neutralizing multi-factor authentication by hijacking the OAuth 2.0 device authorization grant. Threat actors host spoofed portals requesting users to input codes from corporate devices, instantly capturing valid access tokens. Defenders should implement strict OAuth scope restrictions, monitor for high-velocity device code validations, and educate users on recognizing legitimate device authorization prompts

___________________________________


# **[Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA](https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns)**

**PIR: 1.d.1**

Source: ketch Published: 2026-08-25

Modern phishing operations increasingly leverage cloud-native services like serverless functions, object storage, and managed DNS to host malicious infrastructure at scale. This approach reduces detection latency, complicates takedown efforts, and mimics legitimate traffic patterns. Infrastructure teams must implement cloud workload protection platforms, enforce strict egress filtering, and deploy behavioral analytics to identify anomalous cloud resource provisioning tied to phishing domains.

___________________________________


# **[The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations](https://itsecurityguru.org/2026/05/27/the-ai-phishing-revolution-from-spray-and-pray-to-autonomous-operations)**

**PIR: 1.e.1**

Source: ketch Published: 2026-08-25

Generative AI has transformed phishing from broad, low-yield campaigns into highly targeted, autonomous operations capable of real-time content adaptation and multi-language deployment. Threat actors utilize AI to craft context-aware lures, automate infrastructure provisioning, and dynamically adjust payloads based on victim responses. Defenders must shift from signature-based detection to behavioral analytics, implement AI-driven email security gateways, and enforce zero-trust email handling pr

___________________________________


# **[Tycoon2FA Returns: PhaaS Platform Survives Law Enforcement Disruption](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/03/CSA_research_note_Tycoon2FA-PhaaS-resurrection-MaaS-resilience-20260326-csa-styled.pdf)**

**PIR: 1.f.1**

Source: ketch Published: 2026-08-25

The Tycoon2FA phishing-as-a-service platform has re-emerged following a major law enforcement takedown, demonstrating the resilience and decentralized architecture of modern PhaaS ecosystems. Operators now utilize distributed cloud hosting, encrypted communication channels, and automated infrastructure rotation to maintain service continuity. Infrastructure defenders should monitor known PhaaS infrastructure patterns, block associated C2 domains, and enforce strict MFA phishing-resistant standar

___________________________________


# **[The Procurement Trap: Inside an AiTM Campaign Targeting Global Institutions](https://www.hendryadrian.com/the-procurement-trap-inside-an-aitm-campaign-targeting-global-institutions/)**

**PIR: 1.g.1**

Source: ketch Published: 2026-08-25

Attackers are weaponizing procurement workflows to deploy advanced-in-the-middle (AiTM) phishing kits that intercept and relay authentication sessions in real-time. By mimicking vendor portals and purchase order systems, threat actors bypass MFA and extract session cookies from high-value targets. Defenders must implement procurement-specific email filtering, enforce hardware-backed authentication, and deploy session token monitoring to detect active AiTM relay attacks.

___________________________________


# **[Spearphishing Campaign Abuses npm Registry to Target Critical Infrastructure Sales Teams | Mallory](https://mallory.ai/stories/019b5374-9b37-7ddb-9b5b-5a7226c9e64f)**

**PIR: 1.g.2**

Source: ketch Published: 2026-08-25

A sophisticated spearphishing campaign is exploiting the npm registry to distribute malicious packages disguised as legitimate development tools, specifically targeting sales and engineering teams within critical infrastructure sectors. The malware establishes persistent backdoors and exfiltrates internal network maps. Infrastructure teams should enforce strict package integrity verification, implement software bill of materials tracking, and isolate development environments from production netw

___________________________________


# **[CISA and partners publish joint advisory on Russia- ...](https://insidecybersecurity.com/daily-news/cisa-and-partners-publish-joint-advisory-russia-sponsored-sophisticated-phishing-campaign)**

**PIR: 1.h.1**

Source: ketch Published: 2026-08-25

A joint CISA advisory details a state-sponsored phishing campaign utilizing highly customized lures and advanced evasion techniques to target government and defense contractors. The operation employs living-off-the-land binaries and encrypted C2 channels to maintain persistence. Defenders should review CISA mitigation guidance, patch exposed services, enhance endpoint detection rules for LOLBin abuse, and monitor for anomalous outbound traffic to known threat actor infrastructure.

___________________________________


# **[CVE-2026-55640](https://nvd.nist.gov/vuln/detail/CVE-2026-55640)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-25

Nextcloud MCP Server is a production-ready MCP server that connects AI assistants to a Nextcloud instance. Prior to 0.117.2, the POST /webhooks/nextcloud endpoint in nextcloud_mcp_server/vector/webhook_receiver.py has no authentication by default because WEBHOOK_SECRET defaults to None and startup validation does not require it. When WEBHOOK_SECRET is unset, handle_nextcloud_webhook() accepts unauthenticated requests. The payload["user"]["uid"] field parsed in nextcloud_mcp_server/vector/webhook

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-65633 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-65633)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-25

Digital Identity: Critical authentication bypass in a core JWT/bearer token library enables full account takeover via token replay, directly impacting identity management infrastructure.

*Deep dive: `TIER_2_CVE-2026-65633.md`*

___________________________________


# **[CVE-2026-77998 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-77998)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-25

Directly compromises SAML-based Single Sign-On trust boundaries, enabling unauthenticated admin takeover in enterprise and public-sector identity management deployments.

*Deep dive: `TIER_2_CVE-2026-77998.md`*

___________________________________


# **[CVE-2026-80192 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-80192)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-25

Directly impacts Digital Identity infrastructure by bypassing SSO domain verification, enabling unauthorized account linking and organization assignment.

*Deep dive: `TIER_2_CVE-2026-80192.md`*

___________________________________


# **[CVE-2026-63072 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-63072)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-25

Foundational OpenSSL CMS flaw causes deterministic DoS across all regulated sectors relying on encrypted mail/document processing.

*Deep dive: `TIER_2_CVE-2026-63072.md`*

___________________________________


# **[CVE-2026-77136 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-77136)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-25

Actively exploited RCE in TYPO3 Powermail, a general-purpose CMS widely deployed across government and enterprise web infrastructure.

*Deep dive: `TIER_2_CVE-2026-77136.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine