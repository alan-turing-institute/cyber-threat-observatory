# **Infrastructure Daily Brief: 2026-09-17**

**Infrastructure Daily Report TLP:GREEN Alert Id: bb1dd5b3 2026-09-19 23:29:32**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-62874 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-85885 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-90997 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-14850 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-54460 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-76949 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-77903 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-87701 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-63460 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-78501 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-85878 (Tier 2)                                                          | 3.k      |
| Threats    | GhostCode Phishing Kit Bypasses Microsoft 365 MFA to Hijack Accounts in 78 Secon | 1.b      |
| Threats    | Microsoft 365: Block Device Code Flow Against GhostCode                          | 1.c      |
| Threats    | Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA                  | 1.e      |
| Threats    | Microsoft: Passkey Help Desk Calls Are Hijacking Cloud Accounts, Then Draining S | 1.a      |
| Threats    | Midnight Blizzard-Linked Actor GTG-20006 Automated Device Code Phishing With AI  | 1.d      |
| Threats    | Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA      | 1.f      |
| Threats    | The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations         | 1.d      |
| Threats    | Fast Flux Phishing Turns the Internet Into a Moving Target as Silent Push Uncove | 1.f      |
| Threats    | CVE-2026-76460                                                                   | 3.k      |
| Threats    | CVE-2026-92808                                                                   | 1.b      |
| Threats    | CVE-2026-20234                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[GhostCode Phishing Kit Bypasses Microsoft 365 MFA to Hijack Accounts in 78 Seconds](https://cybersecuritynews.com/ghostcode-phishing-kit/amp)**

**PIR: 1.b**

Source: ketch Published: 2026-09-17

GhostCode operators deploy a refined phishing kit that intercepts Microsoft 365 authentication flows, bypassing multi-factor authentication in under two minutes. The campaign leverages real-time session token theft and automated device registration to maintain persistent access. Infrastructure defenders should monitor for anomalous device code grants, enforce conditional access policies restricting legacy authentication, and deploy token revocation scripts immediately upon detection.

___________________________________


# **[Microsoft 365: Block Device Code Flow Against GhostCode](https://windowsforum.com/news/microsoft-365-block-device-code-flow-against-ghostcode.444973)**

**PIR: 1.c**

Source: ketch Published: 2026-09-17

Microsoft recommends immediate mitigation steps to disable the device code authorization flow, a primary vector exploited by GhostCode for M365 account takeover. The advisory outlines PowerShell commands and Entra ID configuration changes to restrict device enrollment and token issuance. IT infrastructure teams must audit active device codes, implement just-in-time access controls, and validate conditional access rules to prevent unauthorized cloud resource provisioning.

___________________________________


# **[Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA](https://tempmail.ninja/blog/laundry-bear-zimbra-phishing)**

**PIR: 1.e**

Source: ketch Published: 2026-09-17

CISA alerts infrastructure teams to a zero-click phishing campaign targeting Zimbra email servers, exploited by the Russian-linked Laundry Bear group. The attack leverages an unpatched server-side vulnerability to inject malicious payloads directly into user inboxes without interaction. Defenders must immediately apply vendor patches, segment email infrastructure, monitor for unauthorized outbound connections, and validate server integrity using known-good baselines.

___________________________________


# **[Microsoft: Passkey Help Desk Calls Are Hijacking Cloud Accounts, Then Draining SharePoint](https://threat-intelligence.redeyesecurity.com/blog/passkey-phishing-microsoft-cloud-hijack-storm-3032-2026)**

**PIR: 1.a**

Source: ketch Published: 2026-09-17

Threat actors are exploiting social engineering via fake Microsoft support calls to trick users into initiating passkey registration on attacker-controlled devices. Once registered, these passkeys grant full administrative access to cloud environments, enabling rapid SharePoint data exfiltration. Defenders should implement passkey registration alerts, enforce hardware-bound credential policies, and train help desk staff to verify identity requests through out-of-band channels.

___________________________________


# **[Midnight Blizzard-Linked Actor GTG-20006 Automated Device Code Phishing With AI](https://aegisai.ai/blog/anthropic-midnight-blizzard-ai-device-code-phishing)**

**PIR: 1.d**

Source: ketch Published: 2026-09-17

A threat actor linked to Midnight Blizzard is automating Microsoft device code phishing campaigns using AI-driven orchestration. The group dynamically generates phishing pages, manages concurrent authentication sessions, and auto-registers rogue devices upon token capture. Defenders should monitor Entra ID sign-in logs for rapid device code approvals, enforce risk-based conditional access, and deploy automated response playbooks to revoke compromised tokens and isolate affected endpoints.

___________________________________


# **[Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA](https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns)**

**PIR: 1.f**

Source: ketch Published: 2026-09-17

Modern phishing operations increasingly leverage cloud-native services like serverless functions, CDN edge nodes, and ephemeral containers to host malicious payloads and evade traditional perimeter defenses. Attackers dynamically rotate infrastructure to bypass DNS blacklists and IP reputation filters. Infrastructure defenders must implement cloud workload protection platforms, monitor for anomalous API calls, and enforce strict egress filtering to detect and block cloud-hosted phishing endpoint

___________________________________


# **[The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations](https://itsecurityguru.org/2026/05/27/the-ai-phishing-revolution-from-spray-and-pray-to-autonomous-operations)**

**PIR: 1.d**

Source: ketch Published: 2026-09-17

Generative AI is transforming phishing from broad, low-success campaigns into highly targeted, autonomous operations capable of adapting to security controls in real time. AI-driven tools automate victim profiling, craft context-aware lures, and dynamically modify landing pages to bypass content filters. Defenders should prioritize behavioral analytics, deploy AI-resistant email authentication standards, and implement continuous user training focused on contextual threat recognition.

___________________________________


# **[Fast Flux Phishing Turns the Internet Into a Moving Target as Silent Push Uncovers a Massive Canada-First Banking Operation + Video - UNDERCODE NEWS](https://undercodenews.com/fast-flux-phishing-turns-the-internet-into-a-moving-target-as-silent-push-uncovers-a-massive-canada-first-banking-operation-video)**

**PIR: 1.f**

Source: ketch Published: 2026-09-17

Attackers are deploying fast-flux DNS networks to rapidly rotate phishing infrastructure across thousands of compromised hosts, making takedown efforts nearly impossible. Combined with silent push notifications, this technique enables large-scale banking credential theft. Infrastructure defenders should implement DNS sinkholing, monitor for high-entropy domain registrations, and deploy network-level threat intelligence feeds to dynamically block fast-flux endpoints before user interaction.

___________________________________


# **[CVE-2026-76460](https://nvd.nist.gov/vuln/detail/CVE-2026-76460)**

**PIR: 3.k**

Source: vulners/duckdb Published: 2026-09-16

A vulnerability in an API of Cisco Identity Services Engine (ISE) could allow an unauthenticated, remote attacker to bypass authentication.

This vulnerability is due to insufficient authentication control on an API endpoint. An attacker could exploit this vulnerability by sending a crafted request to an affected API endpoint. A successful exploit could allow the attacker to gain unauthorized access to the affected device by bypassing the web-based management interface.

___________________________________


# **[CVE-2026-92808](https://nvd.nist.gov/vuln/detail/CVE-2026-92808)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-16

A server-side request forgery (SSRF) vulnerability exists in the UnifiedLogin service of Altium Enterprise Server. An unauthenticated network attacker can cause the server to issue outbound HTTP requests to a destination of the attacker's choosing, including internal services that are reachable only from the server itself.




One such internal service exposes server configuration and credential material without authentication, relying only on the request originating locally. Because the forged 

___________________________________


# **[CVE-2026-20234](https://nvd.nist.gov/vuln/detail/CVE-2026-20234)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-16

As part of Cisco's ongoing commitment to proactive security and product quality, the Cisco Identity Services Engine (ISE) and Cisco ISE Passive Identity Connector (ISE-PIC) engineering teams have conducted a comprehensive internal security review. This review resulted in a software hardening release that addresses multiple internally discovered vulnerabilities.

The vulnerabilities tracked by CVE-2026-20234 are related to insufficiently protected credentials issues that are grouped under the C

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-62874 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-62874)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-17

Critical remote privilege escalation in Microsoft Azure Billing directly impacts financial transaction integrity and government cloud procurement systems.

*Deep dive: `TIER_2_CVE-2026-62874.md`*

___________________________________


# **[CVE-2026-85885 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-85885)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-17

Command injection in Microsoft 365 Copilot impacts Government, Finance, and Healthcare sectors relying on M365 as foundational infrastructure.

*Deep dive: `TIER_2_CVE-2026-85885.md`*

___________________________________


# **[CVE-2026-90997 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-90997)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-17

Digital Identity sector: Core IdAM platform (Keycloak) authentication bypass impacting JWT/DPoP/TOTP replay protection, directly affecting digital identity infrastructure.

*Deep dive: `TIER_2_CVE-2026-90997.md`*

___________________________________


# **[CVE-2026-14850 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-14850)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-17

TIER 2 IDOR in a municipal parking app enables mass account takeover, directly impacting government service delivery and citizen financial transactions.

*Deep dive: `TIER_2_CVE-2026-14850.md`*

___________________________________


# **[CVE-2026-54460 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-54460)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-17

Critical unauthenticated account takeover in healthcare appointment booking software, directly exposing patient data and clinic operations.

*Deep dive: `TIER_2_CVE-2026-54460.md`*

___________________________________


# **[CVE-2026-76949 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-76949)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-17

Core authentication library flaw enabling session hijacking and account takeover, directly impacting Digital Identity infrastructure.

*Deep dive: `TIER_2_CVE-2026-76949.md`*

___________________________________


# **[CVE-2026-77903 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-77903)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-17

Critical unauthenticated privilege escalation in Microsoft Dataverse, a foundational SaaS data platform explicitly underpinning Government, Finance, and Healthcare digital services.

*Deep dive: `TIER_2_CVE-2026-77903.md`*

___________________________________


# **[CVE-2026-87701 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-87701)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-17

Foundational cloud database service explicitly tied to national digital infrastructure resilience, with privilege escalation risks impacting cross-tenant boundaries in regulated/public deployments.

*Deep dive: `TIER_2_CVE-2026-87701.md`*

___________________________________


# **[CVE-2026-63460 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-63460)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-17

Impacts the Finance/Payments sector by exposing headless commerce platforms handling digital transactions to unauthenticated DoS via public APIs.

*Deep dive: `TIER_2_CVE-2026-63460.md`*

___________________________________


# **[CVE-2026-78501 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-78501)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-17

General enterprise AI productivity layer widely deployed across government and regulated sectors; prompt injection risk threatens foundational public service data.

*Deep dive: `TIER_2_CVE-2026-78501.md`*

___________________________________


# **[CVE-2026-85878 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-85878)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-17

Tier 2 privilege escalation in Azure Database for PostgreSQL, a foundational cloud data service underpinning regulated Finance, Healthcare, and Government workloads.

*Deep dive: `TIER_2_CVE-2026-85878.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine