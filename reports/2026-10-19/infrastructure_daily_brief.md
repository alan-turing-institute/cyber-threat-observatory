# **Infrastructure Daily Brief: 2026-10-19**

**Infrastructure Daily Report TLP:GREEN Alert Id: eb197b0f 2026-10-21 20:50:05**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2025-10149 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-112252 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-13695 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-78164 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-85251 (Tier 2)                                                          | 3.k      |
| Threats    | Microsoft Disrupts YAM Store Network Behind 1 Billion Phishing Scams and M365 De | 1.f      |
| Threats    | Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA      | 1.g      |
| Threats    | GhostCode attackers abuse device codes to take over Microsoft 365 accounts       | 1.f      |
| Threats    | SideWinder APT Credential Harvesting Campaign — PaaS Platform Abuse at Scale     | 1.j.3    |
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.h      |
| Threats    | Device Code Phishing: How EvilTokens Hit 12,000+ Inboxes                         | 1.f      |
| Threats    | Device Code Phishing Hits 340+ Microsoft 365 Orgs Across Five Countries via OAut | 1.f      |
| Threats    | Microsoft Teams Phishing via Fake IT Helpdesk Impersonation (External Chat, Vish | 1.e      |
| Threats    | CVE-2026-113682                                                                  | 1.b      |
| Threats    | CVE-2026-80312                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Microsoft Disrupts YAM Store Network Behind 1 Billion Phishing Scams and M365 Device-Code Attacks](https://windowsforum.com/news/microsoft-disrupts-yam-store-network-behind-1-billion-phishing-scams-and-m365-device-code-attacks.448313/post-1012947)**

**PIR: 1.f**

Source: ketch Published: 2026-10-19

Microsoft’s security operations dismantled the YAM Store network, a massive infrastructure supporting over one billion phishing attempts and widespread Microsoft 365 device-code attacks. The campaign leveraged compromised OAuth flows to bypass traditional email filters, directly targeting identity providers. Defenders should monitor for anomalous device-code authorization requests, enforce conditional access policies, and block known malicious redirect URIs. This disruption highlights the scale 

___________________________________


# **[Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA](https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns)**

**PIR: 1.g**

Source: ketch Published: 2026-10-19

Modern phishing operations increasingly leverage cloud-native services like serverless functions, object storage, and CDN networks to host malicious payloads and evade detection. This infrastructure abuse allows attackers to scale campaigns rapidly while maintaining low costs and high resilience. IT defenders must shift focus from static URL blocking to behavioral analysis of cloud service usage. Implementing egress filtering, monitoring for anomalous API calls, and enforcing strict IAM policies

___________________________________


# **[GhostCode attackers abuse device codes to take over Microsoft 365 accounts](https://computerworld.com/article/4223889/ghostcode-attackers-abuse-device-codes-to-take-over-microsoft-365-accounts.html)**

**PIR: 1.f**

Source: ketch Published: 2026-10-19

The GhostCode threat actor group is actively exploiting Microsoft 365 device-code authentication flows to hijack enterprise accounts. By tricking users into entering authorization codes on malicious portals, attackers bypass multi-factor authentication and gain persistent access to email, Teams, and cloud storage. Infrastructure defenders must implement strict conditional access rules, monitor for unusual device-code sign-ins, and educate users on recognizing fake verification prompts. Blocking 

___________________________________


# **[SideWinder APT Credential Harvesting Campaign — PaaS Platform Abuse at Scale](https://intel.breakglass.tech/post/sidewinder-mhil-zeabur)**

**PIR: 1.j.3**

Source: ketch Published: 2026-10-19

The SideWinder APT group is conducting large-scale credential harvesting by abusing Platform-as-a-Service (PaaS) environments to host sophisticated phishing infrastructure. By leveraging legitimate cloud platforms, attackers bypass traditional security controls and target high-value identity accounts. The campaign utilizes automated deployment scripts and dynamic domain generation to maintain persistence. Defenders should monitor for unauthorized PaaS resource provisioning, enforce least-privile

___________________________________


# **[Inside an AI‑enabled device code phishing campaign](https://microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026)**

**PIR: 1.h**

Source: ketch Published: 2026-10-19

Threat actors are deploying AI-generated landing pages and dynamic content to enhance device-code phishing campaigns targeting Microsoft 365 tenants. These AI-driven sites mimic legitimate Microsoft login flows with high fidelity, increasing user compliance rates. The campaign automates token harvesting and rapidly rotates infrastructure to evade takedowns. Defenders should deploy AI-aware web filtering, monitor for rapid OAuth consent spikes, and enforce application allow-listing. Identity gove

___________________________________


# **[Device Code Phishing: How EvilTokens Hit 12,000+ Inboxes](https://ctiacademy.io/blog/device-code-phishing)**

**PIR: 1.f**

Source: ketch Published: 2026-10-19

The EvilTokens campaign demonstrates how attackers weaponize device-code phishing to compromise thousands of inboxes simultaneously. By distributing malicious links via compromised accounts and spam, threat actors harvest OAuth tokens that grant broad M365 permissions. This technique circumvents traditional email security and MFA controls. Infrastructure teams should audit delegated permissions, restrict third-party app registrations, and implement real-time identity threat detection. Monitoring

___________________________________


# **[Device Code Phishing Hits 340+ Microsoft 365 Orgs Across Five Countries via OAuth Abuse](https://news.u-labs.de/link?id=30726)**

**PIR: 1.f**

Source: ketch Published: 2026-10-19

A coordinated OAuth abuse campaign has impacted over 340 Microsoft 365 organizations across five countries, leveraging device-code phishing to steal identity tokens. Attackers exploit legitimate authentication mechanisms to bypass perimeter defenses and establish persistent access. The campaign highlights vulnerabilities in default cloud identity configurations. Defenders must enforce strict consent policies, disable unnecessary device-code flows where possible, and deploy identity protection so

___________________________________


# **[Microsoft Teams Phishing via Fake IT Helpdesk Impersonation (External Chat, Vishing, Screen Sharing, RMM](https://intel.threadlinqs.com/threat/TL-2026-3778)**

**PIR: 1.e**

Source: ketch Published: 2026-10-19

Attackers are executing sophisticated phishing campaigns within Microsoft Teams by impersonating IT helpdesk personnel to initiate external chats, vishing calls, and unauthorized screen-sharing sessions. The tactic leverages trust in internal support channels to deploy Remote Monitoring and Management (RMM) tools on victim endpoints. Infrastructure defenders must restrict external Teams messaging, enforce strict RMM deployment policies, and monitor for anomalous helpdesk account activity. User t

___________________________________


# **[CVE-2026-113682](https://nvd.nist.gov/vuln/detail/CVE-2026-113682)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-20

Networknt light-4j from 2.1.5 before 2.4.0 contains an authentication bypass vulnerability in BasicAuthHandler that allows unauthenticated attackers to log in as LDAP/AD-delegated users. Attackers can send a Basic Authorization header with a known username and empty password, triggering an unauthenticated LDAP bind that is accepted as successful authentication.

___________________________________


# **[CVE-2026-80312](https://nvd.nist.gov/vuln/detail/CVE-2026-80312)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-19

Improper Authentication vulnerability in Apache Camel OAuth component.



This issue affects Apache Camel: from 4.11.0 before 4.18.5, from 4.19.0 before 4.22.1.



The camel-oauth processors that guard a route did not stop the exchange when authentication could not be completed. Where a failure to establish an authenticated session should have terminated routing and returned an error to the caller, the processors fell through and returned control to the route, so the request continued to the pro

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2025-10149 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2025-10149)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-19

Directly impacts core Digital Identity infrastructure (WSO2 Identity Server) via SCIM authorization bypass enabling federated-to-local account takeover.

*Deep dive: `TIER_2_CVE-2025-10149.md`*

___________________________________


# **[CVE-2026-112252 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-112252)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-19

Targets government safety bureaus and state-owned enterprises via a critical infrastructure compliance system, enabling unauthenticated RCE on internal regulatory networks.

*Deep dive: `TIER_2_CVE-2026-112252.md`*

___________________________________


# **[CVE-2026-13695 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-13695)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-19

Unauthenticated SQLi on an enterprise HR login endpoint enables credential theft and PII exposure, directly impacting Digital Identity and Government/Finance workforce systems.

*Deep dive: `TIER_2_CVE-2026-13695.md`*

___________________________________


# **[CVE-2026-78164 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-78164)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-19

Foundational enterprise middleware (Apache Camel) widely deployed in finance, healthcare, and government API routing; default-vulnerable secret/env-var leakage poses direct credential harvesting risk to regulated integrations.

*Deep dive: `TIER_2_CVE-2026-78164.md`*

___________________________________


# **[CVE-2026-85251 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-85251)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-19

Foundational enterprise middleware handling OAuth2 tokens and credentials; redirect-based leakage risks identity, finance, and government integration flows.

*Deep dive: `TIER_2_CVE-2026-85251.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine