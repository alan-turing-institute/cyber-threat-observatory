# **Infrastructure Daily Brief: 2026-08-10**

**Infrastructure Daily Report TLP:GREEN Alert Id: 5971753d 2026-08-11 15:36:43**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                      | PIR(s)   |
|------------|-----------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-72564 (Tier 2)                                                     | 3.k      |
| Cyber News | CVE-2026-72575 (Tier 2)                                                     | 3.k      |
| Cyber News | CVE-2026-10754 (Tier 2)                                                     | 3.k      |
| Cyber News | CVE-2026-47754 (Tier 2)                                                     | 3.k      |
| Cyber News | CVE-2026-72584 (Tier 2)                                                     | 3.k      |
| Cyber News | CVE-2026-72688 (Tier 2)                                                     | 3.k      |
| Cyber News | CVE-2026-72692 (Tier 2)                                                     | 3.k      |
| Cyber News | CVE-2026-66738 (Tier 2)                                                     | 3.k      |
| Threats    | Inside an AI‑enabled device code phishing campaign                          | 1.i      |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover                   | 1.i      |
| Threats    | Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA | 1.i      |
| Threats    | New widespread EvilTokens kit: device code phishing as-a-service            | 1.k      |
| Threats    | Tycoon2FA Returns: PhaaS Platform Survives Law Enforcement Disruption       | 1.k      |
| Threats    | Inside Kali365, a Device Code Phishing Ecosystem | Huntress                 | 1.k      |
| Threats    | The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations    | 1.j      |
| Threats    | Storm-2372 conducts device code phishing campaign | Microsoft Security Blog | 1.a      |
| Threats    | CVE-2025-32736                                                              | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.i**

Source: ketch Published: 2026-08-10

This campaign combines AI-generated lures with OAuth device code flows to bypass traditional email filters and MFA. Attackers trick users into entering device codes on malicious portals, granting them direct access to corporate accounts. Defenders should monitor for unusual device code authorization requests, restrict OAuth app permissions, and deploy identity threat detection solutions that flag rapid, automated consent grants across cloud directories.

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.i**

Source: ketch Published: 2026-08-10

Device code phishing exploits legitimate OAuth flows to harvest valid access tokens, effectively neutralizing password-based MFA. This report outlines the technical mechanics of token theft and lateral movement within cloud environments. IT infrastructure defenders must implement strict OAuth consent policies, monitor for high-privilege token issuance, and deploy identity-aware proxies to validate authentication contexts before granting resource access.

___________________________________


# **[Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA](https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns)**

**PIR: 1.i**

Source: ketch Published: 2026-08-10

Attackers increasingly leverage cloud-native services like serverless functions and object storage to host phishing infrastructure, evading traditional perimeter defenses. This report details how threat actors abuse legitimate cloud APIs to dynamically generate malicious landing pages, rotate domains, and bypass DNS blacklists. Infrastructure defenders must implement cloud workload protection platforms, monitor anomalous API calls, and enforce strict egress filtering to detect and disrupt these 

___________________________________


# **[New widespread EvilTokens kit: device code phishing as-a-service](https://www.sekoia.com/blog/new-widespread-eviltokens-kit-device-code-phishing-as-a-service-part-1)**

**PIR: 1.k**

Source: ketch Published: 2026-08-10

The EvilTokens kit has evolved into a full-featured device code phishing-as-a-service platform, enabling low-skill actors to conduct sophisticated identity theft. The infrastructure supports multi-tenant phishing portals and automated token harvesting. Defenders should block known EvilTokens infrastructure, implement zero-trust identity architectures, and enforce just-in-time access controls to limit the blast radius of compromised credentials and stolen OAuth tokens.

___________________________________


# **[Tycoon2FA Returns: PhaaS Platform Survives Law Enforcement Disruption](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/03/CSA_research_note_Tycoon2FA-PhaaS-resurrection-MaaS-resilience-20260326-csa-styled.pdf)**

**PIR: 1.k**

Source: ketch Published: 2026-08-10

Despite law enforcement takedowns, the Tycoon2FA Phishing-as-a-Service platform has rapidly re-emerged, demonstrating the resilience of modern MaaS ecosystems. The kit facilitates real-time session hijacking and MFA bypass by proxying authentication requests. Infrastructure teams must enforce phishing-resistant MFA standards like FIDO2, monitor for anomalous authentication proxy traffic, and implement conditional access policies that restrict login locations and device compliance to mitigate ses

___________________________________


# **[Inside Kali365, a Device Code Phishing Ecosystem | Huntress](https://www.huntress.com/blog/kali365-device-code-phishing-kit)**

**PIR: 1.k**

Source: ketch Published: 2026-08-10

Kali365 operates as a comprehensive device code phishing ecosystem, offering attackers ready-made infrastructure, victim tracking, and automated credential harvesting. This analysis reveals how the platform scales identity attacks across multiple cloud providers. Infrastructure teams must integrate threat intelligence feeds tracking Kali365 indicators, monitor cloud audit logs for suspicious consent grants, and enforce strict application allow-listing to prevent unauthorized OAuth integrations.

___________________________________


# **[The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations](https://itsecurityguru.org/2026/05/27/the-ai-phishing-revolution-from-spray-and-pray-to-autonomous-operations)**

**PIR: 1.j**

Source: ketch Published: 2026-08-10

Generative AI has transformed phishing from broad, low-success campaigns into highly targeted, autonomous operations. This analysis explores how LLMs craft context-aware lures, automate multi-stage social engineering, and dynamically adapt to victim responses. Defenders should prioritize AI-driven email security gateways, implement continuous user training focused on AI-generated content detection, and deploy behavioral analytics to identify subtle deviations in communication patterns that signa

___________________________________


# **[Storm-2372 conducts device code phishing campaign | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/)**

**PIR: 1.a**

Source: ketch Published: 2026-08-10

The APT group Storm-2372 has adopted device code phishing to target government and defense contractors, leveraging legitimate Microsoft 365 flows to bypass security controls. This campaign highlights the convergence of state-sponsored threat actors and commercial phishing kits. Defenders should monitor for anomalous device code usage patterns, implement advanced identity protection rules, and conduct regular access reviews to detect and revoke compromised service principals and user tokens.

___________________________________


# **[CVE-2025-32736](https://nvd.nist.gov/vuln/detail/CVE-2025-32736)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-10

Cross-Site Request Forgery weaknesses in the Administrative Console of PingFederate versions before version 13.1 may allow actors to perform unauthorized actions via specially-crafted links triggered by administrators with active sessions.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-72564 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-72564)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-10

Breaks multi-tenant isolation in a zero-trust identity platform, enabling cross-organizational lateral movement via token reuse.

*Deep dive: `TIER_2_CVE-2026-72564.md`*

___________________________________


# **[CVE-2026-72575 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-72575)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-10

Unauthenticated authorization bypass in daptin’s core permission middleware directly compromises OAuth/OIDC and JWT-based identity management, impacting Digital Identity infrastructure.

*Deep dive: `TIER_2_CVE-2026-72575.md`*

___________________________________


# **[CVE-2026-10754 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-10754)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-10

Session/crypto signature bypass in Pega Platform directly threatens government citizen portals and financial services workflows relying on its case management and authentication controls.

*Deep dive: `TIER_2_CVE-2026-10754.md`*

___________________________________


# **[CVE-2026-47754 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-47754)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-10

Unauthenticated path traversal in Metacat 2.x threatens federally funded scientific data repositories (NSF DataONE, USGS, NOAA), directly impacting Government sector research infrastructure and sensitive data assets.

*Deep dive: `TIER_2_CVE-2026-47754.md`*

___________________________________


# **[CVE-2026-72584 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-72584)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-10

Directly compromises OTP-based account recovery and authentication flows in a BaaS framework, impacting Digital Identity integrity and access control.

*Deep dive: `TIER_2_CVE-2026-72584.md`*

___________________________________


# **[CVE-2026-72688 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-72688)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-10

Unauthenticated remote read of legally binding contracts in a public-facing e-signature platform directly impacts government procurement, citizen services, and financial compliance workflows.

*Deep dive: `TIER_2_CVE-2026-72688.md`*

___________________________________


# **[CVE-2026-72692 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-72692)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-10

Cross-sector e-signature infrastructure flaw enabling unauthenticated document decline and audit trail falsification, impacting Government, Finance, and Healthcare compliance workflows.

*Deep dive: `TIER_2_CVE-2026-72692.md`*

___________________________________


# **[CVE-2026-66738 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-66738)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-10

RCE in SPIP CMS, widely deployed by government and civic organizations for public-facing portals, posing a direct risk to institutional web infrastructure.

*Deep dive: `TIER_2_CVE-2026-66738.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine