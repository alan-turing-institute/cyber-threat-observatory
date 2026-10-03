# **Infrastructure Daily Brief: 2026-10-02**

**Infrastructure Daily Report TLP:GREEN Alert Id: 21a9499e 2026-10-03 09:38:56**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-103602 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-104637 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-103600 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-104609 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-63568 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-63573 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-104430 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-104431 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-63574 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-63575 (Tier 2)                                                          | 3.k      |
| Threats    | Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA      | 1.e      |
| Threats    | AI-Generated Lures Behind Microsoft Cloud Account Takeovers                      | 1.b      |
| Threats    | Microsoft Entra Passkey Phishing: How Fake IT Calls Abuse Device Codes and MFA P | 1.c      |
| Threats    | AI-Enabled Device Code Phishing Campaign Abuses Device Code Sign-In Flow         | 1.g      |
| Threats    | OAuth Device Code Phishing: M365 Defense Guide                                   | 1.g      |
| Threats    | Tycoon2FA Returns: PhaaS Platform Survives Law Enforcement Disruption            | 1.f      |
| Threats    | The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations         | 1.d      |
| Threats    | GhostCode attackers abuse device codes to take over Microsoft 365 accounts       | 1.g      |
| Threats    | CVE-2026-76142                                                                   | 1.b      |
| Threats    | CVE-2026-94276                                                                   | 1.b      |
| Threats    | CVE-2026-103877                                                                  | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA](https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns)**

**PIR: 1.e**

Source: ketch Published: 2026-10-02

Threat actors increasingly leverage ephemeral cloud resources, serverless functions, and containerized environments to host phishing infrastructure. This report details how attackers bypass traditional IP-based blocklists by dynamically provisioning domains and hosting assets across major cloud providers, forcing defenders to adopt cloud-native telemetry and behavioral analysis for detection.

___________________________________


# **[AI-Generated Lures Behind Microsoft Cloud Account Takeovers](https://labs.cloudsecurityalliance.org/research/csa-research-note-genai-passkey-phishing-msft-20260914-csa-s)**

**PIR: 1.b**

Source: ketch Published: 2026-10-02

Generative AI models are now crafting highly personalized, context-aware phishing lures that successfully trick users into surrendering Microsoft cloud credentials. The analysis reveals how AI-driven content generation reduces campaign development time while increasing success rates, necessitating advanced email security gateways and user training focused on AI-generated deception patterns.

___________________________________


# **[Microsoft Entra Passkey Phishing: How Fake IT Calls Abuse Device Codes and MFA Prompts](https://windowsforum.com/news/microsoft-entra-passkey-phishing-how-fake-it-calls-abuse-device-codes-and-mfa-prompts.446452)**

**PIR: 1.c**

Source: ketch Published: 2026-10-02

Attackers are combining vishing with Microsoft Entra device code flows to bypass passkey and MFA protections. By impersonating IT support, adversaries guide users to enter legitimate device codes on attacker-controlled endpoints, effectively hijacking authentication sessions. Infrastructure defenders must monitor for anomalous device code usage and implement conditional access policies to mitigate this hybrid attack vector.

___________________________________


# **[AI-Enabled Device Code Phishing Campaign Abuses Device Code Sign-In Flow](https://captechgroup.com/threat-intelligence-center/ai-enabled-device-code-phishing-campaign-abuses-de-81a334)**

**PIR: 1.g**

Source: ketch Published: 2026-10-02

This campaign exploits the OAuth 2.0 device authorization grant by using AI to dynamically generate convincing login prompts. Attackers target enterprise users, capturing valid tokens that bypass traditional MFA. The report provides technical indicators, flow analysis, and mitigation strategies for securing device code endpoints and detecting token theft in cloud identity environments.

___________________________________


# **[OAuth Device Code Phishing: M365 Defense Guide](https://protego.me/blog/oauth-device-code-phishing-mfa-bypass-microsoft-365)**

**PIR: 1.g**

Source: ketch Published: 2026-10-02

A comprehensive defense guide addressing the rising threat of OAuth device code phishing against Microsoft 365 tenants. The article outlines architectural weaknesses in the device authorization flow, demonstrates real-world bypass techniques, and provides actionable configuration steps for Conditional Access, token lifetime restrictions, and monitoring to protect infrastructure credentials.

___________________________________


# **[Tycoon2FA Returns: PhaaS Platform Survives Law Enforcement Disruption](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/03/CSA_research_note_Tycoon2FA-PhaaS-resurrection-MaaS-resilience-20260326-csa-styled.pdf)**

**PIR: 1.f**

Source: ketch Published: 2026-10-02

Despite coordinated takedowns, the Tycoon2FA Phishing-as-a-Service platform has rapidly reconstituted using decentralized hosting and automated infrastructure provisioning. This research examines the platform's resilience mechanisms, subscription model, and how it enables low-skill actors to launch sophisticated MFA-bypass campaigns, highlighting the need for proactive threat intelligence sharing.

___________________________________


# **[The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations](https://itsecurityguru.org/2026/05/27/the-ai-phishing-revolution-from-spray-and-pray-to-autonomous-operations)**

**PIR: 1.d**

Source: ketch Published: 2026-10-02

The evolution of phishing campaigns now features fully autonomous AI agents that handle reconnaissance, payload generation, and adaptive delivery. This shift eliminates human bottlenecks, enabling continuous, multi-vector attacks against enterprise infrastructure. Defenders must transition from static rule-based defenses to AI-driven detection and automated response frameworks.

___________________________________


# **[GhostCode attackers abuse device codes to take over Microsoft 365 accounts](https://computerworld.com/article/4223889/ghostcode-attackers-abuse-device-codes-to-take-over-microsoft-365-accounts.html)**

**PIR: 1.g**

Source: ketch Published: 2026-10-02

The GhostCode threat group has weaponized Microsoft 365 device code authentication to execute large-scale account takeovers. By distributing malicious scripts that prompt users to authorize device codes, attackers harvest valid access tokens. The article details the group's infrastructure, token harvesting techniques, and recommended identity protection controls for enterprise environments.

___________________________________


# **[CVE-2026-76142](https://nvd.nist.gov/vuln/detail/CVE-2026-76142)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-01

Insufficient authentication and access control on the internal-only IPC SOAP endpoint of the Genian NAC/ZTNA policy server allows an unauthenticated attacker to invoke internal functions

___________________________________


# **[CVE-2026-94276](https://nvd.nist.gov/vuln/detail/CVE-2026-94276)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-01

Improper Authentication vulnerability in Apache APISIX.

On a route using openid-connect plugin with remote introspection against an authorization server that serves multiple issuers, a token that introspects as active for one issuer may get accepted on a route restricted to another. This issue affects Apache APISIX: from 3.12.0 through 3.18.0.

Users are recommended to upgrade to version 3.19.0, which fixes the issue.

___________________________________


# **[CVE-2026-103877](https://nvd.nist.gov/vuln/detail/CVE-2026-103877)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-02

Deserialization of Untrusted Data vulnerability in Apache Directory LDAP API.



A rogue/compromised LDAP server (or pre-TLS MITM) can answer a client's loadSchema() subschema search with a schema object that contains a serialized Java class, allowing some potential RCE. 



This issue affects Apache Directory LDAP API: from 2.1.0 before 2.1.9.



Users are recommended to upgrade to version 2.1.9, which fixes the issue.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-103602 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-103602)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-02

Bypasses PKIX certificate validation in a widely used crypto library, directly undermining trust infrastructure for digital identity, finance, and government services.

*Deep dive: `TIER_2_CVE-2026-103602.md`*

___________________________________


# **[CVE-2026-104637 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-104637)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-02

Unauthenticated RCE in a Hospital Management System directly compromises patient data and clinical operations, aligning with Healthcare DPI sector.

*Deep dive: `TIER_2_CVE-2026-104637.md`*

___________________________________


# **[CVE-2026-103600 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-103600)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-02

Foundational cryptographic library for TLS/PKI underpinning Digital Identity, Finance, and Government services; unauthenticated DoS risks widespread service disruption.

*Deep dive: `TIER_2_CVE-2026-103600.md`*

___________________________________


# **[CVE-2026-104609 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-104609)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-02

Unauthenticated SQLi in a hospital management system exposes patient records and credentials, directly impacting the Healthcare sector.

*Deep dive: `TIER_2_CVE-2026-104609.md`*

___________________________________


# **[CVE-2026-63568 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-63568)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-02

Impacts foundational PKI and certificate lifecycle management (CMP/CRMF) in the Digital Identity sector, enabling remote DoS against certificate issuance and verification services.

*Deep dive: `TIER_2_CVE-2026-63568.md`*

___________________________________


# **[CVE-2026-63573 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-63573)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-02

Foundational cryptographic library flaw enabling decryption of secure communications, directly impacting Government, Finance, and Healthcare enterprise email and document exchange.

*Deep dive: `TIER_2_CVE-2026-63573.md`*

___________________________________


# **[CVE-2026-104430 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-104430)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-02

Impacts decentralized financial infrastructure (Zcash) by enabling unauthenticated consensus divergence and network stalls, disrupting transaction validation and payment availability.

*Deep dive: `TIER_2_CVE-2026-104430.md`*

___________________________________


# **[CVE-2026-104431 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-104431)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-02

Finance sector relevance: unauthenticated remote DoS disrupts Zcash node availability, impacting cryptocurrency transaction validation and ledger consensus.

*Deep dive: `TIER_2_CVE-2026-104431.md`*

___________________________________


# **[CVE-2026-63574 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-63574)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-02

Foundational .NET cryptographic library with DoS risk to OpenPGP parsing, impacting digital identity workflows like key management, email signing, and certificate services.

*Deep dive: `TIER_2_CVE-2026-63574.md`*

___________________________________


# **[CVE-2026-63575 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-63575)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-02

Foundational .NET cryptographic library with broad transitive reach across government, finance, and healthcare stacks; DoS via crafted certificate files threatens availability of regulated services.

*Deep dive: `TIER_2_CVE-2026-63575.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine