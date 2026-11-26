# **Infrastructure Daily Brief: 2026-11-25**

**Infrastructure Daily Report TLP:GREEN Alert Id: 3249ffca 2026-11-26 13:43:01**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-136706 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-82489 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-82491 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-123879 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-134642 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-134792 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-135142 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-135226 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-136632 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-137077 (Tier 2)                                                         | 3.k      |
| Threats    | The hidden network: Inside the phishing infrastructure ecosystem powering global | 1.a      |
| Threats    | Joint advisory: state-sponsored spear-phishing campaigns targeting critical infr | 1.d      |
| Threats    | Unmasking EvilTokens: Getting to the root of device code phishing                | 1.b      |
| Threats    | The risks of device code authentication for AI coding agents                     | 1.c      |
| Threats    | Tracking BigBear 2.0 Evilginx2 Phishing Campaign                                 | 1.b      |
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.c      |
| Threats    | Device Code Phishing: An Evolving Technique Impacting SLTTs                      | 1.b      |
| Threats    | Storm-2372 conducts device code phishing campaign                                | 1.f      |
| Threats    | CVE-2026-124284                                                                  | 1.b      |
| Threats    | CVE-2026-136165                                                                  | 1.b      |
| Threats    | CVE-2026-80283                                                                   | 1.b      |
| Threats    | CVE-2026-80247                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime](https://www.microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime/)**

**PIR: 1.a**

Source: ketch Published: 2026-11-25

Examines the underground infrastructure supporting global phishing operations, detailing domain generation algorithms, bulletproof hosting networks, and proxy chains used to evade takedowns. Infrastructure defenders can leverage these insights to enhance DNS sinkholing, implement advanced threat intelligence feeds, and harden perimeter defenses against rapidly rotating malicious endpoints.

___________________________________


# **[Joint advisory: state-sponsored spear-phishing campaigns targeting critical infrastructure](https://suvat.uk/blog/five-eyes-advisory.html)**

**PIR: 1.d**

Source: ketch Published: 2026-11-25

Details coordinated Five Eyes intelligence on advanced spear-phishing tactics targeting critical infrastructure sectors. The advisory outlines malicious document payloads, credential harvesting techniques, and lateral movement strategies employed by state actors. Defenders should prioritize email gateway filtering, endpoint detection tuning, and strict access controls for OT/IT convergence points.

___________________________________


# **[Unmasking EvilTokens: Getting to the root of device code phishing](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/)**

**PIR: 1.b**

Source: ketch Published: 2026-11-25

Analyzes the EvilTokens framework, which abuses OAuth device code flows to bypass multi-factor authentication. The report breaks down token interception mechanisms, session hijacking vectors, and mitigation strategies for identity providers. Infrastructure teams must enforce conditional access policies, monitor for anomalous device code requests, and restrict public-facing authentication endpoints.

___________________________________


# **[The risks of device code authentication for AI coding agents](https://microsoft.com/en-us/security/blog/2026/11/17/the-risks-of-device-code-authentication-for-ai-coding-agents)**

**PIR: 1.c**

Source: ketch Published: 2026-11-25

Explores how AI-driven development tools leverage device code flows, creating new attack surfaces for credential theft and unauthorized access. The article highlights risks of automated agent authentication, token persistence, and supply chain compromise. Defenders should implement strict agent identity management, rotate credentials frequently, and audit AI tool authentication scopes.

___________________________________


# **[Tracking BigBear 2.0 Evilginx2 Phishing Campaign](https://www.cloudsek.com/blog/tracking-bigbear-2-0-evilginx2-phishing-campaign)**

**PIR: 1.b**

Source: ketch Published: 2026-11-25

Chronicles a large-scale phishing campaign utilizing Evilginx2 reverse proxy technology to harvest credentials and session cookies. The analysis covers infrastructure patterns, domain registration tactics, and evasion techniques. Network defenders can improve detection by monitoring for proxy-based traffic anomalies, implementing certificate pinning, and deploying advanced URL filtering.

___________________________________


# **[Inside an AI‑enabled device code phishing campaign](https://microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026)**

**PIR: 1.c**

Source: ketch Published: 2026-11-25

Investigates a novel campaign combining generative AI with device code phishing to automate credential harvesting at scale. The report details AI-generated landing pages, dynamic QR code generation, and real-time token forwarding. Identity teams should deploy behavioral analytics, restrict device code usage to trusted networks, and educate users on QR code authentication risks.

___________________________________


# **[Device Code Phishing: An Evolving Technique Impacting SLTTs](https://cisecurity.org/insights/blog/device-code-phishing-evolving-technique-impacting-sltts)**

**PIR: 1.b**

Source: ketch Published: 2026-11-25

Examines how state, local, tribal, and territorial governments face targeted device code phishing attacks exploiting legacy identity systems. The guide provides architectural recommendations for modernizing authentication flows, implementing zero-trust principles, and monitoring for unauthorized device registrations. Infrastructure planners should prioritize identity governance and secure remote access frameworks.

___________________________________


# **[Storm-2372 conducts device code phishing campaign](https://microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign)**

**PIR: 1.f**

Source: ketch Published: 2026-11-25

Documents a persistent threat actor leveraging device code phishing to infiltrate government and defense networks. The analysis covers campaign timelines, infrastructure reuse, and post-compromise tactics. Defenders should correlate authentication logs with threat intelligence, enforce strict MFA policies, and isolate compromised identity accounts immediately.

___________________________________


# **[CVE-2026-124284](https://nvd.nist.gov/vuln/detail/CVE-2026-124284)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-24

A critical security vulnerability affects certain authentication methods in Genetec Security Center, including external identity providers using OpenID Connect (OIDC) or SAML 2.0, and Active Directory Federation Services (AD FS) using WS-Trust or WS-Federation.
Under specific conditions, successful exploitation may allow an unauthenticated attacker to gain unauthorized access to the system with the privileges of an affected user. Successful exploitation requires a specific combination of conditi

___________________________________


# **[CVE-2026-136165](https://nvd.nist.gov/vuln/detail/CVE-2026-136165)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-24

Fider before 0.40.0 contains an account takeover vulnerability that allows unauthenticated attackers to sign in as existing users by linking OAuth identities through unverified email matches. Attackers can use a Google account carrying an unverified copy of a victim's email, including a tenant administrator's, to bind their identity via the OAuthToken handler and obtain persistent session access.

___________________________________


# **[CVE-2026-80283](https://nvd.nist.gov/vuln/detail/CVE-2026-80283)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-25

Dell Secure Connect Gateway (SCG) Virtual Edition, versions prior to 5.36.00.16, contains a Missing Authentication for Critical Function vulnerability. An attacker with local access could potentially exploit this vulnerability, leading to unauthorized disclosure of sensitive information, unauthorized modification of system resources, and execution of privileged actions that could lead to compromise of the appliance.

___________________________________


# **[CVE-2026-80247](https://nvd.nist.gov/vuln/detail/CVE-2026-80247)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-25

Dell Secure Connect Gateway (SCG) Virtual Edition, versions prior to 5.36.00.16, contains a Missing Authentication for Critical Function vulnerability. An attacker with local access to the appliance could potentially exploit this vulnerability, leading to unauthorized access to sensitive information, modification of protected resources, and execution of privileged operations within the appliance security context, potentially resulting in compromise of confidentiality, integrity, and availability

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-136706 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-136706)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-25

Critical unauthenticated SQLi in the eGov Foundation DIGIT platform directly compromises Government citizen services and Digital Identity/access management functions.

*Deep dive: `TIER_2_CVE-2026-136706.md`*

___________________________________


# **[CVE-2026-82489 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-82489)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-25

Unauthenticated RCE in openIMIS directly compromises national health insurance and government healthcare data infrastructure.

*Deep dive: `TIER_2_CVE-2026-82489.md`*

___________________________________


# **[CVE-2026-82491 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-82491)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-25

Impacts national health insurance platforms (Healthcare/Government) by enabling JWT key extraction and silent admin session forgery, undermining core identity and access controls.

*Deep dive: `TIER_2_CVE-2026-82491.md`*

___________________________________


# **[CVE-2026-123879 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-123879)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-25

Core Ubuntu authentication daemon vulnerability enabling UID/GID hijacking and account takeover, directly impacting Digital Identity and enterprise IdP integrations.

*Deep dive: `TIER_2_CVE-2026-123879.md`*

___________________________________


# **[CVE-2026-134642 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-134642)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-25

General infrastructure risk: widely deployed Linux administration tool used in enterprise and government IT, with unauthenticated root RCE impacting backend server management.

*Deep dive: `TIER_2_CVE-2026-134642.md`*

___________________________________


# **[CVE-2026-134792 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-134792)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-25

General web framework vulnerability impacting public sector and civic tech stacks by enabling MITM attacks on backend API calls and credential interception.

*Deep dive: `TIER_2_CVE-2026-134792.md`*

___________________________________


# **[CVE-2026-135142 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-135142)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-25

General web infrastructure flaw in the Laravel-MongoDB stack that risks mass data corruption across user collections in public-facing identity, finance, and government portals.

*Deep dive: `TIER_2_CVE-2026-135142.md`*

___________________________________


# **[CVE-2026-135226 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-135226)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-25

TIER 2 data integrity flaw in MongoDB Ruby driver impacts Finance, Government, and Healthcare systems that parse untrusted Extended JSON, risking transaction and record manipulation.

*Deep dive: `TIER_2_CVE-2026-135226.md`*

___________________________________


# **[CVE-2026-136632 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-136632)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-25

Widely adopted in public-sector project management; allows authenticated or anonymous users to delete projects and expose restricted data.

*Deep dive: `TIER_2_CVE-2026-136632.md`*

___________________________________


# **[CVE-2026-137077 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-137077)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-25

Foundational remote desktop library (FreeRDP) widely deployed in enterprise and government environments for secure remote access; heap corruption enables RCE/DoS.

*Deep dive: `TIER_2_CVE-2026-137077.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine