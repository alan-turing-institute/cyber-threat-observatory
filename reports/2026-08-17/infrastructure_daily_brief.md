# **Infrastructure Daily Brief: 2026-08-17**

**Infrastructure Daily Report TLP:GREEN Alert Id: 5558cce1 2026-08-18 12:10:14**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-71479 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-74878 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-74881 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-75002 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-74997 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-75479 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-19650 (Tier 2)                                                          | 3.k      |
| Threats    | OAuth Device Code Phishing: 37x Surge in Enterprise ATO                          | 1.j.3    |
| Threats    | Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA      | 1.h      |
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.i      |
| Threats    | Device Code Phishing Hits 340+ Microsoft 365 Orgs Across Five Countries ...      | 1.j.3    |
| Threats    | Microsoft 365 Device Code Phishing Campaign Bypasses Password Theft ...          | 1.d      |
| Threats    | Storm-2372 conducts device code phishing campaign                                | 1.a      |
| Threats    | Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA                  | 1.e      |
| Threats    | Three Active Microsoft 365 Phishing Campaigns Targeting Schools and Government A | 1.a      |
| Threats    | CVE-2026-14564                                                                   | 1.b      |
| Threats    | CVE-2026-40144                                                                   | 1.b      |
| Threats    | CVE-2026-40145                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[OAuth Device Code Phishing: 37x Surge in Enterprise ATO](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/04/CSA_research_note_oauth-device-code-phishing-surge_20260405-csa-styled.pdf)**

**PIR: 1.j.3**

Source: ketch Published: 2026-08-17

Enterprise account takeover attacks leveraging OAuth device code flows have surged by 37x. Attackers exploit legitimate authentication mechanisms to bypass MFA and harvest long-lived access tokens. Defenders should monitor for unusual device code grant requests, restrict OAuth app permissions, and implement conditional access policies that validate device compliance and user context during authentication flows.

___________________________________


# **[Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA](https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns)**

**PIR: 1.h**

Source: ketch Published: 2026-08-17

Threat actors increasingly leverage cloud-native services like serverless functions, object storage, and CDNs to host phishing infrastructure. This approach bypasses traditional domain-based blocklists and complicates takedown efforts. IT defenders must implement cloud security posture management, monitor for anomalous API usage, and enforce strict egress controls to mitigate these evolving infrastructure-level phishing tactics.

___________________________________


# **[Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.i**

Source: ketch Published: 2026-08-17

This campaign demonstrates how threat actors combine AI-generated lures with automated device code phishing to scale account compromises. By dynamically generating authentication prompts and mimicking legitimate app interfaces, attackers achieve higher success rates. Infrastructure teams should deploy AI-aware email filtering, monitor for rapid sequential authentication attempts, and enforce step-up authentication for sensitive OAuth grants.

___________________________________


# **[Device Code Phishing Hits 340+ Microsoft 365 Orgs Across Five Countries ...](https://thehackernews.com/2026/03/device-code-phishing-hits-340-microsoft.html)**

**PIR: 1.j.3**

Source: ketch Published: 2026-08-17

Over 340 Microsoft 365 organizations have been targeted by device code phishing campaigns exploiting OAuth abuse. The attacks enable persistent token hijacking and account takeover without traditional credential theft. Defenders must audit registered OAuth applications, disable unnecessary device code grants, and leverage Microsoft Graph alerts to detect anomalous authentication patterns across tenant environments.

___________________________________


# **[Microsoft 365 Device Code Phishing Campaign Bypasses Password Theft ...](https://cybersecuritynews.com/microsoft-365-device-code-phishing-campaign/)**

**PIR: 1.d**

Source: ketch Published: 2026-08-17

ReversingLabs documented a sophisticated campaign using business-themed lures and polished phishing kits to exploit Microsoft's Device Authorization Grant flow. The attack bypasses traditional password theft by leveraging legitimate OAuth mechanisms for near-invisible account takeover. Defenders should enforce strict OAuth consent policies, monitor for high-frequency device code requests, and deploy conditional access rules that require compliant devices.

___________________________________


# **[Storm-2372 conducts device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/)**

**PIR: 1.a**

Source: ketch Published: 2026-08-17

Storm-2372 has been conducting a sustained device code phishing campaign since August 2024, using lures that mimic popular messaging platforms. The group targets enterprise users to bypass MFA and establish persistent access. IT defenders should analyze email headers for spoofed messaging domains, monitor for unfamiliar OAuth consent prompts, and implement user training focused on recognizing app-mimicking authentication requests.

___________________________________


# **[Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA](https://tempmail.ninja/blog/laundry-bear-zimbra-phishing)**

**PIR: 1.e**

Source: ketch Published: 2026-08-17

CISA warns of a zero-click phishing campaign targeting Zimbra email servers, exploiting vulnerabilities to deliver payloads without user interaction. This threat bypasses traditional email security gateways and user training. Defenders must prioritize patching Zimbra instances, implement network segmentation for mail servers, and deploy endpoint detection to catch post-exploitation activity.

___________________________________


# **[Three Active Microsoft 365 Phishing Campaigns Targeting Schools and Government Agencies](https://forsyteit.com/three-active-microsoft-365-phishing-campaigns-targeting-schools-and-government-agencies)**

**PIR: 1.a**

Source: ketch Published: 2026-08-17

Active phishing campaigns are specifically targeting educational and government Microsoft 365 tenants. Attackers use tailored lures to harvest credentials and deploy malicious payloads. Infrastructure defenders in these sectors should prioritize zero-trust network access, enforce multi-factor authentication with phishing-resistant methods, and regularly audit third-party application integrations to prevent unauthorized data exfiltration.

___________________________________


# **[CVE-2026-14564](https://nvd.nist.gov/vuln/detail/CVE-2026-14564)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-17

Insufficiently Protected Credentials vulnerability in Innotim Software Telecommunications and Consulting Trade Ltd. Co. Logsign SIEM allows Retrieve Embedded Sensitive Data.

This issue affects Logsign SIEM: from 6.4.97 before 6.4.114.

___________________________________


# **[CVE-2026-40144](https://nvd.nist.gov/vuln/detail/CVE-2026-40144)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-17

A memory-corruption vulnerability exists in a kernel-mode component of BeyondTrust Endpoint Privilege Management (Windows deployments) prior to version 26.1.2. Insufficient validation of input processed by the component may result in memory being accessed outside its intended bounds.

___________________________________


# **[CVE-2026-40145](https://nvd.nist.gov/vuln/detail/CVE-2026-40145)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-17

A vulnerability exists in the interaction between a Endpoint Privilege Management (Windows Deployment) support utility and the agent's tamper protection controls. Under certain conditions, the protections applied to the utility process may not be enforced as intended.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-71479 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-71479)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-17

TIER 2 integer overflow in an AI gateway billing system enables authenticated users to manipulate account credits, directly impacting financial operations and fund settlement (Finance sector).

*Deep dive: `TIER_2_CVE-2026-71479.md`*

___________________________________


# **[CVE-2026-74878 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-74878)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-17

Bypasses TOTP rate limiting in authentication libraries, enabling brute-force attacks against public-facing identity endpoints.

*Deep dive: `TIER_2_CVE-2026-74878.md`*

___________________________________


# **[CVE-2026-74881 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-74881)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-17

TIER 2 CORS misconfiguration in a Digital Identity/PKI key-management server that enables authenticated cross-origin session hijacking and cryptographic metadata exposure.

*Deep dive: `TIER_2_CVE-2026-74881.md`*

___________________________________


# **[CVE-2026-75002 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-75002)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-17

Core webmail infrastructure for government, healthcare, and finance sectors; compromise risks citizen/patient communications and identity verification workflows.

*Deep dive: `TIER_2_CVE-2026-75002.md`*

___________________________________


# **[CVE-2026-74997 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-74997)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-17

General infrastructure webmail platform explicitly tied to cross-sector DPI operations (Digital Identity recovery, Finance alerts, Healthcare portals, Government citizen services).

*Deep dive: `TIER_2_CVE-2026-74997.md`*

___________________________________


# **[CVE-2026-75479 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-75479)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-17

Unauthenticated authentication bypass in enterprise BI platform risks exposure of sensitive internal reports and tokens in regulated/government environments.

*Deep dive: `TIER_2_CVE-2026-75479.md`*

___________________________________


# **[CVE-2026-19650 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-19650)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-17

TIER 2 CSRF in GitLab CE/EE GraphQL API impacts foundational DevOps/CI-CD infrastructure widely deployed across regulated and public-sector digital service pipelines.

*Deep dive: `TIER_2_CVE-2026-19650.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine