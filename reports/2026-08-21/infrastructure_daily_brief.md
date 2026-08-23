# **Infrastructure Daily Brief: 2026-08-21**

**Infrastructure Daily Report TLP:GREEN Alert Id: f497b709 2026-08-22 23:54:46**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                      | PIR(s)   |
|------------|-----------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-54789 (Tier 2)                                                     | 3.k      |
| Cyber News | CVE-2026-77806 (Tier 1)                                                     | 3.k      |
| Cyber News | CVE-2026-74252 (Tier 2)                                                     | 3.k      |
| Cyber News | CVE-2026-76155 (Tier 2)                                                     | 3.k      |
| Cyber News | CVE-2026-76157 (Tier 2)                                                     | 3.k      |
| Cyber News | CVE-2026-76158 (Tier 2)                                                     | 3.k      |
| Cyber News | CVE-2026-69502 (Tier 2)                                                     | 3.k      |
| Threats    | OAuth Device Code Phishing: 37x Surge in Enterprise ATO                     | 1.f      |
| Threats    | Inside an AI‑enabled device code phishing campaign                          | 1.g      |
| Threats    | Microsoft 365 Device Code Phishing Campaign Bypasses Password Theft ...     | 1.f      |
| Threats    | Tycoon2FA Returns: PhaaS Platform Survives Law Enforcement Disruption       | 1.j.2    |
| Threats    | Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA | 1.f      |
| Threats    | Device Code Phishing Hits 340+ Microsoft 365 Orgs Across Five Countries ... | 1.d      |
| Threats    | Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA             | 1.i      |
| Threats    | The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations    | 1.g      |
| Threats    | CVE-2026-69836                                                              | 1.b      |
| Threats    | CVE-2026-69851                                                              | 1.b      |
| Threats    | CVE-2026-53424                                                              | 1.b      |
| Threats    | CVE-2026-76633                                                              | 1.b      |
| Threats    | CVE-2026-53425                                                              | 1.b      |
| Threats    | CVE-2026-49217                                                              | 1.b      |
| Threats    | CVE-2026-19611                                                              | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[OAuth Device Code Phishing: 37x Surge in Enterprise ATO](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/04/CSA_research_note_oauth-device-code-phishing-surge_20260405-csa-styled.pdf)**

**PIR: 1.f**

Source: ketch Published: 2026-08-21

Enterprise account takeover incidents have surged 37x due to OAuth device code phishing. Attackers exploit the Device Authorization Grant flow to bypass traditional password theft and MFA. This report details infrastructure indicators, token persistence mechanisms, and mitigation strategies for identity administrators managing cloud environments.

___________________________________


# **[Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.g**

Source: ketch Published: 2026-08-21

A new wave of device code phishing shows how threat actors are scaling account compromise using AI and end‑to‑end automation. This campaign goes beyond traditional phishing by generating live authentication codes on demand, enabling higher success rates and sustained post‑compromise access. Defenders should monitor for anomalous OAuth consent grants.

___________________________________


# **[Microsoft 365 Device Code Phishing Campaign Bypasses Password Theft ...](https://cybersecuritynews.com/microsoft-365-device-code-phishing-campaign/)**

**PIR: 1.f**

Source: ketch Published: 2026-08-21

Analysts at ReversingLabs identified and documented this active campaign, noting that it combines realistic business-themed lure emails, a polished phishing kit, and Microsoft's own Device Authorization Grant flow to carry out a near-invisible account takeover. Infrastructure teams must implement conditional access policies that restrict device code flows.

___________________________________


# **[Tycoon2FA Returns: PhaaS Platform Survives Law Enforcement Disruption](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/03/CSA_research_note_Tycoon2FA-PhaaS-resurrection-MaaS-resilience-20260326-csa-styled.pdf)**

**PIR: 1.j.2**

Source: ketch Published: 2026-08-21

The Tycoon2FA Phishing-as-a-Service platform has resurfaced following law enforcement takedowns, demonstrating remarkable infrastructure resilience. The updated MaaS architecture leverages decentralized hosting and automated 2FA interception proxies. Security operations centers should update threat intelligence feeds to block newly registered C2 domains.

___________________________________


# **[Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA](https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns)**

**PIR: 1.f**

Source: ketch Published: 2026-08-21

Modern phishing operations increasingly leverage cloud-native services like serverless functions, object storage, and managed DNS to host malicious payloads and evade traditional perimeter defenses. This analysis maps the infrastructure supply chain abused by threat actors and provides detection rules for cloud workload protection platforms.

___________________________________


# **[Device Code Phishing Hits 340+ Microsoft 365 Orgs Across Five Countries ...](https://thehackernews.com/2026/03/device-code-phishing-hits-340-microsoft.html)**

**PIR: 1.d**

Source: ketch Published: 2026-08-21

Device code phishing targets 340+ Microsoft 365 orgs since Feb 2026 via OAuth abuse, enabling persistent token hijacking and account takeover. The campaign demonstrates how attackers leverage legitimate authentication flows to maintain long-term access. Defenders should audit OAuth app permissions and deploy identity threat detection solutions.

___________________________________


# **[Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA](https://tempmail.ninja/blog/laundry-bear-zimbra-phishing)**

**PIR: 1.i**

Source: ketch Published: 2026-08-21

CISA has issued an alert regarding a zero-click phishing campaign targeting Zimbra email servers. The Laundry Bear group exploits unpatched authentication flaws to inject malicious payloads directly into user inboxes, bypassing traditional email gateways. Infrastructure administrators must prioritize patching and monitor for anomalous server-side script execution.

___________________________________


# **[The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations](https://itsecurityguru.org/2026/05/27/the-ai-phishing-revolution-from-spray-and-pray-to-autonomous-operations)**

**PIR: 1.g**

Source: ketch Published: 2026-08-21

Generative AI has transformed phishing from broad campaigns into highly targeted, autonomous operations. Attackers now use LLMs to craft context-aware lures, automate infrastructure provisioning, and dynamically adapt to security controls. IT defenders must shift from signature-based filtering to behavioral analytics and user interaction telemetry.

___________________________________


# **[CVE-2026-69836](https://nvd.nist.gov/vuln/detail/CVE-2026-69836)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-20

Deserialization of untrusted data in Microsoft Entra ID allows an unauthorized attacker to execute code over a network.

___________________________________


# **[CVE-2026-69851](https://nvd.nist.gov/vuln/detail/CVE-2026-69851)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-20

Server-side request forgery (ssrf) in Azure Active Directory allows an authorized attacker to elevate privileges over a network.

___________________________________


# **[CVE-2026-53424](https://nvd.nist.gov/vuln/detail/CVE-2026-53424)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-20

Authentication Bypass by Capture-replay vulnerability in dropbox samly allows an attacker to authenticate as the subject of a captured SAML assertion by resubmitting it.

Samly.Helper.decode_idp_auth_resp/3 in lib/samly/helper.ex calls esaml_sp:validate_assertion/2, whose default duplicate detector is a no-op. The /3 arity accepting a DuplicateFun exists in esaml and implements the check, but Samly never calls it and offers no configuration to supply one, so the SAML 2.0 Web Browser SSO Profile 

___________________________________


# **[CVE-2026-76633](https://nvd.nist.gov/vuln/detail/CVE-2026-76633)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-20

WeGIA before 3.9.2 contains an authorization bypass vulnerability in the password change flow that allows any authenticated user to change their account password without providing existing credentials by exploiting the unconditional exclusion of the alterarSenha method from permission checks in controle/control.php. Attackers can manipulate the redir parameter to point to alterar_senha.php, routing through verificarSenhaConfig() instead of verificarSenha() to bypass current password verification

___________________________________


# **[CVE-2026-53425](https://nvd.nist.gov/vuln/detail/CVE-2026-53425)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-20

Insufficient Verification of Data Authenticity vulnerability in dropbox samly allows an attacker to establish an authenticated session using a SAML response the service provider never requested.

Samly.SPHandler.validate_authresp/3 in lib/samly/sp_handler.ex validates a SAML response for the SP-initiated flow by comparing only the RelayState value, the IdP identifier, and the presence of a target URL held in the session. It never compares SubjectConfirmationData/@InResponseTo against the ID of t

___________________________________


# **[CVE-2026-49217](https://nvd.nist.gov/vuln/detail/CVE-2026-49217)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-20

Mailu is a mail server as a set of Docker images. Prior to version 2024.06.52, a missing authorization check in the Mailu admin REST API allows any unauthenticated attacker to remove any potential IP restriction or update the comment field from any existing user token provided the REST API is enabled. Upgrade to Mailu 2024.06.52 to receive a patch or, as a workaround, turn the REST API off.

___________________________________


# **[CVE-2026-19611](https://nvd.nist.gov/vuln/detail/CVE-2026-19611)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-20

A flaw was found in WildFly Elytron. Password hashing and verification normalize input with Unicode NFKC, which can collapse fullwidth characters to ASCII equivalents. A remote attacker can more easily guess affected passwords by using an ASCII-only dictionary against accounts whose passwords were intended to include those non-ASCII characters, leading to unauthorized access.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-54789 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-54789)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-21

Digital Identity: Unauthenticated DoS in mod_auth_openidc state-cookie parser disrupts public-facing OpenID Connect authentication flows.

*Deep dive: `TIER_2_CVE-2026-54789.md`*

___________________________________


# **[CVE-2026-77806 (Tier 1)](https://nvd.nist.gov/vuln/detail/CVE-2026-77806)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-21

Unauthenticated RCE in SPIP CMS, widely deployed across French government and public administration websites, with confirmed in-the-wild exploitation.

*Deep dive: `TIER_1_CVE-2026-77806.md`*

___________________________________


# **[CVE-2026-74252 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-74252)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-21

Finance sector relevance: Stored XSS in J2Store guest checkout allows unauthenticated injection of payment-skimming scripts, compromising transaction integrity and customer financial data.

*Deep dive: `TIER_2_CVE-2026-74252.md`*

___________________________________


# **[CVE-2026-76155 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-76155)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-21

Critical default credential vulnerability in a healthcare data management platform, risking full administrative access to clinical and operational data.

*Deep dive: `TIER_2_CVE-2026-76155.md`*

___________________________________


# **[CVE-2026-76157 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-76157)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-21

Healthcare sector: Unauthenticated file upload in a hospital data management platform risks RCE and PHI breaches, impacting clinical operations and compliance.

*Deep dive: `TIER_2_CVE-2026-76157.md`*

___________________________________


# **[CVE-2026-76158 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-76158)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-21

Unauthenticated path traversal in a Healthcare-sector data management platform enables arbitrary file write and potential RCE, risking clinical data integrity and PHI exposure.

*Deep dive: `TIER_2_CVE-2026-76158.md`*

___________________________________


# **[CVE-2026-69502 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-69502)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-21

Critical unauthenticated SSRF in Azure SQL Database enables cloud privilege escalation, impacting foundational data infrastructure across regulated and public-sector deployments.

*Deep dive: `TIER_2_CVE-2026-69502.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine