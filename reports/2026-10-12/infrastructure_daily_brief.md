# **Infrastructure Daily Brief: 2026-10-12**

**Infrastructure Daily Report TLP:GREEN Alert Id: f6c6389a 2026-10-13 21:25:42**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-109371 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-109372 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-109373 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-103903 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-109609 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-109638 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-109648 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-109667 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-109674 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-109575 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-109608 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-109631 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-109633 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-41510 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-109391 (Tier 2)                                                         | 3.k      |
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.d      |
| Threats    | IR Trends Q2 2026: Phishing and weaponized remote management tools ...           | 1.c      |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US        | 1.b      |
| Threats    | We Need to Talk About Device Code Phishing | Huntress                            | 1.b      |
| Threats    | SideWinder APT Credential Harvesting Campaign — PaaS Platform Abuse at Scale     | 1.i      |
| Threats    | Access granted: phishing with device code authorization for account takeover | P | 1.b      |
| Threats    | What is device code phishing, and why are Russian spies so successful at it? - A | 1.g      |
| Threats    | Russian hacker group Laundry Bear exploits Zimbra zero-click flaw to target West | 1.f      |
| Threats    | CVE-2026-53997                                                                   | 1.b      |
| Threats    | CVE-2026-84313                                                                   | 1.b      |
| Threats    | CVE-2026-108865                                                                  | 1.b      |
| Threats    | CVE-2026-85958                                                                   | 1.b      |
| Threats    | CVE-2026-85962                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.d**

Source: ketch Published: 2026-10-12

This campaign represents a major escalation in threat actor sophistication, shifting from static scripts to fully AI-driven infrastructure and end-to-end automation. Building on the Storm-2372 device code phishing activity observed in early 2025, attackers now leverage machine learning to dynamically generate convincing phishing pages, optimize delivery timing, and automate credential harvesting. IT defenders must prioritize monitoring for anomalous OAuth device code flows and implement AI-aware

___________________________________


# **[IR Trends Q2 2026: Phishing and weaponized remote management tools ...](https://blog.talosintelligence.com/ir-trends-q2-2026/)**

**PIR: 1.c**

Source: ketch Published: 2026-10-12

A persistent QR code phishing campaign targeting Australian organizations exploits compromised Microsoft 365 accounts to harvest credentials and propagate laterally via internal contact lists. Active through mid-2026, the operation leverages trusted infrastructure to bypass traditional email filters. Defenders should monitor for unusual QR code attachments, enforce strict MFA policies, and audit M365 account permissions to mitigate credential theft and internal campaign propagation.

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.b**

Source: ketch Published: 2026-10-12

Device code phishing has matured into a primary vector for identity takeover, bypassing traditional MFA by tricking users into authorizing attacker-controlled sessions. This analysis details how threat actors exploit OAuth 2.0 device authorization flows to gain persistent access without stealing passwords. Infrastructure teams must implement conditional access policies, monitor for high-frequency device code requests, and educate users on recognizing legitimate authorization prompts.

___________________________________


# **[We Need to Talk About Device Code Phishing | Huntress](https://www.huntress.com/blog/tradecraft-tuesday-device-code-phishing-explained)**

**PIR: 1.b**

Source: ketch Published: 2026-10-12

Huntress breaks down the mechanics of device code phishing, highlighting why it remains highly effective against modern identity defenses. Attackers leverage legitimate Microsoft authentication endpoints to harvest session tokens, rendering password-based MFA ineffective. The report provides actionable detection strategies, including log analysis for suspicious device code patterns and recommendations for tightening OAuth consent policies to protect enterprise infrastructure.

___________________________________


# **[SideWinder APT Credential Harvesting Campaign — PaaS Platform Abuse at Scale](https://intel.breakglass.tech/post/sidewinder-mhil-zeabur)**

**PIR: 1.i**

Source: ketch Published: 2026-10-12

The SideWinder APT group is conducting large-scale credential harvesting by abusing PaaS platforms to host phishing infrastructure at scale. By leveraging cloud deployment services, attackers rapidly provision and rotate malicious domains, evading traditional blocklists. Defenders should monitor for newly registered PaaS-hosted domains mimicking enterprise login portals and implement DNS-level filtering to disrupt this automated identity theft pipeline.

___________________________________


# **[Access granted: phishing with device code authorization for account takeover | Proofpoint US](https://www.proofpoint.com/us/blog/threat-insight/access-granted-phishing-device-code-authorization-account-takeover)**

**PIR: 1.b**

Source: ketch Published: 2026-10-12

This technical deep dive examines how attackers weaponize device code authorization flows to achieve account takeover without direct credential theft. By directing victims to legitimate Microsoft login pages, threat actors capture valid session tokens. The analysis outlines forensic indicators for SOC teams, emphasizing the need to audit OAuth application permissions and deploy real-time alerting for anomalous device code authentication events.

___________________________________


# **[What is device code phishing, and why are Russian spies so successful at it? - Ars Technica](https://arstechnica.com/information-technology/2025/02/russian-spies-use-device-code-phishing-to-hijack-microsoft-accounts/)**

**PIR: 1.g**

Source: ketch Published: 2026-10-12

Russian intelligence operatives have perfected device code phishing to hijack Microsoft accounts, exploiting the trust users place in official authentication prompts. This report explores the tradecraft behind these campaigns, including social engineering tactics and infrastructure resilience. IT defenders can learn from these state-sponsored techniques to harden identity perimeters, enforce strict conditional access rules, and improve user awareness training.

___________________________________


# **[Russian hacker group Laundry Bear exploits Zimbra zero-click flaw to target Western government, critical infrastructure](https://industrialcyber.co/cisa/russian-hacker-group-laundry-bear-exploits-zimbra-zero-click-flaw-to-target-western-government-critical-infrastructure)**

**PIR: 1.f**

Source: ketch Published: 2026-10-12

Laundry Bear leverages a zero-click vulnerability in Zimbra email servers to compromise Western government and critical infrastructure networks without user interaction. This exploit bypasses traditional phishing defenses, granting attackers direct access to email systems and sensitive communications. Infrastructure teams must prioritize patching Zimbra deployments, implement network segmentation, and monitor for lateral movement indicators following initial compromise.

___________________________________


# **[CVE-2026-53997](https://nvd.nist.gov/vuln/detail/CVE-2026-53997)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-12

Netherman Portal del Hermano (portaldelhermano.es) before 2026-10-06 contains a broken authentication vulnerability in its password-recovery flow at the POST /password/create-access and POST /password/email endpoints, allowing unauthenticated attackers to take over any member account across all tenants by exploiting the lack of rate limiting and distinct error messages that act as oracles for each of the four identity-verification factors (DNI, date of birth, phone number, last four IBAN digits)

___________________________________


# **[CVE-2026-84313](https://nvd.nist.gov/vuln/detail/CVE-2026-84313)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-12

Nginx UI is a web user interface for the Nginx web server. Prior to 2.4.1, POST /api/otp_enroll and POST /api/finish_passkey_register are registered outside RequireSecureSession and accept a normal authenticated session without verifying the current password. An attacker with a stolen JWT can bind an attacker-controlled TOTP secret when the victim has not already enabled TOTP, or can register an attacker-controlled passkey because that path has no equivalent existing-enrollment guard. These chan

___________________________________


# **[CVE-2026-108865](https://nvd.nist.gov/vuln/detail/CVE-2026-108865)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-11

AmoyLab Unla through 0.10.0 contains an authentication bypass vulnerability that allows unauthenticated attackers to obtain valid access tokens because the OAuth2 server never authenticates a resource owner. Attackers can register a client, request a code from /authorize, and exchange it at /token to access OAuth2-protected MCP prefixes, proxied upstream APIs and injected credentials.

___________________________________


# **[CVE-2026-85958](https://nvd.nist.gov/vuln/detail/CVE-2026-85958)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-12

Progress MarkLogic Server 12.x releases before 12.1.0 and 11.x releases before 11.3.7 contain an authentication validation weakness that could allow an attacker to use a token that should not be accepted by the affected server, which could result in unauthorized access.

___________________________________


# **[CVE-2026-85962](https://nvd.nist.gov/vuln/detail/CVE-2026-85962)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-12

Progress MarkLogic Server 12.x releases before 12.1.0 and 11.x releases before 11.3.7 contain an improper authentication vulnerability in SAML processing. In deployments that use SAML authentication, an unauthenticated remote attacker could cause the affected server to accept an assertion that should be rejected, potentially resulting in unauthorized access.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-109371 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-109371)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-12

Unauthenticated account lockout in ZITADEL IdAM platform impacts digital identity infrastructure and administrative access.

*Deep dive: `TIER_2_CVE-2026-109371.md`*

___________________________________


# **[CVE-2026-109372 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-109372)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-12

Critical SAML authentication bypass in ZITADEL IdP enables cross-tenant account takeover, directly impacting digital identity federation and access management infrastructure.

*Deep dive: `TIER_2_CVE-2026-109372.md`*

___________________________________


# **[CVE-2026-109373 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-109373)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-12

Critical authentication bypass in ZITADEL IdAM platform enables unauthenticated session hijacking and MFA bypass, directly impacting Digital Identity infrastructure.

*Deep dive: `TIER_2_CVE-2026-109373.md`*

___________________________________


# **[CVE-2026-103903 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-103903)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-12

General infrastructure flaw underpinning Government, Finance, and Healthcare network connectivity, enabling full administrative compromise via WinBox privilege escalation.

*Deep dive: `TIER_2_CVE-2026-103903.md`*

___________________________________


# **[CVE-2026-109609 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-109609)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-12

Authenticated SQLi in widely deployed ERPNext exposes core financial, payroll, and procurement data, directly impacting Finance and Government sector operations.

*Deep dive: `TIER_2_CVE-2026-109609.md`*

___________________________________


# **[CVE-2026-109638 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-109638)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-12

SQLi in widely deployed ERPNext exposes financial, payroll, and transactional data critical to SME and public-sector operations.

*Deep dive: `TIER_2_CVE-2026-109638.md`*

___________________________________


# **[CVE-2026-109648 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-109648)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-12

Authenticated SQLi in widely deployed ERPNext platform impacts core operational data across government, finance, and healthcare sectors.

*Deep dive: `TIER_2_CVE-2026-109648.md`*

___________________________________


# **[CVE-2026-109667 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-109667)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-12

TIER 2 privilege escalation in Frappe ERPNext enables full administrative takeover, directly threatening financial records, transaction integrity, and accounting operations critical to regulated finance and public-sector ERP deployments.

*Deep dive: `TIER_2_CVE-2026-109667.md`*

___________________________________


# **[CVE-2026-109674 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-109674)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-12

Authenticated SQLi in Frappe ERPNext threatens financial records and citizen service data in public-sector and financial deployments.

*Deep dive: `TIER_2_CVE-2026-109674.md`*

___________________________________


# **[CVE-2026-109575 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-109575)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-12

Critical authentication bypass in HAProxy Data Plane API management plane, impacting foundational load-balancing infrastructure for regulated and public digital services.

*Deep dive: `TIER_2_CVE-2026-109575.md`*

___________________________________


# **[CVE-2026-109608 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-109608)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-12

General enterprise ERP infrastructure with explicit secondary relevance to Finance and Government deployments, impacting financial records and HR data in regulated/public-sector contexts.

*Deep dive: `TIER_2_CVE-2026-109608.md`*

___________________________________


# **[CVE-2026-109631 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-109631)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-12

Tier 2 SQLi in Frappe ERPNext, a horizontal enterprise ERP frequently deployed across Finance, Government, and Healthcare sectors for core operational management.

*Deep dive: `TIER_2_CVE-2026-109631.md`*

___________________________________


# **[CVE-2026-109633 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-109633)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-12

General infrastructure ERP platform with cross-sector relevance; stored XSS enables privileged account takeover impacting financial, healthcare, and government operational data.

*Deep dive: `TIER_2_CVE-2026-109633.md`*

___________________________________


# **[CVE-2026-41510 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-41510)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-12

Foundational WAF library bypass and memory exhaustion affecting public-facing gateways deployed across regulated and civic digital services.

*Deep dive: `TIER_2_CVE-2026-41510.md`*

___________________________________


# **[CVE-2026-109391 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-109391)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-12

TIER 2 insecure deserialization in Square Squash crash reporting tool, explicitly tied to Finance sector as supporting infrastructure for payment/banking application reliability.

*Deep dive: `TIER_2_CVE-2026-109391.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine