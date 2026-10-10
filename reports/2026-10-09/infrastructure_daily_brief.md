# **Infrastructure Daily Brief: 2026-10-09**

**Infrastructure Daily Report TLP:GREEN Alert Id: ccb0bfd4 2026-10-10 09:56:20**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-108268 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-104084 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-107826 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-108107 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-108108 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-108109 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-85531 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-86405 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-107815 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-107845 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-107852 (Tier 2)                                                         | 3.k      |
| Threats    | GhostCode attackers abuse device codes to take over Microsoft 365 accounts       | 1.h      |
| Threats    | Fake IT Help Desk Phishing Campaign Hits Blackstone, Bridgewater, KKR: Detecting | 1.e      |
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.h      |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover                        | 1.h      |
| Threats    | Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA      | 1.g      |
| Threats    | The Alert Gap: Hunting an Undetected Device Code Phishing Compromise             | 1.j      |
| Threats    | n8n Weaponized for Phishing and Device Fingerprinting                            | 1.f      |
| Threats    | The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations         | 1.f      |
| Threats    | CVE-2026-14502                                                                   | 1.b      |
| Threats    | CVE-2026-107406                                                                  | 1.b      |
| Threats    | CVE-2026-107640                                                                  | 1.b      |
| Threats    | CVE-2026-108157                                                                  | 1.b      |
| Threats    | CVE-2026-16823                                                                   | 1.b      |
| Threats    | CVE-2026-19491                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[GhostCode attackers abuse device codes to take over Microsoft 365 accounts](https://computerworld.com/article/4223889/ghostcode-attackers-abuse-device-codes-to-take-over-microsoft-365-accounts.html)**

**PIR: 1.h**

Source: ketch Published: 2026-10-09

The GhostCode threat group exploits Microsoft 365 device code authentication flows to hijack user accounts, bypassing traditional email-based phishing filters. By directing victims to legitimate Microsoft login portals with pre-generated device codes, attackers capture session tokens upon approval. Infrastructure defenders should monitor for anomalous device code grant events, restrict interactive login capabilities for high-privilege accounts, and deploy identity protection tools that flag susp

___________________________________


# **[Fake IT Help Desk Phishing Campaign Hits Blackstone, Bridgewater, KKR: Detecting and Defeating MFA Credential Theft](https://securityarsenal.com/blog/fake-it-help-desk-phishing-campaign-hits-blackstone-bridgewater-kkr-detecting-and-defeating-mfa-credential-theft)**

**PIR: 1.e**

Source: ketch Published: 2026-10-09

A sophisticated phishing campaign impersonating IT help desks has targeted major financial firms, successfully bypassing MFA through real-time credential relay and social engineering. Attackers leverage urgency and authority to trick users into surrendering session tokens or approving push notifications. Infrastructure teams must enforce phishing-resistant MFA, implement conditional access policies that block help-desk credential resets, and deploy user awareness training focused on verifying su

___________________________________


# **[Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.h**

Source: ketch Published: 2026-10-09

Microsoft researchers detail a campaign combining AI-generated lures with device code authentication abuse to compromise enterprise accounts. Attackers use LLMs to craft highly personalized prompts that trick users into entering device codes on malicious sites, which are then relayed to Microsoft’s legitimate auth endpoints. Defenders must implement risk-based conditional access, monitor for rapid device code approvals, and educate users on the dangers of sharing authentication codes.

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.h**

Source: ketch Published: 2026-10-09

Device code phishing represents a significant shift in identity compromise tactics, leveraging Microsoft’s OAuth 2.0 device authorization grant to bypass email security controls. Since the phishing payload redirects to legitimate Microsoft domains, traditional URL filtering fails. Infrastructure teams should prioritize monitoring Azure AD sign-in logs for device code flows, enforce non-interactive app restrictions, and deploy identity threat detection solutions that correlate authentication anom

___________________________________


# **[Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA](https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns)**

**PIR: 1.g**

Source: ketch Published: 2026-10-09

Attackers increasingly leverage cloud-native services like serverless functions, object storage, and CDN providers to host phishing infrastructure, bypassing traditional domain reputation filters. This report details how threat actors abuse legitimate cloud APIs to dynamically generate and rotate phishing domains, complicating takedown efforts. Infrastructure defenders must implement strict egress controls, monitor for anomalous cloud resource provisioning, and integrate cloud-native telemetry i

___________________________________


# **[The Alert Gap: Hunting an Undetected Device Code Phishing Compromise](https://www.cyberproof.com/blog/the-alert-gap-how-threat-hunting-surfaced-an-undetected-device-code-phishing-compromise/)**

**PIR: 1.j**

Source: ketch Published: 2026-10-09

This analysis reveals how device code phishing campaigns often evade standard security alerts due to legitimate-looking authentication endpoints and delayed token usage. Threat hunters demonstrate techniques for identifying compromised accounts by analyzing sign-in velocity, geographic anomalies, and post-authentication lateral movement. Defenders should implement proactive hunting playbooks, tune identity alert thresholds, and integrate behavioral analytics to close detection gaps in modern ide

___________________________________


# **[n8n Weaponized for Phishing and Device Fingerprinting](https://labs.cloudsecurityalliance.org/research/csa-research-note-n8n-ai-workflow-phishing-20260416-csa-styl)**

**PIR: 1.f**

Source: ketch Published: 2026-10-09

Open-source workflow automation tools like n8n are being repurposed by threat actors to orchestrate large-scale phishing operations and collect device fingerprints. By chaining HTTP requests, data parsing, and conditional logic, attackers automate victim profiling and credential harvesting without relying on traditional botnets. Defenders should monitor for unauthorized n8n instances, restrict outbound API calls from automation platforms, and analyze network traffic for characteristic workflow-g

___________________________________


# **[The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations](https://itsecurityguru.org/2026/05/27/the-ai-phishing-revolution-from-spray-and-pray-to-autonomous-operations)**

**PIR: 1.f**

Source: ketch Published: 2026-10-09

Generative AI is transforming phishing from broad, low-success campaigns into highly targeted, autonomous operations. LLMs now craft context-aware lures, dynamically adapt to victim responses, and automate multi-stage social engineering at scale. Defenders must shift from signature-based detection to behavioral analytics, monitor for AI-generated linguistic patterns, and enforce strict email authentication alongside advanced URL sandboxing to counter these adaptive threats.

___________________________________


# **[CVE-2026-14502](https://nvd.nist.gov/vuln/detail/CVE-2026-14502)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-08

IBM DataPower Gateway 10.5.0.0 through 10.5.0.22, 10.6.1 through 10.6.6, 10.6.0.0 through 10.6.0.10, and 11.0.0.0 through 11.0.0.2 could allow a remote attacker to obtain administrative access due to failure to reject empty passwords during LDAP authentication.

___________________________________


# **[CVE-2026-107406](https://nvd.nist.gov/vuln/detail/CVE-2026-107406)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-08

Memory overflow vulnerability leading to Remote Code Execution or Denial of Service Vulnerability in NetScaler ADC.


NetScaler ADC or NetScaler Gateway must be configured as a SAML SP or SAML IdP, subject to the following version-specific requirements:



 

  *  For the following versions: Applicable only when configured as a SAML IdP:
  *  NetScaler ADC and NetScaler Gateway between 14.1-73.37 and 14.1-73.41, inclusive
  *  NetScaler ADC 14.1-FIPS between 14.1-73.37 FIPS and 14.1-73.41 FIPS, 

___________________________________


# **[CVE-2026-107640](https://nvd.nist.gov/vuln/detail/CVE-2026-107640)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-08

Integrics Enswitch 3.13 through 4.4 contains an authentication bypass vulnerability in /api/json/user/password/update/ that allows unauthenticated attackers to change account passwords by omitting the reset parameter. Attackers can target accounts with no pending reset, whose empty reset_key matches the defaulted empty value, to take over administrator accounts after enumerating valid usernames.

___________________________________


# **[CVE-2026-108157](https://nvd.nist.gov/vuln/detail/CVE-2026-108157)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-09

Pingvin Share X from 0.19.0 before 1.22.0 contains an improper authentication vulnerability that allows remote unauthenticated attackers to take over accounts by abusing automatic OAuth email linking in OAuthService.signUp(). Attackers can register a victim's unverified email on an enabled OAuth/OIDC provider, exploiting the missing email_verified check in GenericOidcProvider, to sign in as the victim including administrators while bypassing TOTP.

___________________________________


# **[CVE-2026-16823](https://nvd.nist.gov/vuln/detail/CVE-2026-16823)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-08

IBM Security Verify Access 10.0 through 10.0.9.2 and IBM Verify Identity Access 11.0 through 11.0.3 could allow a remote attacker to bypass security restrictions due to improper authentication.

___________________________________


# **[CVE-2026-19491](https://nvd.nist.gov/vuln/detail/CVE-2026-19491)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-08

IBM Security Verify Access 10.0 through 10.0.9.2 and IBM Verify Identity Access 11.0 through 11.0.3 could allow a remote attacker to bypass authentication due to improper authentication.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-108268 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-108268)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-09

Breaks remote attestation trust in confidential computing stacks explicitly deployed by government, finance, and healthcare for sovereign and regulated data workloads.

*Deep dive: `TIER_2_CVE-2026-108268.md`*

___________________________________


# **[CVE-2026-104084 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-104084)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-09

Directly impacts enterprise email IAM boundaries by allowing stale JWT refresh tokens to bypass admin demotion, threatening session integrity and RBAC enforcement.

*Deep dive: `TIER_2_CVE-2026-104084.md`*

___________________________________


# **[CVE-2026-107826 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-107826)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-09

Foundational edge security infrastructure (WAF) critical for public-facing government, finance, and healthcare services, featuring a trivial default-config DoS.

*Deep dive: `TIER_2_CVE-2026-107826.md`*

___________________________________


# **[CVE-2026-108107 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-108107)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-09

Unauthenticated SQLi in ISP billing/voucher platform exposes customer financial data and credentials, impacting telecom finance operations and network access infrastructure.

*Deep dive: `TIER_2_CVE-2026-108107.md`*

___________________________________


# **[CVE-2026-108108 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-108108)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-09

Impacts ISP billing and network access control, directly affecting payment integrity and telecommunications infrastructure availability (Finance/General Infrastructure).

*Deep dive: `TIER_2_CVE-2026-108108.md`*

___________________________________


# **[CVE-2026-108109 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-108109)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-09

Finance sector relevance due to ISP billing platform compromise enabling account takeover, payment data exposure, and fraudulent transactions.

*Deep dive: `TIER_2_CVE-2026-108109.md`*

___________________________________


# **[CVE-2026-85531 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-85531)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-09

Finance sector: critical cryptographic flaw in payment callback validation enables unauthenticated order status forgery, directly compromising e-commerce transaction integrity.

*Deep dive: `TIER_2_CVE-2026-85531.md`*

___________________________________


# **[CVE-2026-86405 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-86405)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-09

Critical signature verification flaw in a widely deployed e-commerce payment module enabling direct financial fraud and transaction bypass, directly impacting Finance sector digital rails.

*Deep dive: `TIER_2_CVE-2026-86405.md`*

___________________________________


# **[CVE-2026-107815 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-107815)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-09

Tier 2 RCE in MariaDB CONNECT engine; general infrastructure widely deployed in healthcare, finance, and government, though mitigated by authentication and non-default plugin requirements.

*Deep dive: `TIER_2_CVE-2026-107815.md`*

___________________________________


# **[CVE-2026-107845 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-107845)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-09

General-purpose CMS widely deployed by public sector and enterprise entities; stored XSS enables backend takeover and RCE.

*Deep dive: `TIER_2_CVE-2026-107845.md`*

___________________________________


# **[CVE-2026-107852 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-107852)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-09

Payment validation bypass in a self-hosted billing system enables financial fraud and transaction integrity loss, aligning with the Finance sector.

*Deep dive: `TIER_2_CVE-2026-107852.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine