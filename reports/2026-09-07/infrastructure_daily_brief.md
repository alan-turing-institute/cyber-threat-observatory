# **Infrastructure Daily Brief: 2026-09-07**

**Infrastructure Daily Report TLP:GREEN Alert Id: 1dc196d4 2026-09-08 09:35:51**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                       | PIR(s)   |
|------------|------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-18355 (Tier 2)                                                      | 3.k      |
| Cyber News | CVE-2026-18453 (Tier 2)                                                      | 3.k      |
| Cyber News | CVE-2026-18922 (Tier 2)                                                      | 3.k      |
| Cyber News | CVE-2026-61410 (Tier 2)                                                      | 3.k      |
| Cyber News | CVE-2026-76578 (Tier 2)                                                      | 3.k      |
| Cyber News | CVE-2026-80132 (Tier 2)                                                      | 3.k      |
| Cyber News | CVE-2026-80134 (Tier 2)                                                      | 3.k      |
| Cyber News | CVE-2026-75650 (Tier 2)                                                      | 3.k      |
| Cyber News | CVE-2026-82753 (Tier 2)                                                      | 3.k      |
| Cyber News | CVE-2026-86273 (Tier 2)                                                      | 3.k      |
| Cyber News | CVE-2026-86480 (Tier 2)                                                      | 3.k      |
| Cyber News | CVE-2026-79645 (Tier 2)                                                      | 3.k      |
| Cyber News | CVE-2026-80131 (Tier 2)                                                      | 3.k      |
| Cyber News | CVE-2026-84732 (Tier 2)                                                      | 3.k      |
| Threats    | OAuth Device Code Phishing: 37x Surge in Enterprise ATO                      | 1.b      |
| Threats    | The Device Code Phishing Tsunami: What We’re Seeing in the Wild              | 1.c      |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover                    | 1.c      |
| Threats    | Device Code Phishing — The Attack That Makes MFA Irrelevant                  | 1.h      |
| Threats    | Inside an AI‑enabled device code phishing campaign                           | 1.d      |
| Threats    | The Illicit Consent Grant Part 2: Device-Code Phishing and the AI PhaaS Wave | 1.e      |
| Threats    | Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns            | 1.a      |
| Threats    | Tycoon2FA Returns: PhaaS Platform Survives Law Enforcement Disruption        | 1.e      |
| Threats    | CVE-2026-86242                                                               | 1.b      |
| Threats    | CVE-2026-84256                                                               | 1.b      |
| Threats    | CVE-2026-78480                                                               | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[OAuth Device Code Phishing: 37x Surge in Enterprise ATO](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/04/CSA_research_note_oauth-device-code-phishing-surge_20260405-csa-styled.pdf)**

**PIR: 1.b**

Source: ketch Published: 2026-09-07

Enterprise account takeover attacks leveraging OAuth device code flows have surged 37x, bypassing traditional MFA controls. Attackers exploit legitimate consent prompts to harvest long-lived access tokens, enabling persistent infrastructure access. Defenders must implement conditional access policies, monitor for anomalous device code grants, and restrict OAuth app permissions to mitigate this escalating identity threat.

___________________________________


# **[The Device Code Phishing Tsunami: What We’re Seeing in the Wild](https://www.levelblue.com/blogs/spiderlabs-blog/the-device-code-phishing-tsunami-what-were-seeing-in-the-wild)**

**PIR: 1.c**

Source: ketch Published: 2026-09-07

Real-world telemetry reveals a massive wave of device code phishing campaigns targeting cloud administrators and developers. Threat actors automate credential harvesting via QR codes and short URLs, circumventing phishing-resistant MFA. Infrastructure teams should deploy token lifecycle monitoring, enforce FIDO2 hardware keys, and block unauthorized OAuth consent requests to secure critical environments.

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.c**

Source: ketch Published: 2026-09-07

Identity takeover tactics have evolved beyond credential stuffing to exploit OAuth device authorization flows. Attackers now target privileged accounts with tailored consent phishing, granting them direct API access without password interception. IT defenders must audit third-party app integrations, implement zero-trust identity policies, and educate users on recognizing illicit consent prompts.

___________________________________


# **[Device Code Phishing — The Attack That Makes MFA Irrelevant](https://cybergrind.org/blog/2026-06-02-device-code-phishing)**

**PIR: 1.h**

Source: ketch Published: 2026-09-07

Traditional multi-factor authentication is increasingly rendered obsolete by device code phishing, which leverages legitimate OAuth flows to bypass security controls. By tricking users into authorizing malicious apps, attackers obtain persistent tokens that evade MFA challenges. Infrastructure security teams must transition to phishing-resistant authentication, enforce strict consent policies, and monitor for token abuse.

___________________________________


# **[Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.d**

Source: ketch Published: 2026-09-07

Microsoft researchers dissect a sophisticated campaign using AI to craft hyper-realistic device code phishing pages and automate victim targeting. The attack chain exploits OAuth flows to harvest credentials and tokens, bypassing standard MFA. Infrastructure defenders must prioritize phishing-resistant MFA, monitor for anomalous OAuth consent activity, and leverage AI-driven threat detection to identify emerging campaigns.

___________________________________


# **[The Illicit Consent Grant Part 2: Device-Code Phishing and the AI PhaaS Wave](https://slashid.com/blog/illicit-consent-grant-part-2)**

**PIR: 1.e**

Source: ketch Published: 2026-09-07

The convergence of illicit consent grants and AI-driven Phishing-as-a-Service platforms has created a highly automated identity threat landscape. Attackers dynamically generate convincing OAuth consent pages, scaling device code phishing across enterprises. Defenders should implement automated consent policy enforcement, deploy AI-detection tools for phishing infrastructure, and restrict OAuth scope permissions.

___________________________________


# **[Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns](https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns)**

**PIR: 1.a**

Source: ketch Published: 2026-09-07

Modern phishing operations increasingly leverage cloud-native services like serverless functions, object storage, and CDN networks to host malicious payloads and evade detection. This infrastructure abuse complicates takedown efforts and extends campaign lifespans. IT security teams must implement cloud security posture management, monitor for misconfigured cloud assets, and integrate cloud telemetry into phishing detection workflows.

___________________________________


# **[Tycoon2FA Returns: PhaaS Platform Survives Law Enforcement Disruption](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/03/CSA_research_note_Tycoon2FA-PhaaS-resurrection-MaaS-resilience-20260326-csa-styled.pdf)**

**PIR: 1.e**

Source: ketch Published: 2026-09-07

Despite law enforcement takedowns, the Tycoon2FA Phishing-as-a-Service platform has rapidly resurfaced, demonstrating the resilience of underground identity theft ecosystems. The platform offers attackers customizable MFA bypass tools and automated phishing infrastructure. Defenders should track known PhaaS indicators, enforce strict OAuth consent policies, and prepare incident response playbooks for rapid token revocation.

___________________________________


# **[CVE-2026-86242](https://nvd.nist.gov/vuln/detail/CVE-2026-86242)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-06

Bifrost HTTP transport before 2.0.0 accepts an enabled custom plugin whose path is an HTTP URL through unauthenticated POST /api/plugins when management authentication is disabled (the default, governance.auth_config.is_enabled=false). The shared-object loader treats an http-prefixed path as a download URL, writes the body to a temporary .so, and passes it to Go's plugin.Open. After a successful open, optional Init runs immediately with the supplied config as the Bifrost process user. On documen

___________________________________


# **[CVE-2026-84256](https://nvd.nist.gov/vuln/detail/CVE-2026-84256)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-07

An argument parsing issue in OpenVPN 2.1_rc10 through 2.6.22 and 2.7_alpha1 through 2.7.6 on Windows allows remote authenticated users to execute arbitrary commands via a crafted certificate subject

___________________________________


# **[CVE-2026-78480](https://nvd.nist.gov/vuln/detail/CVE-2026-78480)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-07

Dell SCG 5.0 Appliance versions prior to 5.36.00.16 and Dell SCG 5.0 Application versions prior to 5.36.00.00, contains a Missing Authentication for Critical Function vulnerability. An unauthenticated attacker with remote access could potentially exploit this vulnerability, leading to unauthorized access.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-18355 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-18355)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-07

Digital Identity sector: core LDAP/IdAM directory server flaw enabling post-auth RCE/DoS, directly impacting enterprise and public-sector authentication infrastructure.

*Deep dive: `TIER_2_CVE-2026-18355.md`*

___________________________________


# **[CVE-2026-18453 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-18453)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-07

Core Digital Identity infrastructure (389/Red Hat Directory Server) with unauthenticated DoS disrupting authentication, SSO, and credential lookups.

*Deep dive: `TIER_2_CVE-2026-18453.md`*

___________________________________


# **[CVE-2026-18922 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-18922)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-07

Critical authentication bypass in Red Hat 389 Directory Server enables unauthenticated full Directory Manager privilege escalation, directly compromising core LDAP/IdAM infrastructure (Digital Identity sector).

*Deep dive: `TIER_2_CVE-2026-18922.md`*

___________________________________


# **[CVE-2026-61410 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-61410)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-07

Critical unauthenticated RCE in Dell Secure Connect Gateway, a public-facing ZTNA appliance that handles authentication, authorization, and session management for remote digital identity workflows.

*Deep dive: `TIER_2_CVE-2026-61410.md`*

___________________________________


# **[CVE-2026-76578 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-76578)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-07

Core Digital Identity infrastructure (FreeIPA/IdM) allowing unauthenticated LDAP clients to forge administrative Kerberos credentials, enabling full identity takeover.

*Deep dive: `TIER_2_CVE-2026-76578.md`*

___________________________________


# **[CVE-2026-80132 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-80132)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-07

Unauthenticated remote access in Dell's ZTNA/IAM gateway directly compromises digital identity enforcement and public/enterprise network security.

*Deep dive: `TIER_2_CVE-2026-80132.md`*

___________________________________


# **[CVE-2026-80134 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-80134)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-07

Hard-coded credentials in a public-facing ZTNA gateway directly compromise authentication and session management for Digital Identity, Government, and Finance deployments.

*Deep dive: `TIER_2_CVE-2026-80134.md`*

___________________________________


# **[CVE-2026-75650 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-75650)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-07

Critical unauthenticated RCE in widely deployed e-commerce platforms directly impacts the Finance sector by compromising payment processing, customer accounts, and transactional data.

*Deep dive: `TIER_2_CVE-2026-75650.md`*

___________________________________


# **[CVE-2026-82753 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-82753)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-07

Digital Identity: DoS vulnerability in a foundational OAuth2/OIDC authorization server library that can exhaust database and memory resources on public-facing endpoints.

*Deep dive: `TIER_2_CVE-2026-82753.md`*

___________________________________


# **[CVE-2026-86273 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-86273)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-07

Unauthenticated SSRF in Brazil's core state government document management system (SIGA), enabling internal reconnaissance and lateral movement in public sector networks.

*Deep dive: `TIER_2_CVE-2026-86273.md`*

___________________________________


# **[CVE-2026-86480 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-86480)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-07

Critical unauthenticated superuser escalation in JetBrains Hub, an internal IdAM platform managing credentials and access for enterprise development tools.

*Deep dive: `TIER_2_CVE-2026-86480.md`*

___________________________________


# **[CVE-2026-79645 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-79645)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-07

Unauthenticated remote access to a foundational ZTNA gateway compromises Zero Trust architectures widely deployed for secure remote access in regulated and public-sector environments.

*Deep dive: `TIER_2_CVE-2026-79645.md`*

___________________________________


# **[CVE-2026-80131 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-80131)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-07

Unauthenticated RCE in internet-facing ZTNA gateway compromises Zero Trust perimeters critical for regulated enterprise and public sector remote access.

*Deep dive: `TIER_2_CVE-2026-80131.md`*

___________________________________


# **[CVE-2026-84732 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-84732)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-07

Foundational VPN gateway component for public-sector and enterprise remote access; unauthenticated DoS disrupts critical connectivity pathways.

*Deep dive: `TIER_2_CVE-2026-84732.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine