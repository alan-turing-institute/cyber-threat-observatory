# **Infrastructure Daily Brief: 2026-11-03**

**Infrastructure Daily Report TLP:GREEN Alert Id: b365b21b 2026-11-04 15:15:05**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-121543 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-4052 (Tier 2)                                                           | 3.k      |
| Cyber News | CVE-2026-46487 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-119215 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-95731 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-114550 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-92188 (Tier 2)                                                          | 3.k      |
| Threats    | Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Se | 1.c      |
| Threats    | The hidden network: Inside the phishing infrastructure ecosystem powering global | 1.a      |
| Threats    | Phishers are hijacking legitimate cloud infrastructure | Securelist              | 1.b      |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover                        | 1.c      |
| Threats    | Device-code phishing: How real login pages enable attacks                        | 1.j.3    |
| Threats    | The Infrastructure Behind Phishing | Zerot Security Research                     | 1.a      |
| Threats    | MadApe: The Code That Opens the Door                                             | 1.d      |
| Threats    | Inside Wazza: A Newly Observed Device Code Phishing Kit Targeting Microsoft 365  | 1.d      |
| Threats    | CVE-2026-118527                                                                  | 3.k      |
| Threats    | CVE-2026-105769                                                                  | 1.b      |
| Threats    | CVE-2026-116606                                                                  | 1.b      |
| Threats    | CVE-2026-121736                                                                  | 1.b      |
| Threats    | CVE-2026-121454                                                                  | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/)**

**PIR: 1.c**

Source: ketch Published: 2026-11-03

This deep dive examines the EvilTokens framework, which exploits OAuth device code flows to bypass multi-factor authentication and conditional access policies. The report details how attackers intercept authorization codes, automate token exchange, and maintain persistent access without triggering standard login alerts. Identity and infrastructure defenders receive mitigation steps, including flow monitoring, token lifecycle management, and architectural adjustments to secure device code endpoin

___________________________________


# **[The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime/)**

**PIR: 1.a**

Source: ketch Published: 2026-11-03

This analysis maps the underground hosting and domain registration networks that sustain large-scale phishing operations. Defenders will find actionable intelligence on shared infrastructure patterns, bulletproof hosting providers, and automated domain generation algorithms. The report details how threat actors rotate IP ranges and abuse legitimate DNS services to evade takedowns, offering network teams specific indicators and architectural insights to block malicious traffic at the perimeter.

___________________________________


# **[Phishers are hijacking legitimate cloud infrastructure | Securelist](https://securelist.com/cloud-platforms-in-phishing/120832/)**

**PIR: 1.b**

Source: ketch Published: 2026-11-03

Attackers increasingly leverage compromised or misconfigured cloud accounts to host phishing pages and proxy traffic, bypassing traditional web filters. This research outlines detection strategies for cloud-based phishing infrastructure, including identifying anomalous storage bucket configurations, serverless function abuse, and CDN misconfigurations. Infrastructure teams can use these findings to harden cloud environments, implement stricter IAM policies, and deploy behavioral monitoring to ca

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover](https://proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.c**

Source: ketch Published: 2026-11-03

An authoritative overview of how device code phishing has matured into a primary identity takeover vector, circumventing traditional MFA and SSO controls. The article explains the technical mechanics of code interception, session hijacking, and automated credential stuffing pipelines. For infrastructure defenders, it provides network-level detection signatures, proxy configuration recommendations, and identity governance controls to limit blast radius and enforce stricter device compliance durin

___________________________________


# **[Device-code phishing: How real login pages enable attacks](https://blog.barracuda.com/2026/11/02/device-code-phishing-real-login-page)**

**PIR: 1.j.3**

Source: ketch Published: 2026-11-03

This technical analysis reveals how attackers leverage legitimate authentication endpoints to harvest device codes, making traditional URL filtering ineffective. The report outlines the proxy architecture used to relay real login pages while capturing authorization tokens in transit. Infrastructure teams learn how to implement TLS inspection, monitor for anomalous OAuth traffic patterns, and deploy conditional access rules that detect rapid code validation attempts, strengthening perimeter and i

___________________________________


# **[The Infrastructure Behind Phishing | Zerot Security Research](https://research.zerot-security.com/the-infrastructure-behind-phishing/)**

**PIR: 1.a**

Source: ketch Published: 2026-11-03

A comprehensive breakdown of the technical stack powering modern phishing campaigns, from fast-flux DNS networks to ephemeral container deployments. The article provides defenders with architectural diagrams of attacker infrastructure, highlighting how load balancers, reverse proxies, and automated scaling tools are weaponized. Network and security operations teams gain practical guidance on identifying infrastructure fingerprints, correlating cross-campaign hosting patterns, and implementing pr

___________________________________


# **[MadApe: The Code That Opens the Door](https://group-ib.com/blog/madape-microsoft-device-code-phishing-kit)**

**PIR: 1.d**

Source: ketch Published: 2026-11-03

Group-IB dissects the MadApe phishing kit, a modular toolchain designed specifically for Microsoft 365 device code harvesting. The analysis covers the kit’s backend infrastructure, automated victim tracking, and token exfiltration mechanisms. Defenders gain insight into the kit’s deployment patterns, associated hosting providers, and network indicators. The article provides actionable recommendations for hardening identity providers, monitoring OAuth endpoints, and blocking kit-specific infrastr

___________________________________


# **[Inside Wazza: A Newly Observed Device Code Phishing Kit Targeting Microsoft 365 Accounts](https://www.levelblue.com/blogs/spiderlabs-blog/inside-wazza-a-newly-observed-device-code-phishing-kit-targeting-microsoft-365-accounts)**

**PIR: 1.d**

Source: ketch Published: 2026-11-03

This research uncovers the Wazza phishing kit, highlighting its use of cloud-native infrastructure and automated domain rotation to evade detection. The report details how the kit captures device codes, manages victim sessions, and integrates with credential stuffing services. Infrastructure defenders receive technical indicators, hosting provider patterns, and network-level blocking strategies. The article emphasizes the need for continuous infrastructure monitoring and identity flow validation

___________________________________


# **[CVE-2026-118527](https://nvd.nist.gov/vuln/detail/CVE-2026-118527)**

**PIR: 3.k**

Source: vulners/duckdb Published: 2026-11-03

Use of predictable filenames in Ivanti Connect Secure before versions 25.1.1.3 and 22.8R2.6 allows a remote authenticated attacker to upload files with attacker-controlled content to a known location on disk.

___________________________________


# **[CVE-2026-105769](https://nvd.nist.gov/vuln/detail/CVE-2026-105769)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-02

kaniko before 1.25.20 can send a Microsoft Entra ID (Azure AD) access token for Azure Resource Manager to an attacker-controlled registry host. kaniko uses the Azure Container Registry credential helper github.com/chrismellard/docker-credential-acr-env, which decides whether a host is an ACR registry with an unanchored regular expression, so any hostname containing .azurecr.io, .azurecr.cn, .azurecr.de or .azurecr.us is accepted. kaniko consults this helper for any registry that has no credentia

___________________________________


# **[CVE-2026-116606](https://nvd.nist.gov/vuln/detail/CVE-2026-116606)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-02

An authentication bypass in Barracuda Email Security Gateway versions earlier than 9.4.0.030 allows an unauthenticated remote attacker to invoke a configuration-import function and restore a crafted, compatible backup archive, resulting in unauthorized modification of the appliance’s global configuration.

___________________________________


# **[CVE-2026-121736](https://nvd.nist.gov/vuln/detail/CVE-2026-121736)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-03

NocoDB 0.300.0 before 2026.08.0 contains a missing authentication vulnerability in the POST /api/v2/oauth/authorize handler that allows unauthenticated attackers to create OAuth authorization codes. Attackers can send anonymous requests with client_id, redirect_uri and approved=true to insert unbounded ownerless authorization code records, limited only by rate limiting.

___________________________________


# **[CVE-2026-121454](https://nvd.nist.gov/vuln/detail/CVE-2026-121454)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-03

Padloc through 4.3.0 contains a missing authentication vulnerability in ScimServer._handleScimGet() that allows unauthenticated attackers to read SCIM directories by sending any non-empty bearer token. Attackers who know an organization id can query the Users and Groups SCIM endpoints to retrieve provisioned usernames, emails, names, externalIds, and group memberships.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-121543 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-121543)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-03

Direct Digital Identity sector impact: default authorization bypass in an open-source SSO/IdP enables full identity provider takeover and downstream service compromise.

*Deep dive: `TIER_2_CVE-2026-121543.md`*

___________________________________


# **[CVE-2026-4052 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-4052)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-03

Core IdAM/SSO token issuance flaw in WSO2 Identity Server allows privilege escalation to admin APIs, directly impacting digital identity boundaries and credential scoping.

*Deep dive: `TIER_2_CVE-2026-4052.md`*

___________________________________


# **[CVE-2026-46487 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-46487)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-03

Foundational software for government Spatial Data Infrastructures (SDI); unauthenticated bypass exposes restricted civic geospatial metadata.

*Deep dive: `TIER_2_CVE-2026-46487.md`*

___________________________________


# **[CVE-2026-119215 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-119215)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-03

Digital Identity: Authorization bypass in an Elixir/Phoenix auth library allows MFA/TOTP secret hijacking and account takeover, impacting enterprise and public-sector identity platforms.

*Deep dive: `TIER_2_CVE-2026-119215.md`*

___________________________________


# **[CVE-2026-95731 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-95731)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-03

Foundational data center orchestration tool with hardcoded admin credentials, posing high lateral-movement risk to internal networks underpinning Finance, Healthcare, and Government digital services.

*Deep dive: `TIER_2_CVE-2026-95731.md`*

___________________________________


# **[CVE-2026-114550 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-114550)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-03

Unauthenticated RCE in a foundational MQTT library used across IoT telemetry stacks in healthcare, government, and finance deployments.

*Deep dive: `TIER_2_CVE-2026-114550.md`*

___________________________________


# **[CVE-2026-92188 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-92188)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-03

Unauthenticated SYSTEM RCE in enterprise database monitoring software widely deployed across Finance, Government, and Healthcare to secure critical backend assets.

*Deep dive: `TIER_2_CVE-2026-92188.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine