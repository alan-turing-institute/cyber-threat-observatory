# **Infrastructure Daily Brief: 2026-09-09**

**Infrastructure Daily Report TLP:GREEN Alert Id: cf1e1cae 2026-09-10 17:06:11**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-80172 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-67403 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-79322 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-79635 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-79636 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-79641 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-85102 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-87016 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-79689 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-80122 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-85103 (Tier 2)                                                          | 3.k      |
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.c.2    |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover                        | 1.b.1    |
| Threats    | When checking the URL isn’t enough: phishing via the Microsoft identity platform | 1.e.3    |
| Threats    | Device Code Phishing: Turning a Convenience Feature Into an MFA Bypass | Trend M | 1.b.4    |
| Threats    | EvilTokens abuses Microsoft device code flow for account takeovers | CSO Online  | 1.e.1    |
| Threats    | Russian hacker group Laundry Bear exploits Zimbra zero-click flaw to target West | 1.d.1    |
| Threats    | PhantomEnigma: How a Malware Crew Turned Brazilian Government Sites Into Trusted | 1.f.2    |
| Threats    | Three Active Microsoft 365 Phishing Campaigns Targeting Schools and Government A | 1.g.1    |
| Threats    | CVE-2026-86464                                                                   | 1.b      |
| Threats    | CVE-2026-83941                                                                   | 1.b      |
| Threats    | CVE-2026-79576                                                                   | 1.b      |
| Threats    | CVE-2026-87806                                                                   | 1.b      |
| Threats    | CVE-2026-53939                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.c.2**

Source: ketch Published: 2026-09-09

Threat actors are leveraging AI to automate device code phishing at scale, generating live authentication codes on demand. This evolution bypasses traditional MFA controls and enables sustained post-compromise access. Infrastructure defenders must monitor for anomalous device code requests, implement conditional access policies, and deploy AI-driven detection to counter automated credential harvesting.

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.b.1**

Source: ketch Published: 2026-09-09

Device code phishing represents a significant shift in identity takeover tactics, exploiting legitimate authentication flows to circumvent multi-factor authentication. Attackers trick users into entering codes on malicious portals, granting threat actors direct token access. Defenders should enforce strict device compliance, monitor for unusual authentication patterns, and educate users on recognizing device code prompts.

___________________________________


# **[When checking the URL isn’t enough: phishing via the Microsoft identity platform | Securelist](https://securelist.com/microsoft-device-code-phishing-attack/120350/)**

**PIR: 1.e.3**

Source: ketch Published: 2026-09-09

Modern phishing campaigns increasingly abuse the Microsoft identity platform, rendering traditional URL inspection insufficient. Attackers leverage legitimate OAuth endpoints and token manipulation to steal credentials and session tokens. IT teams must implement advanced identity protection, enforce app consent policies, and deploy real-time telemetry to detect platform abuse.

___________________________________


# **[Device Code Phishing: Turning a Convenience Feature Into an MFA Bypass | Trend Micro (US)](https://www.trendmicro.com/en_us/research/26/g/device-code-phishing.html)**

**PIR: 1.b.4**

Source: ketch Published: 2026-09-09

The device code flow, designed for seamless authentication, is being weaponized to bypass MFA. Attackers host fake login pages that prompt users to enter device codes, effectively hijacking sessions without passwords. Infrastructure security requires tightening conditional access rules, disabling unnecessary device code flows, and monitoring for rapid token issuance.

___________________________________


# **[EvilTokens abuses Microsoft device code flow for account takeovers | CSO Online](https://www.csoonline.com/article/4153742/eviltokens-abuses-microsoft-device-code-flow-for-account-takeovers.html)**

**PIR: 1.e.1**

Source: ketch Published: 2026-09-09

The EvilTokens malware family exploits Microsoft’s device code authentication flow to silently harvest access tokens. By automating the device code exchange, attackers achieve persistent account access while evading traditional login alerts. Defenders should audit token issuance logs, restrict device code usage to managed devices, and deploy endpoint detection for token theft indicators.

___________________________________


# **[Russian hacker group Laundry Bear exploits Zimbra zero-click flaw to target Western government, critical infrastructure](https://industrialcyber.co/cisa/russian-hacker-group-laundry-bear-exploits-zimbra-zero-click-flaw-to-target-western-government-critical-infrastructure)**

**PIR: 1.d.1**

Source: ketch Published: 2026-09-09

Laundry Bear leverages a zero-click vulnerability in Zimbra mail servers to infiltrate government and critical infrastructure networks without user interaction. This exploit enables silent data exfiltration and lateral movement. Infrastructure teams must prioritize patching Zimbra deployments, deploy network segmentation, and monitor for anomalous outbound traffic indicative of zero-click compromises.

___________________________________


# **[PhantomEnigma: How a Malware Crew Turned Brazilian Government Sites Into Trusted Malware Hubs](https://securebulletin.com/phantomenigma-how-a-malware-crew-turned-brazilian-government-sites-into-trusted-malware-hubs)**

**PIR: 1.f.2**

Source: ketch Published: 2026-09-09

The PhantomEnigma group hijacked compromised government websites to distribute malware, leveraging trusted domains to bypass security controls. This infrastructure abuse tactic complicates threat intelligence and endpoint detection. Defenders should implement strict web reputation filtering, monitor for domain hijacking indicators, and isolate critical assets from untrusted networks.

___________________________________


# **[Three Active Microsoft 365 Phishing Campaigns Targeting Schools and Government Agencies](https://forsyteit.com/three-active-microsoft-365-phishing-campaigns-targeting-schools-and-government-agencies)**

**PIR: 1.g.1**

Source: ketch Published: 2026-09-09

Coordinated phishing campaigns are actively targeting educational and government sectors using Microsoft 365 infrastructure. Attackers deploy credential harvesting pages and malicious attachments to compromise administrative accounts. IT defenders must prioritize MFA enforcement, segment privileged accounts, and leverage Microsoft Defender for Office 365 to block campaign infrastructure.

___________________________________


# **[CVE-2026-86464](https://nvd.nist.gov/vuln/detail/CVE-2026-86464)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-08

In the current development version of Eclipse aeriOS, for which no official release has yet been published, the Identity Manager (IdM) deployment included insecure default configurations and credentials for security-sensitive services.




The Helm chart exposed the Keycloak service and its PostgreSQL backing database through Kubernetes NodePort services by default, while the Docker Compose deployment similarly exposed PostgreSQL on all network interfaces. The deployment included fixed default c

___________________________________


# **[CVE-2026-83941](https://nvd.nist.gov/vuln/detail/CVE-2026-83941)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-08

Missing authorization in Entra ID allows an authorized attacker to elevate privileges over a network.

___________________________________


# **[CVE-2026-79576](https://nvd.nist.gov/vuln/detail/CVE-2026-79576)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-08

An issue in the Single-Sign On (SSO) component of Digital-Infrastructure v9.6.7 allows attackers to authenticate as any user, including the Admin, without a password.

___________________________________


# **[CVE-2026-87806](https://nvd.nist.gov/vuln/detail/CVE-2026-87806)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-09

Parse Server versions <= 8.6.87 and >= 9.0.0 < 9.10.1-alpha.7 contain an authentication bypass in the built-in LDAP authentication adapter. The adapter forwarded the client-supplied password to the directory without verifying that a password had been supplied, and treated any non-error response from the directory as proof of authentication. A zero-length credential turns an LDAP simple bind into the unauthenticated authentication mechanism described in RFC 4513 section 5.1.2, which some director

___________________________________


# **[CVE-2026-53939](https://nvd.nist.gov/vuln/detail/CVE-2026-53939)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-08

OpenIDC/cjose is a C library implementing the Javascript Object Signing and Encryption (JOSE). In versions 0.6.1 through 0.6.2.5, when cjose encrypts a JWE using an AES-CBC-HMAC content-encryption algorithm (`A128CBC-HS256`, `A192CBC-HS384`, or `A256CBC-HS512`) together with any key-management algorithm that generates a fresh content-encryption key (CEK), the CEK is all zero bytes instead of being randomly generated. The resulting JWE is therefore encrypted and authenticated under a fixed, publi

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-80172 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-80172)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-09

Critical unauthenticated flaw in Dell's ZTNA gateway enables indefinite administrative token generation, directly compromising Digital Identity and access management infrastructure.

*Deep dive: `TIER_2_CVE-2026-80172.md`*

___________________________________


# **[CVE-2026-67403 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-67403)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-09

Finance sector: critical cross-tenant authorization bypass in a SaaS accounts receivable platform threatens financial data integrity and regulatory compliance.

*Deep dive: `TIER_2_CVE-2026-67403.md`*

___________________________________


# **[CVE-2026-79322 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-79322)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-09

Unauthenticated SQLi in a widely deployed Magento 2 extension exposes customer PII and payment/transaction data, directly impacting Finance and e-commerce infrastructure.

*Deep dive: `TIER_2_CVE-2026-79322.md`*

___________________________________


# **[CVE-2026-79635 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-79635)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-09

Unauthenticated SSRF in a public-facing ZTNA gateway poses direct risk to foundational remote access infrastructure commonly deployed by government and finance sectors.

*Deep dive: `TIER_2_CVE-2026-79635.md`*

___________________________________


# **[CVE-2026-79636 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-79636)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-09

Unauthenticated remote access bypass in Dell SCG ZTNA gateway undermines Digital Identity perimeter controls and zero-trust session validation.

*Deep dive: `TIER_2_CVE-2026-79636.md`*

___________________________________


# **[CVE-2026-79641 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-79641)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-09

Foundational ZTNA edge gateway vulnerability impacting secure remote access for government and finance deployments, with no available workarounds.

*Deep dive: `TIER_2_CVE-2026-79641.md`*

___________________________________


# **[CVE-2026-85102 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-85102)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-09

Critical unauthenticated RCE in widely deployed enterprise VPN gateways, explicitly noted as foundational infrastructure for Government and Finance perimeter security.

*Deep dive: `TIER_2_CVE-2026-85102.md`*

___________________________________


# **[CVE-2026-87016 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-87016)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-09

Digital Identity sector: OAuth/SCIM identity resolution bypass enables full session takeover via SQL wildcard injection in self-hosted AI platforms.

*Deep dive: `TIER_2_CVE-2026-87016.md`*

___________________________________


# **[CVE-2026-79689 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-79689)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-09

Unauthenticated remote command injection in a default public-facing enterprise gateway with no workarounds, posing a direct pivot risk to underlying DPI services.

*Deep dive: `TIER_2_CVE-2026-79689.md`*

___________________________________


# **[CVE-2026-80122 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-80122)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-09

Internet-facing ZTNA gateway vulnerability with no mitigations, directly impacting secure remote access architectures foundational to regulated and public-sector operations.

*Deep dive: `TIER_2_CVE-2026-80122.md`*

___________________________________


# **[CVE-2026-85103 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-85103)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-09

Tier 2 unauthenticated RCE in internet-facing Check Point VPN gateways; critical general infrastructure underpinning secure remote access for regulated and public-sector networks.

*Deep dive: `TIER_2_CVE-2026-85103.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine