# **Infrastructure Daily Brief: 2026-09-14**

**Infrastructure Daily Report TLP:GREEN Alert Id: 51b4a15d 2026-09-15 23:35:41**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-21391 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-76461 (Tier 1)                                                          | 3.k      |
| Cyber News | CVE-2026-78336 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-87802 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-90942 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-19290 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-67399 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-76441 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-76443 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-90805 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-90840 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-53714 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-57578 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-76442 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-90841 (Tier 2)                                                          | 3.k      |
| Threats    | Microsoft: Passkey Help Desk Calls Are Hijacking Cloud Accounts, Then Draining S | 1.f.2    |
| Threats    | Storm-3121 Fakes Passkey Portals to Steal M365 Data                              | 1.f.1    |
| Threats    | Device Code Phishing Surge — Threat Analysis                                     | 1.b.3    |
| Threats    | AI-Enabled Device Code Phishing Campaign Abuses Device Code Sign-In Flow         | 1.c.2    |
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.c.1    |
| Threats    | Dual-RMM Phishing And PowerShell RAT Campaign Hits SLTTs                         | 1.e.4    |
| Threats    | The Device Code Phishing Tsunami: What We’re Seeing in the Wild                  | 1.b.1    |
| Threats    | Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns                | 1.d.2    |
| Threats    | CVE-2026-90961                                                                   | 1.b      |
| Threats    | CVE-2026-90895                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Microsoft: Passkey Help Desk Calls Are Hijacking Cloud Accounts, Then Draining SharePoint](https://threat-intelligence.redeyesecurity.com/blog/passkey-phishing-microsoft-cloud-hijack-storm-3032-2026)**

**PIR: 1.f.2**

Source: ketch Published: 2026-09-14

Attackers are exploiting social engineering via fake help desk calls to trick IT staff into initiating passkey registration flows. Once registered, threat actors hijack cloud accounts and systematically drain SharePoint repositories. This campaign highlights a critical gap in identity verification processes and underscores the need for strict change-management protocols for authentication methods. Infrastructure defenders must implement multi-person approval for passkey additions and monitor for

___________________________________


# **[Storm-3121 Fakes Passkey Portals to Steal M365 Data](https://0daynews.com/articles/2026-09-12-shinyhunters-passkey-phishing-m365-aitm)**

**PIR: 1.f.1**

Source: ketch Published: 2026-09-14

The Storm-3121 threat group has deployed sophisticated phishing portals that mimic Microsoft’s native passkey registration interface. By intercepting authentication-in-motion tokens, attackers bypass traditional MFA and gain persistent access to M365 environments. Defenders should deploy conditional access policies that restrict passkey registration to known corporate networks and monitor for rapid credential validation followed by bulk data exfiltration.

___________________________________


# **[Device Code Phishing Surge — Threat Analysis](https://intel.threadlinqs.com/threat/TL-2026-2468)**

**PIR: 1.b.3**

Source: ketch Published: 2026-09-14

A significant increase in device code phishing campaigns is targeting organizations relying on Microsoft’s device code authentication flow. Attackers host malicious pages that prompt users to visit a legitimate Microsoft login URL, tricking them into authorizing attacker-controlled sessions. This technique effectively bypasses MFA without requiring credential theft. Infrastructure teams should disable device code flows where possible and implement user education focused on recognizing unauthoriz

___________________________________


# **[AI-Enabled Device Code Phishing Campaign Abuses Device Code Sign-In Flow](https://captechgroup.com/threat-intelligence-center/ai-enabled-device-code-phishing-campaign-abuses-de-81a334)**

**PIR: 1.c.2**

Source: ketch Published: 2026-09-14

Threat actors are leveraging AI to dynamically generate highly convincing device code phishing pages that adapt to target domains and branding. The campaign automates the delivery of tailored prompts, significantly increasing success rates. By abusing the legitimate device code sign-in flow, attackers harvest valid access tokens. Defenders must prioritize token lifecycle management, enforce strict conditional access rules, and deploy AI-driven detection to identify anomalous authorization patter

___________________________________


# **[Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.c.1**

Source: ketch Published: 2026-09-14

Microsoft’s security research details an advanced campaign combining AI-generated lures with device code authentication abuse. The threat actors use machine learning to optimize phishing page layouts and timing, maximizing victim interaction. By capturing valid OAuth tokens, they bypass password and MFA protections entirely. The report provides actionable mitigation strategies, including restricting device code flows, implementing token-bound policies, and leveraging Microsoft Defender for Cloud

___________________________________


# **[Dual-RMM Phishing And PowerShell RAT Campaign Hits SLTTs](https://www.hendryadrian.com/dual-rmm-phishing-and-powershell-rat-campaign-hits-sltts/)**

**PIR: 1.e.4**

Source: ketch Published: 2026-09-14

A targeted campaign against state, local, tribal, and territorial governments combines phishing lures with dual RMM software deployment and a PowerShell-based RAT. Attackers use initial access to install legitimate remote management tools, establishing persistent backdoors that evade traditional endpoint detection. Infrastructure defenders should enforce strict RMM whitelisting, monitor for unauthorized PowerShell execution chains, and implement network segmentation to limit lateral movement pos

___________________________________


# **[The Device Code Phishing Tsunami: What We’re Seeing in the Wild](https://www.levelblue.com/blogs/spiderlabs-blog/the-device-code-phishing-tsunami-what-were-seeing-in-the-wild)**

**PIR: 1.b.1**

Source: ketch Published: 2026-09-14

Operational analysis reveals a massive wave of device code phishing attacks exploiting the OAuth 2.0 device authorization grant. Attackers are distributing malicious QR codes and short URLs via email and messaging platforms. Once scanned, victims are directed to legitimate Microsoft login pages, unknowingly granting attackers session tokens. Infrastructure defenders should monitor for high volumes of device code requests, restrict grant types to essential services, and implement real-time alerti

___________________________________


# **[Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns](https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns)**

**PIR: 1.d.2**

Source: ketch Published: 2026-09-14

Modern phishing operations are increasingly leveraging cloud-native services like serverless functions, CDN networks, and managed DNS to host malicious infrastructure. This approach provides attackers with high availability, geographic distribution, and resilience against takedown efforts. Defenders must shift from static URL blocking to behavioral analysis, monitoring for newly provisioned cloud resources, anomalous DNS resolutions, and infrastructure patterns associated with phishing-as-a-serv

___________________________________


# **[CVE-2026-90961](https://nvd.nist.gov/vuln/detail/CVE-2026-90961)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-14

The LdapAuth and LinOTPAuth authentication plugins in MISP contain an authentication bypass vulnerability. Both LdapAuthenticate and LinOTPAuthenticate replace CakePHP's FormAuthenticate class but fail to replicate its _checkFields() input validation guard. As a result, the email and password fields extracted from the login request are passed to downstream authentication logic without verifying that they are non-empty strings.

In the LDAP authenticator, an empty or null password is forwarded to

___________________________________


# **[CVE-2026-90895](https://nvd.nist.gov/vuln/detail/CVE-2026-90895)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-14

Affected versions of MISP’s interactive CLI shell implement access control independently from the normal web application, causing several authorization inconsistencies.


The patch shows that CLI access could differ from the web application in multiple security-sensitive areas:

 - feed listings did not enforce the same lookup_visible restrictions for non-host-organisation users;
 - feed detail access did not enforce the same host-organisation/site-admin authorization as FeedsController::view();

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-21391 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-21391)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-14

Critical authentication bypass in PingAM IdP/SSO platform allows unauthenticated attackers to forge ID Token claims, directly impacting Digital Identity infrastructure and federated access controls.

*Deep dive: `TIER_2_CVE-2026-21391.md`*

___________________________________


# **[CVE-2026-76461 (Tier 1)](https://nvd.nist.gov/vuln/detail/CVE-2026-76461)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-14

Foundational perimeter email gateway infrastructure actively exploited in the wild, directly impacting Government, Healthcare, and Finance communications and data routing.

*Deep dive: `TIER_1_CVE-2026-76461.md`*

___________________________________


# **[CVE-2026-78336 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-78336)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-14

Exposes plaintext OIDC client secrets to any authenticated user in Apache Syncope, directly compromising enterprise SSO/IdAM infrastructure (Digital Identity) and enabling token forgery across identity-bound services.

*Deep dive: `TIER_2_CVE-2026-78336.md`*

___________________________________


# **[CVE-2026-87802 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-87802)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-14

Critical authentication bypass in Apache Syncope IAM gateway allows JWT forgery and full user impersonation, directly impacting Digital Identity infrastructure.

*Deep dive: `TIER_2_CVE-2026-87802.md`*

___________________________________


# **[CVE-2026-90942 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-90942)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-14

Digital Identity: Critical authorization flaw in Casdoor IdP allows org admins to extract global JWT signing keys, enabling cross-tenant token forgery and full platform compromise.

*Deep dive: `TIER_2_CVE-2026-90942.md`*

___________________________________


# **[CVE-2026-19290 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-19290)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-14

Unauthenticated remote data exposure on IBM Sterling File Gateway, a perimeter B2B integration component widely deployed across finance, healthcare, and government for secure EDI and document exchange.

*Deep dive: `TIER_2_CVE-2026-19290.md`*

___________________________________


# **[CVE-2026-67399 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-67399)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-14

Unauthenticated RCE in WHMCS billing platform directly impacts financial operations infrastructure and payment processing for hosting providers and ISPs.

*Deep dive: `TIER_2_CVE-2026-67399.md`*

___________________________________


# **[CVE-2026-76441 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-76441)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-14

Critical unauthenticated bypass in perimeter email gateways widely deployed across government, healthcare, and finance sectors for secure communications.

*Deep dive: `TIER_2_CVE-2026-76441.md`*

___________________________________


# **[CVE-2026-76443 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-76443)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-14

Critical general infrastructure flaw in internet-facing email gateways widely deployed across government, finance, and healthcare, enabling remote code execution and potential data interception.

*Deep dive: `TIER_2_CVE-2026-76443.md`*

___________________________________


# **[CVE-2026-90805 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-90805)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-14

Unauthenticated SQL injection in a clinic management system bypasses doctor authentication and exposes patient appointment data, directly impacting healthcare infrastructure confidentiality.

*Deep dive: `TIER_2_CVE-2026-90805.md`*

___________________________________


# **[CVE-2026-90840 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-90840)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-14

Unauthenticated admin access in a blood donor management system compromises healthcare data integrity and donor PII.

*Deep dive: `TIER_2_CVE-2026-90840.md`*

___________________________________


# **[CVE-2026-53714 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-53714)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-14

Foundational Kubernetes service mesh/gateway component with unauthenticated internal config/secret exposure, impacting cloud-native deployments across regulated and public sector environments.

*Deep dive: `TIER_2_CVE-2026-53714.md`*

___________________________________


# **[CVE-2026-57578 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-57578)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-14

Critical authorization bypass in a .NET web framework widely used for internal LOB and public-facing services in regulated sectors.

*Deep dive: `TIER_2_CVE-2026-57578.md`*

___________________________________


# **[CVE-2026-76442 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-76442)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-14

General infrastructure flaw in enterprise email gateways, explicitly tied to government and public sector network deployments.

*Deep dive: `TIER_2_CVE-2026-76442.md`*

___________________________________


# **[CVE-2026-90841 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-90841)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-14

Unauthenticated SQLi in a blood donor management system exposes clinical donor PII and credentials, directly impacting healthcare digital infrastructure.

*Deep dive: `TIER_2_CVE-2026-90841.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine