# **Infrastructure Daily Brief: 2026-10-26**

**Infrastructure Daily Report TLP:GREEN Alert Id: 94a061f6 2026-10-27 12:16:02**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-110475 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-116587 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-110474 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-116112 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-116253 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-116257 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-116540 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-85297 (Tier 2)                                                          | 3.k      |
| Threats    | Joint advisory: state-sponsored spear-phishing campaigns targeting ...           | 1.a      |
| Threats    | Reports & advisories | National Cyber Security Centre                            | 1.a      |
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.j.3    |
| Threats    | Operation HookedWing: 4-Year Campaign Compromises 500 Orgs - Phishing            | 1.e      |
| Threats    | AI-enabled device code phishing campaign exploits OAuth flow for account takeove | 1.j.3    |
| Threats    | Device Code Phishing: How EvilTokens Hit 12,000+ Inboxes                         | 1.j.3    |
| Threats    | Coordinated phishing campaign targeting UK public sector organisations           | 1.e      |
| Threats    | GhostCode: How Device-Code Phishing Is Hijacking Microsoft 365 Accounts          | 1.j.3    |
| Threats    | CVE-2026-116163                                                                  | 1.b      |
| Threats    | CVE-2026-89209                                                                   | 1.b      |
| Threats    | CVE-2026-116006                                                                  | 1.b      |
| Threats    | CVE-2026-115910                                                                  | 1.b      |
| Threats    | CVE-2026-71455                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Joint advisory: state-sponsored spear-phishing campaigns targeting ...](https://suvat.uk/blog/five-eyes-advisory.html)**

**PIR: 1.a**

Source: ketch Published: 2026-10-26

A Five Eyes joint advisory warns critical infrastructure operators of state-sponsored spear-phishing campaigns targeting energy, transport, and water sectors. The threat actors deploy highly tailored lures and malicious attachments to establish initial access. Infrastructure defenders should review email filtering rules, segment OT/IT networks, and monitor for lateral movement indicators aligned with the provided IOCs.

___________________________________


# **[Reports & advisories | National Cyber Security Centre](https://www.ncsc.gov.uk/section/keep-up-to-date/reports-advisories)**

**PIR: 1.a**

Source: ketch Published: 2026-10-26

The NCSC and international partners expose a Russian state-supported zero-click phishing campaign targeting Western organizations. The LAUNDRY BEAR threat group utilizes sophisticated exploit chains delivered via seemingly benign communications to bypass user interaction requirements. Infrastructure teams should prioritize patching known vulnerabilities, implementing network segmentation, and deploying advanced endpoint detection to mitigate silent compromises.

___________________________________


# **[Inside an AI‑enabled device code phishing campaign](https://microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026)**

**PIR: 1.j.3**

Source: ketch Published: 2026-10-26

Microsoft security researchers detail a sophisticated campaign leveraging AI-generated lures to exploit OAuth device code flows. Attackers trick users into entering device codes on fraudulent portals, bypassing MFA and enabling full account takeover. The report provides technical indicators, mitigation strategies for identity providers, and guidance for monitoring anomalous OAuth consent events.

___________________________________


# **[Operation HookedWing: 4-Year Campaign Compromises 500 Orgs - Phishing](https://dailysecurityreview.com/phishing/operation-hookedwing-4-year-campaign-compromises-500-orgs/)**

**PIR: 1.e**

Source: ketch Published: 2026-10-26

SOCRadar reveals Operation HookedWing, a long-running credential-harvesting operation that compromised thousands of accounts across critical infrastructure sectors. Attackers leveraged GitHub Pages to host persistent phishing infrastructure, evading traditional blocklists. The report details campaign timelines, targeted verticals, and defensive recommendations for monitoring code hosting platforms and enforcing passwordless authentication.

___________________________________


# **[AI-enabled device code phishing campaign exploits OAuth flow for account takeover](https://helpnetsecurity.com/2026/04/07/microsoft-device-code-phishing-campaign)**

**PIR: 1.j.3**

Source: ketch Published: 2026-10-26

This analysis breaks down how threat actors abuse the Microsoft device code authentication mechanism to circumvent multi-factor authentication. By hosting fake login pages that request device codes, attackers gain persistent access to enterprise accounts. The article outlines detection rules for SIEM platforms, recommended conditional access policies, and steps to revoke compromised OAuth grants.

___________________________________


# **[Device Code Phishing: How EvilTokens Hit 12,000+ Inboxes](https://ctiacademy.io/blog/device-code-phishing)**

**PIR: 1.j.3**

Source: ketch Published: 2026-10-26

CTIA Academy examines the EvilTokens campaign, which successfully delivered device code phishing lures to over 12,000 corporate inboxes. The report highlights the technical mechanics of token theft, the role of compromised legitimate domains in hosting phishing pages, and actionable defense playbooks for email security gateways and identity protection teams.

___________________________________


# **[Coordinated phishing campaign targeting UK public sector organisations](https://suvat.uk/blog/public-sector-phishing.html)**

**PIR: 1.e**

Source: ketch Published: 2026-10-26

SUVAT identifies a coordinated credential-harvesting campaign targeting UK public sector entities, including NHS trusts and local authorities. Attackers spoof official government domains and deploy realistic email lures to capture staff credentials. Defenders should implement strict DMARC enforcement, monitor for domain impersonation, and enforce multi-factor authentication across all public-facing identity portals.

___________________________________


# **[GhostCode: How Device-Code Phishing Is Hijacking Microsoft 365 Accounts](https://9to5windows.com/ghostcode-device-code-phishing-microsoft-365-accounts)**

**PIR: 1.j.3**

Source: ketch Published: 2026-10-26

GhostCode represents a persistent threat actor group specializing in device code phishing against Microsoft 365 tenants. The campaign uses highly convincing templates and automated infrastructure to harvest codes at scale. Defenders are advised to audit OAuth app permissions, enforce device compliance policies, and monitor for unusual sign-in patterns originating from unfamiliar IP ranges.

___________________________________


# **[CVE-2026-116163](https://nvd.nist.gov/vuln/detail/CVE-2026-116163)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-25

Parse Server before 8.6.102 and 9.0.0 before 9.10.5-alpha.2 contains an authentication bypass because the validateSetUp, validateLogin, and validateUpdate methods of custom adapters subclassing AuthAdapter are never called, and an inherited default that accepts any authData is used instead. Attackers can supply arbitrary authData to sign up, link identities, log in as existing users, or skip custom additional authentication factors.

___________________________________


# **[CVE-2026-89209](https://nvd.nist.gov/vuln/detail/CVE-2026-89209)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-26

A vulnerability has been identified in Mendix SAML (Mendix 10 compatible) (All versions < V4.2.4), Mendix SAML (Mendix 11 compatible) (All versions < V4.2.4), Mendix SAML (Mendix 9 compatible) (All versions < V3.6.29). Affected versions of the module do not properly protect against SAML assertion replay in IdP-initiated authentication flows. This could allow unauthenticated remote attackers to gain unauthorized access to the application by replaying a valid SAML response.

___________________________________


# **[CVE-2026-116006](https://nvd.nist.gov/vuln/detail/CVE-2026-116006)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-25

A vulnerability was detected in YunaiV/zhijiantianya ruoyi-vue-pro up to 2026.09. The affected element is an unknown function of the file AuthController.java of the component SMS Code Verification. The manipulation of the argument mobile/code results in improper authentication. The attack can be launched remotely. The exploit is now public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

___________________________________


# **[CVE-2026-115910](https://nvd.nist.gov/vuln/detail/CVE-2026-115910)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-26

Python Social Auth is a social authentication and registration mechanism. Prior to 6.2.0, OpenIdConnectAuth in social_core/backends/open_id_connect.py uses get_and_store_nonce to place the OpenID Connect nonce in a shared OpenIdConnectAssociation table, and get_nonce and validate_claims verify only that the nonce exists and has not expired rather than binding it to the browser session and OAuth state that initiated the login. An attacker who obtains a victim's unused authorization code can start

___________________________________


# **[CVE-2026-71455](https://nvd.nist.gov/vuln/detail/CVE-2026-71455)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-26

Cleartext storage of sensitive information in memory vulnerability in Johnson Controls Kantech Entrapass allows Retrieve Embedded Sensitive Data.

This issue affects Kantech Entrapass: before 9.20.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-110475 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-110475)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-26

Unauthenticated authentication bypass in a BFSI debt collection platform enables full admin takeover and PII/financial data exfiltration, directly impacting national financial infrastructure.

*Deep dive: `TIER_2_CVE-2026-110475.md`*

___________________________________


# **[CVE-2026-116587 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-116587)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-26

Directly impacts Digital Identity infrastructure by enabling remote DoS on JWT/JWK parsing in widely deployed Go-based identity providers and API gateways.

*Deep dive: `TIER_2_CVE-2026-116587.md`*

___________________________________


# **[CVE-2026-110474 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-110474)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-26

Hardcoded API key in a BFSI-focused AI call centre app enables unauthenticated exfiltration of financial customer data and call recordings, directly impacting Finance sector compliance and operations.

*Deep dive: `TIER_2_CVE-2026-110474.md`*

___________________________________


# **[CVE-2026-116112 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-116112)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-26

Unauthenticated SQLi in a public-facing medical appointment system exposes patient records and enables unauthorized doctor account creation.

*Deep dive: `TIER_2_CVE-2026-116112.md`*

___________________________________


# **[CVE-2026-116253 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-116253)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-26

Unauthenticated remote code injection in DedeCMS, a CMS widely deployed by Chinese government agencies and public institutions for official web portals.

*Deep dive: `TIER_2_CVE-2026-116253.md`*

___________________________________


# **[CVE-2026-116257 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-116257)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-26

Finance sector relevance: self-hosted billing platform handling payment processor integrations, invoices, and customer financial data, with unauthenticated admin takeover risk during deployment.

*Deep dive: `TIER_2_CVE-2026-116257.md`*

___________________________________


# **[CVE-2026-116540 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-116540)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-26

Foundational TLS library for enterprise Java stacks underpins Finance, Government, Healthcare, and Identity services; DoS risk during key rotation impacts regulated public-facing infrastructure.

*Deep dive: `TIER_2_CVE-2026-116540.md`*

___________________________________


# **[CVE-2026-85297 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-85297)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-26

Foundational GCP deployment tool (Cloud Run MCP) with bucket squatting flaw impacting CI/CD and AI workflows for government, finance, and enterprise cloud infrastructure.

*Deep dive: `TIER_2_CVE-2026-85297.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine