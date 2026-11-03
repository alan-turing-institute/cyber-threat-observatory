# **Infrastructure Daily Brief: 2026-11-02**

**Infrastructure Daily Report TLP:GREEN Alert Id: 12955818 2026-11-03 10:58:44**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-99231 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-106804 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-111048 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-119731 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-119732 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-120442 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-119736 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-120459 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-28588 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-116606 (Tier 2)                                                         | 3.k      |
| Threats    | The hidden network: Inside the phishing infrastructure ecosystem powering global | 1.d      |
| Threats    | Joint advisory: state-sponsored spear-phishing campaigns targeting ...           | 1.e      |
| Threats    | Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale | Microsoft  | 1.b      |
| Threats    | Inside Wazza: A Newly Observed Device Code Phishing Kit Targeting Microsoft 365  | 1.c      |
| Threats    | Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Se | 1.c      |
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.f      |
| Threats    | Operation HookedWing: Four-Year Phishing Campaign Hits 500 ...                   | 1.e      |
| Threats    | Talos: Attackers Refine Phishing Playbook To Target Critical ...                 | 1.e      |
| Threats    | CVE-2026-105769                                                                  | 1.b      |
| Threats    | CVE-2026-88810                                                                   | 1.b      |
| Threats    | CVE-2026-82840                                                                   | 1.b      |
| Threats    | CVE-2024-9517                                                                    | 1.b      |
| Threats    | CVE-2026-120263                                                                  | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime/)**

**PIR: 1.d**

Source: ketch Published: 2026-11-02

Microsoft Security researchers dissect the sprawling infrastructure ecosystem that underpins modern phishing campaigns. The report details how threat actors leverage compromised legitimate domains, cloud hosting services, and dynamic DNS providers to rapidly deploy and rotate phishing pages. Defenders gain actionable insights into tracking infrastructure footprints, identifying shared hosting patterns, and implementing proactive takedown strategies to disrupt the supply chain before credentials 

___________________________________


# **[Joint advisory: state-sponsored spear-phishing campaigns targeting ...](https://suvat.uk/blog/five-eyes-advisory.html)**

**PIR: 1.e**

Source: ketch Published: 2026-11-02

A Five Eyes joint advisory warns of ongoing state-sponsored spear-phishing campaigns specifically targeting energy, transport, and water sectors. The report outlines attacker TTPs, including highly tailored lures, malicious document attachments, and credential harvesting portals. Critical infrastructure operators are advised to review email filtering rules, enforce strict conditional access policies, and monitor for anomalous authentication attempts to mitigate identity compromise risks.

___________________________________


# **[Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale/)**

**PIR: 1.b**

Source: ketch Published: 2026-11-02

This analysis exposes the Tycoon2FA kit, a sophisticated Adversary-in-the-Middle tool that bypasses multi-factor authentication by proxying real-time sessions between victims and legitimate services. The article breaks down the kit architecture, automation capabilities, and deployment tactics. Infrastructure defenders learn how to detect proxy traffic patterns, identify malicious reverse-proxy configurations, and enforce session-binding controls to neutralize AiTM attacks.

___________________________________


# **[Inside Wazza: A Newly Observed Device Code Phishing Kit Targeting Microsoft 365 Accounts](https://www.levelblue.com/blogs/spiderlabs-blog/inside-wazza-a-newly-observed-device-code-phishing-kit-targeting-microsoft-365-accounts)**

**PIR: 1.c**

Source: ketch Published: 2026-11-02

Level Blue researchers analyze the Wazza kit, a novel device code phishing tool designed to bypass MFA by tricking users into authorizing attacker-controlled sessions. The article details the kit user interface, backend token exchange mechanisms, and distribution methods. Defenders receive guidance on monitoring for suspicious device code authorization requests, blocking malicious redirect URIs, and educating users on recognizing device code prompts.

___________________________________


# **[Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/)**

**PIR: 1.c**

Source: ketch Published: 2026-11-02

Microsoft Security investigates EvilTokens, a prevalent device code phishing framework that exploits OAuth 2.0 device authorization flows. The report explains how attackers harvest valid tokens without requiring passwords or MFA codes. Infrastructure teams are provided with detection queries for Azure AD logs, recommendations for restricting device code grant types, and strategies to implement token binding to prevent session hijacking.

___________________________________


# **[Inside an AI‑enabled device code phishing campaign](https://microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026)**

**PIR: 1.f**

Source: ketch Published: 2026-11-02

This Microsoft Security blog post examines a campaign leveraging generative AI to automate device code phishing at scale. Attackers use AI to craft highly convincing prompts, dynamically generate landing pages, and adapt messaging in real-time. The article highlights infrastructure indicators, AI-generated content detection techniques, and defensive measures such as enhanced URL filtering and user awareness training focused on AI-assisted social engineering.

___________________________________


# **[Operation HookedWing: Four-Year Phishing Campaign Hits 500 ...](https://cybersecurityjournal.ca/techtalk/84066-operation-hookedwing-phishing-aviation-critical-infrastructure-2026-05-11/)**

**PIR: 1.e**

Source: ketch Published: 2026-11-02

SecurityWeek reports on Operation HookedWing, a persistent credential-harvesting campaign active since 2022 targeting aviation, government, and critical infrastructure sectors. The analysis covers the campaign infrastructure evolution, domain registration patterns, and phishing page templates. Defenders are advised to monitor for known malicious domains, implement strict email authentication, and review historical login anomalies for compromised accounts.

___________________________________


# **[Talos: Attackers Refine Phishing Playbook To Target Critical ...](https://securityledger.com/2026/07/talos-attackers-refine-phishing-playbook-to-target-critical-infrastructure/)**

**PIR: 1.e**

Source: ketch Published: 2026-11-02

Cisco Talos details how threat actors are refining phishing techniques to specifically target healthcare, local government, and critical infrastructure organizations. The report highlights the abuse of trusted collaboration platforms, cloud storage services, and legitimate SaaS integrations to evade detection. Infrastructure defenders gain insights into identifying malicious OAuth applications, monitoring for unusual API activity, and hardening identity perimeters against evolving phishing tacti

___________________________________


# **[CVE-2026-105769](https://nvd.nist.gov/vuln/detail/CVE-2026-105769)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-02

kaniko before 1.25.20 can send a Microsoft Entra ID (Azure AD) access token for Azure Resource Manager to an attacker-controlled registry host. kaniko uses the Azure Container Registry credential helper github.com/chrismellard/docker-credential-acr-env, which decides whether a host is an ACR registry with an unanchored regular expression, so any hostname containing .azurecr.io, .azurecr.cn, .azurecr.de or .azurecr.us is accepted. kaniko consults this helper for any registry that has no credentia

___________________________________


# **[CVE-2026-88810](https://nvd.nist.gov/vuln/detail/CVE-2026-88810)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-02

A privilege escalation issue was discovered in Rancher Manager's role-based access control. The inheritedNamespacedRules field of a GlobalRole propagates permissions into named namespaces of every downstream cluster managed by the Rancher instance, but it was not subject to the privilege-escalation validation applied to the other permission-carrying fields of a GlobalRole. As a result, a non-administrative user could be granted, through a global role  binding, permissions in downstream clusters 

___________________________________


# **[CVE-2026-82840](https://nvd.nist.gov/vuln/detail/CVE-2026-82840)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-01

Session fixation in Apache Wicket.

org.apache.wicket.authroles.authentication.AuthenticatedWebSession is the authentication base class of Wicket's role-based security module, and its signIn(String, String) method is the entry point through which an application authenticates a session. Renewing the container session id at that point is the standard defence against an attacker who has fixed a session id in a victim's browser, and Wicket provides that renewal as org.apache.wicket.Session#changeSes

___________________________________


# **[CVE-2024-9517](https://nvd.nist.gov/vuln/detail/CVE-2024-9517)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-02

The refresh token grant type in WSO2 products fails to re-validate account status before issuing new access tokens. This weakness allows an attacker to obtain valid access tokens for user accounts even after they have been blocked by the user store, bypassing account lockout mechanisms.

This vulnerability can lead to unauthorized access to user accounts and their associated resources. Attackers can leverage this to perform actions on behalf of blocked users, potentially leading to privilege esc

___________________________________


# **[CVE-2026-120263](https://nvd.nist.gov/vuln/detail/CVE-2026-120263)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-01

When `[oauth2_client].ACCOUNT_LINKING` is set to `auto` (not the default) and registration is enabled, the link-account sign-up form looked up the existing account to link by the user name or email submitted in the form instead of the identity asserted by the OAuth2 provider. An attacker with an account on a configured OAuth2 provider could submit another user's name, link their external identity to that Gitea account and be signed in as it without its password, including as an administrator. Th

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-99231 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-99231)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-02

Foundational Linux kernel vulnerability enabling local privilege escalation across all DPI sectors (Identity, Healthcare, Finance, Government) deployed on servers and cloud infrastructure.

*Deep dive: `TIER_2_CVE-2026-99231.md`*

___________________________________


# **[CVE-2026-106804 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-106804)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-02

General Infrastructure (Telecom): Unauthenticated DoS in Kamailio IMS P-CSCF nodes disrupts VoLTE/VoNR and national emergency calling services.

*Deep dive: `TIER_2_CVE-2026-106804.md`*

___________________________________


# **[CVE-2026-111048 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-111048)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-02

Finance sector relevance: FOSSBilling manages client billing, invoices, and payments; stored XSS enables admin takeover and potential financial data exfiltration in regulated billing environments.

*Deep dive: `TIER_2_CVE-2026-111048.md`*

___________________________________


# **[CVE-2026-119731 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-119731)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-02

Finance sector relevance: unauthenticated payment webhook bypass in an AI accounting platform compromises subscription integrity and financial operations for SMEs.

*Deep dive: `TIER_2_CVE-2026-119731.md`*

___________________________________


# **[CVE-2026-119732 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-119732)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-02

Finance sector SaaS vulnerability allowing unauthorized deletion of invoices and financial records, impacting accounting compliance and transaction integrity for SMEs.

*Deep dive: `TIER_2_CVE-2026-119732.md`*

___________________________________


# **[CVE-2026-120442 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-120442)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-02

Critical JWT authentication bypass in an enterprise RBAC framework directly impacts Digital Identity infrastructure by enabling unauthenticated admin token forgery and full access control takeover.

*Deep dive: `TIER_2_CVE-2026-120442.md`*

___________________________________


# **[CVE-2026-119736 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-119736)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-02

Hard-coded credentials in a payroll/attendance app expose internet-facing MQTT brokers, risking sensitive employee and compensation data in enterprise financial infrastructure.

*Deep dive: `TIER_2_CVE-2026-119736.md`*

___________________________________


# **[CVE-2026-120459 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-120459)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-02

Core JWT library vulnerability enabling authentication bypass; foundational to Digital Identity and enterprise API token handling.

*Deep dive: `TIER_2_CVE-2026-120459.md`*

___________________________________


# **[CVE-2026-28588 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-28588)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-02

TIER 2 local EoP in Android Framework breaks app sandboxing, directly impacting enterprise MDM and secure mobile endpoints deployed across finance, healthcare, and government sectors.

*Deep dive: `TIER_2_CVE-2026-28588.md`*

___________________________________


# **[CVE-2026-116606 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-116606)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-02

Critical authentication bypass in enterprise email security gateways deployed across public sector and regulated environments, enabling unauthenticated configuration takeover.

*Deep dive: `TIER_2_CVE-2026-116606.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine