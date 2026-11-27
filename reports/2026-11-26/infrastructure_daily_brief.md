# **Infrastructure Daily Brief: 2026-11-26**

**Infrastructure Daily Report TLP:GREEN Alert Id: 269cbdd6 2026-11-27 12:02:57**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2017-20291 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-124843 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-130637 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-137579 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-137581 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-137582 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-124840 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-124842 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-134705 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-137500 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-137523 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-137536 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-137550 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-137552 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-137559 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-137560 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-137564 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-137580 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-137583 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-52803 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-123910 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-123911 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-124844 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-137389 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-137390 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-137481 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-137551 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-135205 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-137457 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-137478 (Tier 2)                                                         | 3.k      |
| Threats    | The hidden network: Inside the phishing infrastructure ecosystem powering global | 1.a      |
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.j.3    |
| Threats    | Unmasking EvilTokens: Getting to the root of device code phishing                | 1.j.3    |
| Threats    | Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale              | 1.j.3    |
| Threats    | Microsoft 365 device code phishing campaign bypasses password stealing | RL Blog | 1.j.3    |
| Threats    | Resurgence of a multi‑stage AiTM phishing and BEC campaign abusing SharePoint    | 1.b      |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US        | 1.c      |
| Threats    | High volume phishing campaign uses Microsoft 365 outage lures to target multiple | 1.a      |
| Threats    | CVE-2026-123903                                                                  | 1.b      |
| Threats    | CVE-2026-137499                                                                  | 1.b      |
| Threats    | CVE-2026-135384                                                                  | 1.b      |
| Threats    | CVE-2026-136916                                                                  | 1.b      |
| Threats    | CVE-2026-80283                                                                   | 1.b      |
| Threats    | CVE-2026-80247                                                                   | 1.b      |
| Threats    | CVE-2026-80361                                                                   | 1.b      |
| Threats    | CVE-2026-80291                                                                   | 1.b      |
| Threats    | CVE-2026-80287                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime](https://microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime)**

**PIR: 1.a**

Source: ketch Published: 2026-11-26

This analysis dissects the underground infrastructure supporting large-scale phishing operations, revealing how threat actors leverage bulletproof hosting, domain generation algorithms, and proxy networks to evade takedowns. Defenders can use these insights to enhance DNS sinkholing, improve proxy detection rules, and prioritize infrastructure-level blocking over endpoint-only controls.

___________________________________


# **[Inside an AI‑enabled device code phishing campaign](https://microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign)**

**PIR: 1.j.3**

Source: ketch Published: 2026-11-26

This campaign utilizes AI-generated landing pages and automated device code flows to bypass traditional email filters and credential harvesting defenses. Attackers trick users into authorizing malicious applications via Microsoft’s device code authentication endpoint, granting direct token access without passwords. Infrastructure defenders should monitor OAuth consent logs, restrict device code flows to approved apps, and deploy AI-detection heuristics.

___________________________________


# **[Unmasking EvilTokens: Getting to the root of device code phishing](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/)**

**PIR: 1.j.3**

Source: ketch Published: 2026-11-26

EvilTokens is a novel device code phishing framework that automates token theft by exploiting OAuth 2.0 authorization flows. The tool enables attackers to silently acquire long-lived access tokens, bypassing password resets and MFA prompts. Infrastructure teams must audit OAuth application registrations, enforce token lifetime restrictions, and deploy identity protection solutions that detect anomalous consent grants.

___________________________________


# **[Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale](https://microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale)**

**PIR: 1.j.3**

Source: ketch Published: 2026-11-26

Tycoon2FA represents a sophisticated Adversary-in-the-Middle kit that intercepts multi-factor authentication tokens in real-time, rendering traditional MFA ineffective. The kit operates at scale by proxying user sessions and dynamically generating login pages. Defenders must implement phishing-resistant MFA methods like FIDO2 security keys and deploy conditional access policies that block legacy authentication protocols.

___________________________________


# **[Microsoft 365 device code phishing campaign bypasses password stealing | RL Blog](https://www.reversinglabs.com/blog/device-code-phishing-campaign)**

**PIR: 1.j.3**

Source: ketch Published: 2026-11-26

ReversingLabs analyzes a campaign that bypasses password-stealing mechanisms by directly targeting Microsoft 365 device code authentication endpoints. Attackers use automated scripts to harvest authorization codes and exchange them for valid access tokens. Infrastructure defenders should implement conditional access policies that restrict device code usage, monitor for high-frequency token exchanges, and deploy network-level blocking for known malicious OAuth endpoints.

___________________________________


# **[Resurgence of a multi‑stage AiTM phishing and BEC campaign abusing SharePoint](https://microsoft.com/en-us/security/blog/2026/01/21/multistage-aitm-phishing-bec-campaign-abusing-sharepoint)**

**PIR: 1.b**

Source: ketch Published: 2026-11-26

Threat actors combine AiTM proxies with Business Email Compromise tactics, abusing SharePoint permissions to exfiltrate sensitive data after initial account compromise. The multi-stage approach evades standard email security by leveraging legitimate cloud storage APIs. Defenders should enforce least-privilege SharePoint access, monitor for anomalous file sharing patterns, and implement continuous identity risk scoring.

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.c**

Source: ketch Published: 2026-11-26

Proofpoint details how device code phishing has evolved from simple credential harvesting to full identity takeover, leveraging automated consent flows and token theft. The technique circumvents traditional email security and password-based MFA. Defenders should prioritize zero-trust identity architectures, monitor for suspicious OAuth consent events, and educate users on recognizing device code authorization prompts.

___________________________________


# **[High volume phishing campaign uses Microsoft 365 outage lures to target multiple industry sectors](https://microsoft.com/en-us/security/blog/2026/11/16/high-volume-phishing-campaign-uses-microsoft-365-outage-lures)**

**PIR: 1.a**

Source: ketch Published: 2026-11-26

Attackers are exploiting widespread Microsoft 365 service disruptions to distribute high-volume phishing emails mimicking official outage notifications. The campaign targets multiple sectors by leveraging trusted sender domains and urgent language to drive credential harvesting. Infrastructure teams should monitor for anomalous outbound traffic to newly registered domains and validate M365 status through official channels.

___________________________________


# **[CVE-2026-123903](https://nvd.nist.gov/vuln/detail/CVE-2026-123903)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-26

VMware vCenter contains an authentication bypass vulnerability in the VMware Directory Service. Broadcom has evaluated the severity of this issue to be in the Critical severity range with a maximum CVSSv3 base score of 9.8.
Affected versions:
VMware vCenter Server 9.1.x.x: fixed in 9.1.2
VMware vCenter Server 9.0.x.x: fixed in 9.0.2.0300
VMware vCenter Server 8.0: fixed in 8.0 U3m
VMware Cloud Foundation 5.x: fixed in 5.2.5
VMware Telco Cloud Platform 3.0: fixed in KB463501
VMware Telco Cloud Pl

___________________________________


# **[CVE-2026-137499](https://nvd.nist.gov/vuln/detail/CVE-2026-137499)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-26

Budibase from 3.41.0 before 4.0.0 contains an authentication bypass vulnerability that allows unauthenticated attackers to take over password-less global Builder accounts via unverified-email OIDC/SSO account linking. Attackers can assert a victim's email with email_verified=false at a trusted IdP, bypassing the isAccountLinkable allowlist to control all apps, datasources, and automations.

___________________________________


# **[CVE-2026-135384](https://nvd.nist.gov/vuln/detail/CVE-2026-135384)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-26

Improper authentication in OIDC bearer token verification in Canonical LXD before 5.0.12, 5.21.10, 6.10.2 allows a remote attacker holding a token signed by the configured identity provider to authenticate to the LXD API and gain unauthorized control or impersonate users via presenting tokens issued for other applications, ID tokens, or unverified email claims.

___________________________________


# **[CVE-2026-136916](https://nvd.nist.gov/vuln/detail/CVE-2026-136916)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-25

HortusFox (hortusfox-web) through 6.4 contains a password reset poisoning vulnerability in UserModel::restorePassword that builds reset links from the client-controlled Host header. Unauthenticated attackers can request a reset with a forged Host header to capture the victim's reset token and take over accounts including administrators.

___________________________________


# **[CVE-2026-80283](https://nvd.nist.gov/vuln/detail/CVE-2026-80283)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-25

Dell Secure Connect Gateway (SCG) Virtual Edition, versions prior to 5.36.00.16, contains a Missing Authentication for Critical Function vulnerability. An attacker with local access could potentially exploit this vulnerability, leading to unauthorized disclosure of sensitive information, unauthorized modification of system resources, and execution of privileged actions that could lead to compromise of the appliance.

___________________________________


# **[CVE-2026-80247](https://nvd.nist.gov/vuln/detail/CVE-2026-80247)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-25

Dell Secure Connect Gateway (SCG) Virtual Edition, versions prior to 5.36.00.16, contains a Missing Authentication for Critical Function vulnerability. An attacker with local access to the appliance could potentially exploit this vulnerability, leading to unauthorized access to sensitive information, modification of protected resources, and execution of privileged operations within the appliance security context, potentially resulting in compromise of confidentiality, integrity, and availability

___________________________________


# **[CVE-2026-80361](https://nvd.nist.gov/vuln/detail/CVE-2026-80361)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-25

Dell Secure Connect Gateway (SCG) Virtual Edition, versions prior to 5.36.00.16, contains a Missing Authentication for Critical Function vulnerability. An attacker with local access to the appliance could potentially exploit this vulnerability, leading to unauthorized access to sensitive information, unauthorized modification of application data, and execution of actions with elevated privileges within the appliance environment.

___________________________________


# **[CVE-2026-80291](https://nvd.nist.gov/vuln/detail/CVE-2026-80291)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-25

Dell Secure Connect Gateway (SCG) Virtual Edition, versions prior to 5.36.00.16, contains a Missing Authentication for Critical Function vulnerability. A local attacker could potentially exploit this vulnerability, leading to unauthorized access to sensitive data, modification of critical resources, and disruption of appliance functionality.

___________________________________


# **[CVE-2026-80287](https://nvd.nist.gov/vuln/detail/CVE-2026-80287)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-25

Dell Secure Connect Gateway (SCG) Virtual Edition, versions prior to 5.36.00.16, contains a Missing Authentication for Critical Function vulnerability. An attacker with local access could potentially exploit this vulnerability, leading to unauthorized access to system resources, disclosure of sensitive information, modification of protected configurations, and execution of privileged operations.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2017-20291 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2017-20291)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-26

High-severity XXE in Broadcom SiteMinder SSO federation services directly compromises enterprise authentication and identity assertion boundaries.

*Deep dive: `TIER_2_CVE-2017-20291.md`*

___________________________________


# **[CVE-2026-124843 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-124843)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-26

Hard-coded crypto fallback in SEPPmail SEG enables unauthenticated token forgery and account takeover, directly impacting Digital Identity, Government, and Finance secure communications.

*Deep dive: `TIER_2_CVE-2026-124843.md`*

___________________________________


# **[CVE-2026-130637 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-130637)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-26

Pre-auth SSTI in internet-facing secure email gateway widely deployed in Swiss government and healthcare sectors, enabling unauthenticated account takeover.

*Deep dive: `TIER_2_CVE-2026-130637.md`*

___________________________________


# **[CVE-2026-137579 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-137579)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-26

Directly compromises JWT/JWE cryptographic foundations used in modern authentication and session management, impacting Digital Identity infrastructure across regulated and public services.

*Deep dive: `TIER_2_CVE-2026-137579.md`*

___________________________________


# **[CVE-2026-137581 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-137581)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-26

Directly impacts Digital Identity infrastructure by enabling DoS against JWT validation services foundational to OAuth/OIDC/SSO ecosystems used in government and enterprise access portals.

*Deep dive: `TIER_2_CVE-2026-137581.md`*

___________________________________


# **[CVE-2026-137582 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-137582)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-26

Directly impacts JWT/OAuth/OIDC processing in public-facing authentication services, threatening availability of core Digital Identity infrastructure.

*Deep dive: `TIER_2_CVE-2026-137582.md`*

___________________________________


# **[CVE-2026-124840 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-124840)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-26

TIER 2 session confusion in SEPPmail SEG enables account takeover via security questions, directly impacting Digital Identity and secure email infrastructure in public sector and regulated industries.

*Deep dive: `TIER_2_CVE-2026-124840.md`*

___________________________________


# **[CVE-2026-124842 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-124842)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-26

Impacts Digital Identity by allowing unauthenticated forced password resets and API token revocation in enterprise email gateways, disrupting credential integrity and access controls.

*Deep dive: `TIER_2_CVE-2026-124842.md`*

___________________________________


# **[CVE-2026-134705 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-134705)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-26

TIER 2 privilege escalation in a widely deployed WordPress OTP/MFA plugin directly compromises authentication workflows and credential verification, impacting the Digital Identity sector.

*Deep dive: `TIER_2_CVE-2026-134705.md`*

___________________________________


# **[CVE-2026-137500 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-137500)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-26

Privilege escalation in a low-code platform widely adopted by government and healthcare for citizen portals and internal workflows, risking full tenant takeover.

*Deep dive: `TIER_2_CVE-2026-137500.md`*

___________________________________


# **[CVE-2026-137523 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-137523)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-26

Default-vulnerable Google SSO bypass in ToolJet, an internal platform widely deployed across government, healthcare, and finance for administrative workflows and dashboards.

*Deep dive: `TIER_2_CVE-2026-137523.md`*

___________________________________


# **[CVE-2026-137536 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-137536)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-26

Critical OAuth SSO authentication bypass in a low-code platform, directly impacting Digital Identity workflows and internal application security.

*Deep dive: `TIER_2_CVE-2026-137536.md`*

___________________________________


# **[CVE-2026-137550 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-137550)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-26

TIER 2 authorization bypass in Frappe Framework compromises data integrity and enables privilege escalation in ERP/CRM systems widely deployed across Finance and Government digital infrastructure.

*Deep dive: `TIER_2_CVE-2026-137550.md`*

___________________________________


# **[CVE-2026-137552 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-137552)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-26

Directly impacts Digital Identity and general infrastructure by bypassing 2FA and session controls in the widely deployed Frappe web framework via an OAuth2 password grant flaw.

*Deep dive: `TIER_2_CVE-2026-137552.md`*

___________________________________


# **[CVE-2026-137559 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-137559)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-26

Impacts Digital Identity infrastructure by enabling CPU exhaustion DoS on JWT-based authentication and session management endpoints.

*Deep dive: `TIER_2_CVE-2026-137559.md`*

___________________________________


# **[CVE-2026-137560 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-137560)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-26

Impacts core Digital Identity infrastructure by enabling unauthenticated DoS against JWT/DPoP verification in OAuth/OIDC providers and public-facing authentication endpoints.

*Deep dive: `TIER_2_CVE-2026-137560.md`*

___________________________________


# **[CVE-2026-137564 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-137564)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-26

Directly impacts the Digital Identity sector by compromising JWT token integrity and authentication mechanisms in public-facing web applications and APIs.

*Deep dive: `TIER_2_CVE-2026-137564.md`*

___________________________________


# **[CVE-2026-137580 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-137580)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-26

Impacts Digital Identity infrastructure by enabling DoS against JWT-based authentication and session management endpoints via CPU exhaustion.

*Deep dive: `TIER_2_CVE-2026-137580.md`*

___________________________________


# **[CVE-2026-137583 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-137583)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-26

Directly impacts financial payment orchestration infrastructure by allowing unauthenticated webhook forgery to manipulate transaction states, posing a high fraud risk to merchant operations.

*Deep dive: `TIER_2_CVE-2026-137583.md`*

___________________________________


# **[CVE-2026-52803 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-52803)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-26

Session fixation in self-hosted Git platform undermines authentication and access control, directly impacting Digital Identity assurance and sensitive codebases in government/finance sectors.

*Deep dive: `TIER_2_CVE-2026-52803.md`*

___________________________________


# **[CVE-2026-123910 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-123910)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-26

General infrastructure: unauthenticated hypervisor RCE in VMware ESXi, foundational to government, finance, and healthcare datacenters.

*Deep dive: `TIER_2_CVE-2026-123910.md`*

___________________________________


# **[CVE-2026-123911 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-123911)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-26

Critical unauthenticated RCE in VMware ESXi hypervisor, a foundational compute layer underpinning government, finance, and healthcare digital infrastructure.

*Deep dive: `TIER_2_CVE-2026-123911.md`*

___________________________________


# **[CVE-2026-124844 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-124844)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-26

Tier 2 unauthenticated DoS in a foundational email gateway that underpins government and regulated sector communications.

*Deep dive: `TIER_2_CVE-2026-124844.md`*

___________________________________


# **[CVE-2026-137389 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-137389)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-26

Enterprise email gateway RCE impacting government and financial sector communications infrastructure; requires authentication but poses high operational risk to regulated mail flows.

*Deep dive: `TIER_2_CVE-2026-137389.md`*

___________________________________


# **[CVE-2026-137390 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-137390)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-26

Enterprise email archiving platform widely deployed across government, finance, and healthcare for compliance; authenticated RCE enables full server compromise and data exfiltration.

*Deep dive: `TIER_2_CVE-2026-137390.md`*

___________________________________


# **[CVE-2026-137481 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-137481)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-26

Critical authorization bypass in a widely deployed edge reverse proxy that underpins public-facing digital services across government, finance, and healthcare sectors.

*Deep dive: `TIER_2_CVE-2026-137481.md`*

___________________________________


# **[CVE-2026-137551 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-137551)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-26

General-purpose framework (Frappe/ERPNext) underpins Government and Finance deployments; RCE via Jinja sandbox bypass impacts regulated web platforms.

*Deep dive: `TIER_2_CVE-2026-137551.md`*

___________________________________


# **[CVE-2026-135205 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-135205)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-26

General infrastructure web framework flaw impacting public-facing APIs; report explicitly advises DPI organizations to prioritize patching.

*Deep dive: `TIER_2_CVE-2026-135205.md`*

___________________________________


# **[CVE-2026-137457 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-137457)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-26

General infrastructure remote access tooling deployed in government and enterprise environments; unauthenticated input injection enables lateral movement on internal management networks.

*Deep dive: `TIER_2_CVE-2026-137457.md`*

___________________________________


# **[CVE-2026-137478 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-137478)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-26

TIER 2 authentication bypass in Traefik edge proxy impacts public-facing service gateways commonly used in regulated/cloud-native DPI deployments.

*Deep dive: `TIER_2_CVE-2026-137478.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine