# **Infrastructure Daily Brief: 2026-11-01**

**Infrastructure Daily Report TLP:GREEN Alert Id: 8f82b160 2026-11-02 02:34:36**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-120232 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-84170 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-95863 (Tier 2)                                                          | 3.k      |
| Threats    | Unmasking EvilTokens: Getting to the root of device code phishing                | 1.d      |
| Threats    | Breaking the code: Multi-stage ‘code of conduct’ phishing campaign leads to AiTM | 1.b      |
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.c      |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover                        | 1.d      |
| Threats    | Joint advisory: state-sponsored spear-phishing campaigns targeting critical infr | 1.e      |
| Threats    | The ‘code of conduct’ phishing campaign: What MSPs need to know right now        | 1.a      |
| Threats    | Storm-2372 conducts device code phishing campaign                                | 1.e      |
| Threats    | Access granted: phishing with device code authorization for account takeover     | 1.d      |
| Threats    | CVE-2026-103898                                                                  | 1.b      |
| Threats    | CVE-2026-82840                                                                   | 1.b      |
| Threats    | CVE-2026-120263                                                                  | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Unmasking EvilTokens: Getting to the root of device code phishing](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/)**

**PIR: 1.d**

Source: ketch Published: 2026-11-01

This analysis dissects the EvilTokens infrastructure, revealing how threat actors automate device code phishing to bypass multi-factor authentication. Defenders will find detailed indicators of compromise, network traffic patterns, and mitigation strategies for OAuth 2.0 device authorization flows. The report emphasizes the need for conditional access policies and real-time token monitoring to prevent silent identity takeover in enterprise environments.

___________________________________


# **[Breaking the code: Multi-stage ‘code of conduct’ phishing campaign leads to AiTM token compromise](https://microsoft.com/en-us/security/blog/2026/05/04/breaking-the-code-multi-stage-code-of-conduct-phishing-campaign-leads-to-aitm)**

**PIR: 1.b**

Source: ketch Published: 2026-11-01

Examines a sophisticated multi-stage campaign leveraging social engineering around corporate compliance to deploy Adversary-in-the-Middle proxies. The article details how attackers capture session tokens in real-time, rendering traditional MFA ineffective. Infrastructure teams are advised to implement token binding, deploy browser isolation, and monitor for anomalous OAuth consent grants to neutralize this evolving identity threat.

___________________________________


# **[Inside an AI‑enabled device code phishing campaign](https://microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign)**

**PIR: 1.c**

Source: ketch Published: 2026-11-01

Explores the integration of generative AI into device code phishing operations, enabling dynamic landing pages and personalized lures at scale. The breakdown highlights automated infrastructure provisioning and evasion techniques used to bypass email security gateways. Defenders should prioritize AI-driven threat detection, enforce strict OAuth scope limitations, and educate users on recognizing AI-crafted authorization prompts.

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.d**

Source: ketch Published: 2026-11-01

Provides a comprehensive overview of how device code phishing has matured into a primary vector for enterprise identity compromise. The report maps the attack lifecycle from initial lure to token exfiltration, emphasizing the limitations of current email filtering. IT infrastructure defenders are guided through architectural adjustments, including conditional access rules, token revocation workflows, and enhanced logging for OAuth endpoints.

___________________________________


# **[Joint advisory: state-sponsored spear-phishing campaigns targeting critical infrastructure](https://suvat.uk/blog/five-eyes-advisory.html)**

**PIR: 1.e**

Source: ketch Published: 2026-11-01

A Five Eyes intelligence advisory detailing coordinated spear-phishing operations by state-sponsored actors against critical infrastructure sectors. The document outlines TTPs, including supply chain manipulation and credential harvesting via malicious attachments. Infrastructure defenders are urged to segment OT/IT networks, enforce strict email attachment sandboxing, and monitor for lateral movement indicators following initial compromise.

___________________________________


# **[The ‘code of conduct’ phishing campaign: What MSPs need to know right now](https://blog.barracuda.com/2026/05/07/code-of-conduct-phishing-campaign-msp-response)**

**PIR: 1.a**

Source: ketch Published: 2026-11-01

Focuses on the operational impact of the ‘code of conduct’ phishing wave on managed service providers and their client infrastructure. The article provides actionable response playbooks, including tenant isolation, credential reset protocols, and detection rules for security information and event management platforms. Essential reading for MSPs managing multi-tenant identity environments under active threat.

___________________________________


# **[Storm-2372 conducts device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/)**

**PIR: 1.e**

Source: ketch Published: 2026-11-01

Documents a targeted campaign by the Storm-2372 threat group utilizing device code authorization flows to infiltrate government and defense contractor networks. The analysis covers infrastructure hosting, domain generation algorithms, and persistence mechanisms. Defenders should review OAuth application permissions, implement just-in-time access controls, and correlate login telemetry with known adversary infrastructure.

___________________________________


# **[Access granted: phishing with device code authorization for account takeover](https://www.proofpoint.com/us/blog/threat-insight/access-granted-phishing-device-code-authorization-account-takeover)**

**PIR: 1.d**

Source: ketch Published: 2026-11-01

Details the technical mechanics behind device code authorization phishing, demonstrating how attackers exploit legitimate OAuth endpoints to bypass perimeter defenses. The report includes packet captures, consent screen manipulation techniques, and recommended detection signatures. Infrastructure teams are advised to audit third-party application integrations and deploy user behavior analytics to flag anomalous authorization requests.

___________________________________


# **[CVE-2026-103898](https://nvd.nist.gov/vuln/detail/CVE-2026-103898)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-31

The Wp Social Login and Register Social Counter plugin for WordPress is vulnerable to Authentication Bypass in all versions up to, and including, 3.2.2. This is due to the social login REST callback registered at `/wp-json/wslu-social-login/type/{provider}/` with `permission_callback => __return_true` locating an existing WordPress account solely by the email string returned from the OAuth provider and calling `wp_set_auth_cookie()` without a password check, while the only verification guard — `

___________________________________


# **[CVE-2026-82840](https://nvd.nist.gov/vuln/detail/CVE-2026-82840)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-01

Session fixation in Apache Wicket.

org.apache.wicket.authroles.authentication.AuthenticatedWebSession is the authentication base class of Wicket's role-based security module, and its signIn(String, String) method is the entry point through which an application authenticates a session. Renewing the container session id at that point is the standard defence against an attacker who has fixed a session id in a victim's browser, and Wicket provides that renewal as org.apache.wicket.Session#changeSes

___________________________________


# **[CVE-2026-120263](https://nvd.nist.gov/vuln/detail/CVE-2026-120263)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-01

When `[oauth2_client].ACCOUNT_LINKING` is set to `auto` (not the default) and registration is enabled, the link-account sign-up form looked up the existing account to link by the user name or email submitted in the form instead of the identity asserted by the OAuth2 provider. An attacker with an account on a configured OAuth2 provider could submit another user's name, link their external identity to that Gitea account and be signed in as it without its password, including as an administrator. Th

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-120232 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-120232)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-01

TIER 2 local privilege escalation in endpoint restoration software deployed on government kiosks and healthcare terminals, posing post-compromise risks to public-facing infrastructure.

*Deep dive: `TIER_2_CVE-2026-120232.md`*

___________________________________


# **[CVE-2026-84170 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-84170)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-01

General-purpose Java web framework deployed in government and critical public services; unbounded uploads risk DoS for citizen-facing applications.

*Deep dive: `TIER_2_CVE-2026-84170.md`*

___________________________________


# **[CVE-2026-95863 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-95863)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-01

Tier 2 passive XSS in Apache Wicket, a foundational Java web framework deployed across enterprise and government-facing applications.

*Deep dive: `TIER_2_CVE-2026-95863.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine