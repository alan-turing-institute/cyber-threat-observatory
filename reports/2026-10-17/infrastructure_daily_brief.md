# **Infrastructure Daily Brief: 2026-10-17**

**Infrastructure Daily Report TLP:GREEN Alert Id: b0ac4212 2026-10-19 00:05:42**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-111880 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-111881 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-111895 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-111898 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-111911 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-111923 (Tier 2)                                                         | 3.k      |
| Threats    | Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale              | 1.b      |
| Threats    | Unmasking EvilTokens: Getting to the root of device code phishing                | 1.c      |
| Threats    | The hidden network: Inside the phishing infrastructure ecosystem powering global | 1.a      |
| Threats    | Device Code Phishing: Turning a Convenience Feature Into an MFA Bypass           | 1.c      |
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.c      |
| Threats    | SideWinder APT Credential Harvesting Campaign — PaaS Platform Abuse at Scale     | 1.d      |
| Threats    | Device Code Phishing: How EvilTokens Hit 12,000+ Inboxes                         | 1.c      |
| Threats    | Three Active Microsoft 365 Phishing Campaigns Targeting Schools and Government A | 1.d      |
| Threats    | CVE-2026-111882                                                                  | 1.b      |
| Threats    | CVE-2026-104627                                                                  | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale](https://www.microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale/)**

**PIR: 1.b**

Source: ketch Published: 2026-10-17

An in-depth technical breakdown of the Tycoon2FA Adversary-in-the-Middle phishing kit, revealing its proxy architecture, session hijacking mechanisms, and deployment tactics. The analysis provides actionable indicators of compromise and mitigation strategies for securing identity providers, blocking reverse proxy traffic, and educating users against real-time credential interception.

___________________________________


# **[Unmasking EvilTokens: Getting to the root of device code phishing](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/)**

**PIR: 1.c**

Source: ketch Published: 2026-10-17

A comprehensive threat intelligence report on the EvilTokens campaign, which abuses Microsoft 365 device code authentication to harvest valid access tokens. Defenders will find detailed telemetry on token exchange patterns, recommended identity protection rules, and architectural adjustments to limit device code abuse across enterprise environments.

___________________________________


# **[The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime](https://www.microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime/)**

**PIR: 1.a**

Source: ketch Published: 2026-10-17

This report dissects the underground infrastructure supporting large-scale phishing operations, detailing how threat actors leverage cloud services, domain generation algorithms, and bulletproof hosting to evade takedowns. IT defenders can use these insights to enhance DNS filtering, implement stricter cloud posture management, and detect anomalous infrastructure patterns before campaigns scale.

___________________________________


# **[Device Code Phishing: Turning a Convenience Feature Into an MFA Bypass](https://www.trendmicro.com/en_us/research/26/g/device-code-phishing.html)**

**PIR: 1.c**

Source: ketch Published: 2026-10-17

Analyzes the technical mechanics behind device code phishing attacks that circumvent multi-factor authentication by leveraging legitimate OAuth flows. The research provides network and identity administrators with detection signatures, conditional access policy templates, and user training frameworks to neutralize MFA-bypass attempts without disrupting legitimate remote access workflows.

___________________________________


# **[Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.c**

Source: ketch Published: 2026-10-17

Explores how attackers weaponize generative AI to craft highly convincing device code phishing lures that bypass traditional email filters. The article outlines the OAuth 2.0 device authorization flow vulnerabilities exploited, offering infrastructure teams guidance on monitoring for suspicious device code requests, implementing conditional access policies, and detecting AI-generated social engineering patterns.

___________________________________


# **[SideWinder APT Credential Harvesting Campaign — PaaS Platform Abuse at Scale](https://intel.breakglass.tech/post/sidewinder-mhil-zeabur)**

**PIR: 1.d**

Source: ketch Published: 2026-10-17

Investigates how the SideWinder APT group leverages Platform-as-a-Service environments to host credential harvesting infrastructure at scale. The analysis covers PaaS abuse patterns, identity provider misconfigurations exploited, and defensive strategies for cloud workload protection, including runtime monitoring, least-privilege access controls, and automated credential rotation protocols.

___________________________________


# **[Device Code Phishing: How EvilTokens Hit 12,000+ Inboxes](https://ctiacademy.io/blog/device-code-phishing)**

**PIR: 1.c**

Source: ketch Published: 2026-10-17

Examines the operational scale and delivery tactics of the EvilTokens device code phishing campaign, highlighting how attackers bypass spam filters and target high-value accounts. Infrastructure teams gain insights into email gateway tuning, threat hunting queries for device code abuse, and incident response playbooks tailored for rapid containment of token-based account takeovers.

___________________________________


# **[Three Active Microsoft 365 Phishing Campaigns Targeting Schools and Government Agencies](https://forsyteit.com/three-active-microsoft-365-phishing-campaigns-targeting-schools-and-government-agencies)**

**PIR: 1.d**

Source: ketch Published: 2026-10-17

Details three concurrent phishing campaigns exploiting Microsoft 365 login pages to harvest credentials from educational and public sector networks. The report includes campaign timelines, infrastructure indicators, and defensive recommendations for implementing multi-factor authentication enforcement, phishing-resistant credentials, and automated takedown procedures for compromised domains.

___________________________________


# **[CVE-2026-111882](https://nvd.nist.gov/vuln/detail/CVE-2026-111882)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-17

phpMyFAQ 3.2.0-alpha before 4.1.9 and 4.2.0-alpha before 4.2.0-beta contains an authentication bypass vulnerability that allows IdP-authenticated users to skip TOTP two-factor authentication through the Keycloak and Entra ID SSO callbacks. Attackers holding a valid or phished IdP identity linked to a 2FA-enabled account can complete the OIDC flow and obtain a fully authenticated session, including administrator accounts.

___________________________________


# **[CVE-2026-104627](https://nvd.nist.gov/vuln/detail/CVE-2026-104627)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-18

The Gitea OpenID association callback in the security settings accepted a positive OpenID 2.0 assertion without checking that the signed-in user had started the linking. Because OpenID 2.0 allows unsolicited assertions, an attacker-controlled OpenID provider could attach the attacker's identity to the account of a signed-in victim who opened a crafted link, and the attacker could then sign in as the victim through OpenID login, which does not apply the local TOTP or WebAuthn checks. The callback

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-111880 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-111880)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-17

Foundational remote access infrastructure (FreeRDP) widely deployed across government, healthcare, and finance VDI environments, with a high-impact NTLM authentication flaw.

*Deep dive: `TIER_2_CVE-2026-111880.md`*

___________________________________


# **[CVE-2026-111881 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-111881)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-17

Foundational remote desktop client widely deployed across Government, Healthcare, and Finance sectors for secure workforce connectivity, making it critical general infrastructure for regulated environments.

*Deep dive: `TIER_2_CVE-2026-111881.md`*

___________________________________


# **[CVE-2026-111895 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-111895)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-17

Directly impacts Digital Identity by exploiting Entra ID SSO/OAuth claim mapping, enabling session hijacking and admin account takeover in enterprise helpdesk deployments.

*Deep dive: `TIER_2_CVE-2026-111895.md`*

___________________________________


# **[CVE-2026-111898 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-111898)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-17

Directly compromises SSO trust boundaries and account linking in Keycloak-integrated deployments, impacting the Digital Identity sector.

*Deep dive: `TIER_2_CVE-2026-111898.md`*

___________________________________


# **[CVE-2026-111911 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-111911)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-17

Direct Digital Identity sector match due to critical WebAuthn/passkey authentication bypass enabling full account takeover in public-facing platforms.

*Deep dive: `TIER_2_CVE-2026-111911.md`*

___________________________________


# **[CVE-2026-111923 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-111923)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-17

Unauthenticated DoS in enterprise MDM platform impacts device management availability for government and financial institutions relying on centralized fleet controls.

*Deep dive: `TIER_2_CVE-2026-111923.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine