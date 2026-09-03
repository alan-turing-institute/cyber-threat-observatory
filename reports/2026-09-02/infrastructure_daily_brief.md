# **Infrastructure Daily Brief: 2026-09-02**

**Infrastructure Daily Report TLP:GREEN Alert Id: 04f867a1 2026-09-03 09:26:35**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-49249 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-73475 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-78689 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-84699 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-14957 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-84668 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-20212 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-84394 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-84645 (Tier 2)                                                          | 3.k      |
| Threats    | Inside Knight Office, a New M365 AiTM Phishing Kit | Huntress                    | 1.a      |
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.d      |
| Threats    | Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale | Microsoft  | 1.a      |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover                        | 1.b      |
| Threats    | Starkiller Phishing Framework Proxies Real Login Pages… | Abnormal AI            | 1.g      |
| Threats    | NovaCookies at scale: Inside the $320 Phishing Service Targeting Hundreds of Org | 1.c      |
| Threats    | Why do device code phishing campaigns create more account takeover risk ...      | 1.e      |
| Threats    | IronToll: Global Government-Impersonation PhaaS | PhishEye                       | 1.f      |
| Threats    | CVE-2026-19117                                                                   | 1.b      |
| Threats    | CVE-2026-84672                                                                   | 1.b      |
| Threats    | CVE-2026-84423                                                                   | 1.b      |
| Threats    | CVE-2026-75136                                                                   | 1.b      |
| Threats    | CVE-2026-82968                                                                   | 1.b      |
| Threats    | CVE-2026-84114                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Inside Knight Office, a New M365 AiTM Phishing Kit | Huntress](https://www.huntress.com/blog/inside-knight-office-m365-aitm-attack)**

**PIR: 1.a**

Source: ketch Published: 2026-09-02

Huntress researchers dissect the Knight Office M365 AiTM phishing kit, detailing how threat actors proxy Microsoft 365 login flows to bypass MFA. The analysis covers infrastructure patterns, session hijacking techniques, and detection strategies for IT defenders managing cloud identity environments.

___________________________________


# **[Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.d**

Source: ketch Published: 2026-09-02

Microsoft details a sophisticated device code phishing campaign leveraging AI for end-to-end automation. Attackers generate live authentication codes on demand, significantly increasing account takeover success rates. Defenders are advised to monitor for anomalous device code flows and implement stricter session validation controls.

___________________________________


# **[Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale/)**

**PIR: 1.a**

Source: ketch Published: 2026-09-02

Microsoft Security researchers expose the Tycoon2FA AiTM phishing kit, revealing its large-scale operational model. The report outlines how the framework intercepts authentication tokens in real-time, evades conditional access policies, and provides actionable indicators for infrastructure teams to block proxy-based credential theft.

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.b**

Source: ketch Published: 2026-09-02

Proofpoint analyzes the evolution of device code phishing as a primary identity takeover vector. The campaign exploits corporate validation workflows and leverages account takeover jumping to propagate across contact networks. Infrastructure teams must review OAuth consent policies and deploy behavioral analytics to detect automated code generation.

___________________________________


# **[Starkiller Phishing Framework Proxies Real Login Pages… | Abnormal AI](https://abnormal.ai/blog/starkiller-phishing-kit)**

**PIR: 1.g**

Source: ketch Published: 2026-09-02

Abnormal AI researchers analyze the Starkiller phishing framework, which proxies real login pages to capture credentials and MFA tokens. The toolkit’s architecture enables seamless session hijacking while evading traditional URL filtering. Defenders should implement certificate pinning, monitor for proxy traffic patterns, and enforce phishing-resistant MFA methods.

___________________________________


# **[NovaCookies at scale: Inside the $320 Phishing Service Targeting Hundreds of Organizations](https://www.island.io/blog/novacookies-at-scale-inside-the-320-phishing-service-targeting-hundreds-of-organizations)**

**PIR: 1.c**

Source: ketch Published: 2026-09-02

Island.io investigates the NovaCookies phishing service, a $320 PhaaS operation targeting hundreds of organizations. The report breaks down how the service harvests session cookies to bypass MFA and maintain persistent access. Defenders should focus on cookie security attributes, session rotation, and network-level blocking of known PhaaS infrastructure.

___________________________________


# **[Why do device code phishing campaigns create more account takeover risk ...](https://nhimg.org/faq/why-do-device-code-phishing-campaigns-create-more-account-takeover-risk-than-tra/)**

**PIR: 1.e**

Source: ketch Published: 2026-09-02

NHIMG explains why device code phishing poses elevated account takeover risks compared to traditional methods. Successful attacks grant mailbox access, SaaS persistence, and token-based lateral movement, particularly where conditional access and session controls are weak. Infrastructure teams must prioritize token lifecycle management and zero-trust identity validation.

___________________________________


# **[IronToll: Global Government-Impersonation PhaaS | PhishEye](https://phisheye.com/blog/irontoll-iron-man-phaas-campaign)**

**PIR: 1.f**

Source: ketch Published: 2026-09-02

PhishEye uncovers IronToll, a global PhaaS campaign impersonating government entities. The framework automates credential harvesting and session hijacking across multiple cloud platforms. IT infrastructure defenders are urged to monitor for government-branded phishing domains, enforce strict conditional access rules, and deploy email authentication controls.

___________________________________


# **[CVE-2026-19117](https://nvd.nist.gov/vuln/detail/CVE-2026-19117)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-02

Under specific conditions, an attacker can register an attacker-controlled FIDO2 credential against a target account and then authenticate as
that user. This issue affects on-premises deployments only.

___________________________________


# **[CVE-2026-84672](https://nvd.nist.gov/vuln/detail/CVE-2026-84672)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-02

Jenkins Microsoft Entra ID (previously Azure AD) Plugin 710.v0b_ff8e9cc2d2 and earlier grants Entra group permissions using both the group's unique object ID and its display name, allowing attackers who can create an Entra group with a colliding display name to gain the permissions configured for a privileged group.

___________________________________


# **[CVE-2026-84423](https://nvd.nist.gov/vuln/detail/CVE-2026-84423)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-01

A vulnerability has been found in Casdoor up to 4.0.0. This affects an unknown function of the file controllers/resource.go of the component upload-resource API. Such manipulation leads to missing authentication. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. The vendor deleted the GitHub issue for this vulnerability without any explanation. Afterwards the vendor was contacted early about this disclosure via email but did not respond i

___________________________________


# **[CVE-2026-75136](https://nvd.nist.gov/vuln/detail/CVE-2026-75136)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-02

UpSignOn for Windows before 7.19.0 contains an insecure credential storage vulnerability that allows local attackers to retrieve the biometric unlock key stored in the Windows PasswordVault API without triggering any authentication prompt. Attackers can access the stored biometric key from a standard local process within the same Windows session to decrypt the protected vault files and export the entire password manager contents in cleartext.

___________________________________


# **[CVE-2026-82968](https://nvd.nist.gov/vuln/detail/CVE-2026-82968)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-02

A flaw was found in the first-broker-login flow of the Keycloak identity management service. When a user links a social identity provider account to their local account, the verification proof generated is not strictly bound to the specific upstream identity being verified. This allows an attacker with a different account on the same social provider to intercept the process and link their own account to the victim's local profile, gaining unauthorized access.

___________________________________


# **[CVE-2026-84114](https://nvd.nist.gov/vuln/detail/CVE-2026-84114)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-01

A vulnerability has been found in Cleo Harmony up to 5.8.1.10. Impacted is the function LocalUserUtil.getNativeUserByAssertions of the component SAML Authentication. Such manipulation of the argument Email leads to improper authentication. The attack can be executed remotely. The exploit has been disclosed to the public and may be used. Upgrading to version 5.8.1.11 is recommended to address this issue. Upgrading the affected component is recommended.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-49249 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-49249)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-02

TIER 2 DoS in Boruta OAuth/OIDC identity provider crashes the BEAM VM, blocking all downstream authentication flows for digital identity services.

*Deep dive: `TIER_2_CVE-2026-49249.md`*

___________________________________


# **[CVE-2026-73475 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-73475)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-02

Finance sector relevance; bypasses payment validation in Drupal Commerce PayPal module, impacting transaction integrity and merchant revenue.

*Deep dive: `TIER_2_CVE-2026-73475.md`*

___________________________________


# **[CVE-2026-78689 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-78689)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-02

Digital Identity: Directly compromises SAML-based SSO endpoints via the nginx-saml reference implementation, disrupting authentication flows for enterprise and government digital services.

*Deep dive: `TIER_2_CVE-2026-78689.md`*

___________________________________


# **[CVE-2026-84699 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-84699)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-02

Critical authentication bypass in self-hosted enterprise password manager enabling unauthenticated local account takeover, directly impacting organizational Digital Identity and credential infrastructure.

*Deep dive: `TIER_2_CVE-2026-84699.md`*

___________________________________


# **[CVE-2026-14957 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-14957)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-02

Core IPsec VPN infrastructure for government and regulated enterprises, with FIPS compliance mandates making it a critical availability target for public-sector remote access.

*Deep dive: `TIER_2_CVE-2026-14957.md`*

___________________________________


# **[CVE-2026-84668 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-84668)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-02

Directly impacts Digital Identity and General Infrastructure by enabling SAML authentication bypass and full admin takeover in enterprise CI/CD pipelines.

*Deep dive: `TIER_2_CVE-2026-84668.md`*

___________________________________


# **[CVE-2026-20212 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-20212)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-02

TIER 2 unauthenticated root RCE on Cisco Nexus 9000 data center switches; critical general infrastructure underpinning regulated and public-sector networks.

*Deep dive: `TIER_2_CVE-2026-20212.md`*

___________________________________


# **[CVE-2026-84394 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-84394)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-02

SSRF bypass in a widely adopted Node.js URI library risks internal network and cloud metadata access across enterprise and public-sector web platforms.

*Deep dive: `TIER_2_CVE-2026-84394.md`*

___________________________________


# **[CVE-2026-84645 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-84645)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-02

Foundational CI/CD infrastructure flaw enabling RCE on Jenkins controllers, directly impacting software supply chains for government, finance, and healthcare digital services.

*Deep dive: `TIER_2_CVE-2026-84645.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine