# **Infrastructure Daily Brief: 2026-09-01**

**Infrastructure Daily Report TLP:GREEN Alert Id: 7c7de6bb 2026-09-02 23:13:13**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-18765 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-84423 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-4813 (Tier 2)                                                           | 3.k      |
| Cyber News | CVE-2026-66357 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-73270 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-73276 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-79687 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-73812 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-75538 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-84119 (Tier 2)                                                          | 3.k      |
| Threats    | Inside Knight Office, a New M365 AiTM Phishing Kit | Huntress                    | 1.a      |
| Threats    | Mirage2FA Phishing Kit Bypasses MFA to Hijack Microsoft 365 Sessions, Targeting  | 1.a      |
| Threats    | NovaCookies at scale: Inside the $320 Phishing Service Targeting Hundreds of Org | 1.c      |
| Threats    | Phishing tactics evolve with rise of QR-code and identity-token abuse targeting  | 1.b      |
| Threats    | Device Code Phishing: Turning a Convenience Feature Into an MFA Bypass | Trend M | 1.b      |
| Threats    | When checking the URL isn’t enough: phishing via the Microsoft identity platform | 1.e      |
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.d      |
| Threats    | Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale | Microsoft  | 1.a      |
| Threats    | CVE-2026-82859                                                                   | 1.b      |
| Threats    | CVE-2026-82857                                                                   | 1.b      |
| Threats    | CVE-2026-84114                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Inside Knight Office, a New M365 AiTM Phishing Kit | Huntress](https://www.huntress.com/blog/inside-knight-office-m365-aitm-attack)**

**PIR: 1.a**

Source: ketch Published: 2026-09-01

Huntress researchers dissect the Knight Office M365 AiTM phishing kit, detailing its real-time session hijacking capabilities and infrastructure deployment patterns. The report outlines how attackers proxy authentication flows to bypass conditional access policies, providing defenders with IOCs, proxy domain structures, and recommended M365 security settings to mitigate session theft.

___________________________________


# **[Mirage2FA Phishing Kit Bypasses MFA to Hijack Microsoft 365 Sessions, Targeting 3,500+ Organizations - Cyber Accord](https://www.cyberaccord.com/mirage2fa-phishing-kit-bypasses-mfa-to-hijack-microsoft-365-sessions-targeting-3500-organizations/)**

**PIR: 1.a**

Source: ketch Published: 2026-09-01

Cyber Accord analyzes the Mirage2FA kit, which successfully bypasses multi-factor authentication to hijack Microsoft 365 sessions across thousands of organizations. The breakdown covers the kit’s reverse-proxy architecture, token extraction methods, and infrastructure footprint, offering actionable guidance for identity protection teams to detect and block unauthorized session reuse.

___________________________________


# **[NovaCookies at scale: Inside the $320 Phishing Service Targeting Hundreds of Organizations](https://www.island.io/blog/novacookies-at-scale-inside-the-320-phishing-service-targeting-hundreds-of-organizations)**

**PIR: 1.c**

Source: ketch Published: 2026-09-01

Island reveals the operational scale of NovaCookies, a low-cost phishing-as-a-service platform targeting hundreds of enterprises. The analysis details its automated infrastructure provisioning, credential harvesting pipelines, and MFA evasion tactics, equipping security operations centers with threat intelligence to identify compromised accounts and harden identity perimeters.

___________________________________


# **[Phishing tactics evolve with rise of QR-code and identity-token abuse targeting critical infrastructure | Noah Intelligence](https://noah-news.com/phishing-tactics-evolve-with-rise-of-qr-code-and-identity-token-abuse-targeting/)**

**PIR: 1.b**

Source: ketch Published: 2026-09-01

Noah Intelligence examines evolving phishing tactics leveraging QR codes and identity token manipulation to compromise critical infrastructure environments. The report highlights how attackers abuse legitimate authentication flows to bypass traditional email security controls, providing network and identity defenders with detection strategies for token replay and QR-based credential theft.

___________________________________


# **[Device Code Phishing: Turning a Convenience Feature Into an MFA Bypass | Trend Micro (US)](https://www.trendmicro.com/en_us/research/26/g/device-code-phishing.html)**

**PIR: 1.b**

Source: ketch Published: 2026-09-01

Trend Micro explores how device code phishing transforms a legitimate convenience feature into a potent MFA bypass vector. The technical breakdown explains the authentication flow abuse, infrastructure indicators, and detection gaps, guiding IT defenders on implementing device code restrictions and monitoring for anomalous consent grants.

___________________________________


# **[When checking the URL isn’t enough: phishing via the Microsoft identity platform | Securelist](https://securelist.com/microsoft-device-code-phishing-attack/120350/)**

**PIR: 1.e**

Source: ketch Published: 2026-09-01

Kaspersky Securelist details a sophisticated campaign exploiting the Microsoft identity platform to bypass URL-based phishing defenses. The analysis covers device code abuse, token theft mechanisms, and infrastructure patterns, offering identity security teams actionable telemetry and policy recommendations to secure authentication endpoints.

___________________________________


# **[Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.d**

Source: ketch Published: 2026-09-01

Microsoft Security researchers document an AI-driven device code phishing campaign that automates victim interaction and credential harvesting. The report outlines the AI’s role in social engineering, infrastructure deployment, and MFA circumvention, providing defenders with behavioral indicators and automated response playbooks for identity threat mitigation.

___________________________________


# **[Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale/)**

**PIR: 1.a**

Source: ketch Published: 2026-09-01

Microsoft Security dissects the Tycoon2FA AiTM kit, revealing its large-scale operational infrastructure and real-time session hijacking techniques. The analysis details proxy configurations, MFA bypass methods, and attacker TTPs, equipping IT infrastructure teams with comprehensive detection rules and M365 hardening strategies to prevent unauthorized access.

___________________________________


# **[CVE-2026-82859](https://nvd.nist.gov/vuln/detail/CVE-2026-82859)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-31

hulumi versions before v1.3.2 contain a deployment SCP template that allows tag-on-create bypasses for hulumi:iac-role protections. Attackers can bypass intended IAM boundary restrictions by exploiting the weakened SCP template in downstream deployments.

___________________________________


# **[CVE-2026-82857](https://nvd.nist.gov/vuln/detail/CVE-2026-82857)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-31

hulumi versions before v1.3.2 contain a privilege escalation vulnerability in the weekly integration IAM policy that allows role lifecycle operations on af-e2e-* roles without sufficient boundary restrictions. Attackers with the documented principal can create persistent higher-privilege roles in the sandbox account.

___________________________________


# **[CVE-2026-84114](https://nvd.nist.gov/vuln/detail/CVE-2026-84114)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-01

A vulnerability has been found in Cleo Harmony up to 5.8.1.10. Impacted is the function LocalUserUtil.getNativeUserByAssertions of the component SAML Authentication. Such manipulation of the argument Email leads to improper authentication. The attack can be executed remotely. The exploit has been disclosed to the public and may be used. Upgrading to version 5.8.1.11 is recommended to address this issue. Upgrading the affected component is recommended.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-18765 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-18765)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-01

Government sector: Critical SQL injection in a public-facing Turkish municipal portal handling citizen permits and administrative services.

*Deep dive: `TIER_2_CVE-2026-18765.md`*

___________________________________


# **[CVE-2026-84423 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-84423)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-01

Directly impacts Digital Identity infrastructure by allowing unauthenticated file uploads and identity spoofing in Casdoor, an open-source IdAM/SSO platform handling OAuth/OIDC/SAML flows.

*Deep dive: `TIER_2_CVE-2026-84423.md`*

___________________________________


# **[CVE-2026-4813 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-4813)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-01

Critical RCE in Lutece Core, a CMS framework widely deployed by European municipalities for citizen-facing government portals and smart city platforms.

*Deep dive: `TIER_2_CVE-2026-4813.md`*

___________________________________


# **[CVE-2026-66357 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-66357)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-01

General infrastructure vulnerability in Erlang/OTP backend HTTP server, explicitly tied to fintech and telecommunications deployments behind reverse proxies.

*Deep dive: `TIER_2_CVE-2026-66357.md`*

___________________________________


# **[CVE-2026-73270 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-73270)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-01

Foundational Erlang/OTP runtime deployed across telecom, finance, and government; auth bypass in embedded HTTP server impacts management interfaces and internal APIs.

*Deep dive: `TIER_2_CVE-2026-73270.md`*

___________________________________


# **[CVE-2026-73276 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-73276)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-01

HTTP request smuggling in Erlang/OTP's inets library impacts proxied web services in fintech and enterprise backends, posing desync risks to regulated infrastructure.

*Deep dive: `TIER_2_CVE-2026-73276.md`*

___________________________________


# **[CVE-2026-79687 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-79687)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-01

General enterprise storage infrastructure underpinning Healthcare, Finance, and Government workloads; unauthenticated filesystem access enables lateral movement and data exfiltration in regulated datacenters.

*Deep dive: `TIER_2_CVE-2026-79687.md`*

___________________________________


# **[CVE-2026-73812 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-73812)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-01

Tier 2 HTTP request smuggling in Erlang/OTP httpd, a foundational backend runtime explicitly noted for deployment across finance and government infrastructure.

*Deep dive: `TIER_2_CVE-2026-73812.md`*

___________________________________


# **[CVE-2026-75538 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-75538)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-01

Tier 2 DoS in Erlang/OTP runtime, a foundational backend platform for telecom and financial messaging systems.

*Deep dive: `TIER_2_CVE-2026-75538.md`*

___________________________________


# **[CVE-2026-84119 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-84119)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-01

Critical sandbox escape in foundational browser/email clients widely deployed across regulated enterprise and public sector environments.

*Deep dive: `TIER_2_CVE-2026-84119.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine