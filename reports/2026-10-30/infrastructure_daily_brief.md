# **Infrastructure Daily Brief: 2026-10-30**

**Infrastructure Daily Report TLP:GREEN Alert Id: dd16938d 2026-10-31 16:22:17**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-119421 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-46560 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-63182 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-63377 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-119420 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-119422 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-119655 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-119656 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-63341 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-63414 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-119409 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-63339 (Tier 2)                                                          | 3.k      |
| Threats    | Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale | Microsoft  | 1.b      |
| Threats    | Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Se | 1.c      |
| Threats    | The hidden network: Inside the phishing infrastructure ecosystem powering global | 1.d      |
| Threats    | Inside an AI‑enabled device code phishing campaign | Microsoft Security Blog     | 1.c      |
| Threats    | Resecurity | Iron Man & YamStore: Powering a Global Phishing-as-a-Service Ecosys | 1.d      |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover                        | 1.j.3    |
| Threats    | Microsoft 365 Device Code Phishing Campaign Bypasses Password Theft ...          | 1.c      |
| Threats    | Storm-2372 conducts device code phishing campaign                                | 1.a      |
| Threats    | CVE-2026-116239                                                                  | 1.b      |
| Threats    | CVE-2026-63378                                                                   | 1.b      |
| Threats    | CVE-2026-92744                                                                   | 1.b      |
| Threats    | CVE-2026-115829                                                                  | 1.b      |
| Threats    | CVE-2026-115830                                                                  | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale/)**

**PIR: 1.b**

Source: ketch Published: 2026-10-30

An in-depth technical breakdown of the Tycoon2FA Adversary-in-the-Middle (AiTM) kit, detailing its reverse proxy architecture, session token theft mechanisms, and MFA bypass techniques. Infrastructure teams should review reverse proxy signatures, enforce certificate pinning, and deploy conditional access policies that detect anomalous session behaviors to mitigate AiTM threats.

___________________________________


# **[Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/)**

**PIR: 1.c**

Source: ketch Published: 2026-10-30

Microsoft researchers expose EvilTokens, a sophisticated toolkit exploiting OAuth device authorization flows to bypass traditional MFA. The report outlines token validation bypasses, automated polling techniques, and infrastructure patterns. Defenders must monitor for unusual device code grant requests, restrict OAuth app permissions, and implement token binding to secure identity perimeters.

___________________________________


# **[The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime/)**

**PIR: 1.d**

Source: ketch Published: 2026-10-30

Microsoft Threat Intelligence dissects the underground infrastructure supporting modern phishing campaigns, revealing how threat actors leverage cloud services, domain generation algorithms, and proxy networks to evade detection. Defenders can use these indicators to harden email gateways, monitor DNS anomalies, and block malicious hosting providers before credential harvesting occurs.

___________________________________


# **[Inside an AI‑enabled device code phishing campaign | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.c**

Source: ketch Published: 2026-10-30

This analysis covers a campaign leveraging generative AI to craft highly personalized lures and automate device code phishing workflows. The attack chain combines AI-generated content with OAuth exploitation to harvest valid access tokens. IT defenders should deploy AI-aware email filtering, monitor for rapid device code polling, and enforce strict conditional access rules for token issuance.

___________________________________


# **[Resecurity | Iron Man & YamStore: Powering a Global Phishing-as-a-Service Ecosystem](https://www.resecurity.com/blog/article/iron-man-yamstore-powering-a-global-phishing-as-a-service-ecosystem)**

**PIR: 1.d**

Source: ketch Published: 2026-10-30

Resecurity maps the Iron Man and YamStore PhaaS platforms, detailing their modular phishing kits, affiliate tracking systems, and infrastructure-as-a-service offerings. The report provides actionable IOCs and architectural insights to help security teams block PhaaS domains, disrupt affiliate networks, and harden web application firewalls against kit-generated payloads.

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.j.3**

Source: ketch Published: 2026-10-30

Proofpoint examines the rapid proliferation of device code phishing tools and their role in modern identity takeover attacks. The article highlights how publicly available toolkits and PhaaS models lower the barrier for attackers. Defenders are advised to audit OAuth consent grants, implement token lifetime restrictions, and deploy identity threat detection platforms to catch anomalous authorization flows.

___________________________________


# **[Microsoft 365 Device Code Phishing Campaign Bypasses Password Theft ...](https://cybersecuritynews.com/microsoft-365-device-code-phishing-campaign/)**

**PIR: 1.c**

Source: ketch Published: 2026-10-30

ReversingLabs documents an active campaign exploiting Microsoft 365’s Device Authorization Grant flow to achieve near-invisible account takeovers. The attack uses realistic business lures and polished kits to trick users into entering device codes. Infrastructure teams should monitor for high-frequency device code validations, restrict third-party app access, and educate users on recognizing OAuth phishing prompts.

___________________________________


# **[Storm-2372 conducts device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/)**

**PIR: 1.a**

Source: ketch Published: 2026-10-30

Microsoft tracks Storm-2372’s persistent use of device code phishing, mimicking messaging platforms like Teams and WhatsApp to harvest credentials. The campaign demonstrates how threat actors adapt lures to bypass user skepticism. Defenders should implement URL reputation filtering, monitor for messaging-app impersonation patterns, and enforce multi-factor authentication with phishing-resistant methods like FIDO2.

___________________________________


# **[CVE-2026-116239](https://nvd.nist.gov/vuln/detail/CVE-2026-116239)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-30

In server mode pgAdmin 4 keeps an account per authentication source, so the same username can exist as, for example, an internal account and an LDAP account. After LDAP or Kerberos authenticated a user, pgAdmin chose the account to log in by username alone, or took the account Flask-Security's login form had looked up, without checking that it came from the source that authenticated the user. The session therefore belonged to another account, with its role, its servers and its saved database pas

___________________________________


# **[CVE-2026-63378](https://nvd.nist.gov/vuln/detail/CVE-2026-63378)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-30

TAKO AI Agent for Okta is a local-first AI agent that helps Okta administrators query tenant data using natural language. Prior to 3.0.1-beta, any authenticated user with a valid `fctr_session` cookie can submit arbitrary Python source in the `script_code` field of `POST /api/react/execute-script`, without administrator privilege. In `src/api/routers/react_stream.py`, the source is stored with `skip_discovery=True`, bypassing AI-based content filtering, and is passed to `validate_generated_code`

___________________________________


# **[CVE-2026-92744](https://nvd.nist.gov/vuln/detail/CVE-2026-92744)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-29

Under certain conditions, privilege manager agent allows a remote unauthenticated attacker to execute
arbitrary code as LocalSystem.

___________________________________


# **[CVE-2026-115829](https://nvd.nist.gov/vuln/detail/CVE-2026-115829)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-30

In Secret Server versions earlier than 12.3.1, a user could bypass the initial login step and authenticate by successfully negotiating the second factor login step only.

___________________________________


# **[CVE-2026-115830](https://nvd.nist.gov/vuln/detail/CVE-2026-115830)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-30

In Secret Server versions earlier than 12.3.1, a user under certain conditions could submit an unsigned JWT and receive cloudadmin permissions in response.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-119421 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-119421)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-30

Finance sector: missing authorization in payment gateway payout API enables unauthorized fund transfers and routing manipulation.

*Deep dive: `TIER_2_CVE-2026-119421.md`*

___________________________________


# **[CVE-2026-46560 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-46560)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-30

Core IdAM platform (OpenAM) authentication bypass enables session hijacking, directly impacting digital identity and access management infrastructure.

*Deep dive: `TIER_2_CVE-2026-46560.md`*

___________________________________


# **[CVE-2026-63182 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-63182)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-30

Digital Identity: Critical SAML 2.0 library flaw enables authentication bypass, directly threatening federated identity, SSO, and cross-organization trust frameworks in government and enterprise infrastructure.

*Deep dive: `TIER_2_CVE-2026-63182.md`*

___________________________________


# **[CVE-2026-63377 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-63377)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-30

Critical missing authentication in an Okta identity administration agent allows unauthenticated admin takeover, directly impacting the Digital Identity sector and core IdAM credential management.

*Deep dive: `TIER_2_CVE-2026-63377.md`*

___________________________________


# **[CVE-2026-119420 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-119420)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-30

Directly impacts financial operations and payment integrations via authentication bypass in a widely used billing/metering API.

*Deep dive: `TIER_2_CVE-2026-119420.md`*

___________________________________


# **[CVE-2026-119422 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-119422)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-30

Finance: Authentication bypass in Hyperswitch payment gateway enables forged webhooks to manipulate transaction statuses and payouts, directly threatening financial infrastructure integrity.

*Deep dive: `TIER_2_CVE-2026-119422.md`*

___________________________________


# **[CVE-2026-119655 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-119655)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-30

Unauthenticated SQLi in a public-facing e-commerce platform exposes customer financial transaction histories and payment data, directly impacting the Finance sector and digital payment infrastructure.

*Deep dive: `TIER_2_CVE-2026-119655.md`*

___________________________________


# **[CVE-2026-119656 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-119656)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-30

Unauthenticated SQLi in a public-facing e-commerce platform exposes customer financial data and transaction records, directly impacting the Finance sector's digital payment infrastructure.

*Deep dive: `TIER_2_CVE-2026-119656.md`*

___________________________________


# **[CVE-2026-63341 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-63341)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-30

Impacts foundational MQTT messaging infrastructure supporting industrial IoT, healthcare telemetry, and smart city systems, causing complete broker crashes and disrupting critical backend services.

*Deep dive: `TIER_2_CVE-2026-63341.md`*

___________________________________


# **[CVE-2026-63414 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-63414)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-30

Cross-tenant authorization bypass in Shopify's core app framework threatens tenant isolation for merchant accounts and payment transaction data, directly impacting the Finance sector.

*Deep dive: `TIER_2_CVE-2026-63414.md`*

___________________________________


# **[CVE-2026-119409 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-119409)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-30

Critical firewall RCE impacting government and enterprise edge deployments; foundational infrastructure requiring immediate patching to prevent root compromise.

*Deep dive: `TIER_2_CVE-2026-119409.md`*

___________________________________


# **[CVE-2026-63339 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-63339)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-30

Tier 2 privilege escalation in critical internet exchange infrastructure, impacting national/regional network peering and connectivity operations.

*Deep dive: `TIER_2_CVE-2026-63339.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine