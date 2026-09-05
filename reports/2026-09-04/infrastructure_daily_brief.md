# **Infrastructure Daily Brief: 2026-09-04**

**Infrastructure Daily Report TLP:GREEN Alert Id: d7f5b3d1 2026-09-05 16:19:18**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-18658 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-61686 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-85184 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-85398 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-85689 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-18221 (Tier 2)                                                          | 3.k      |
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.a      |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US        | 1.b      |
| Threats    | When checking the URL isn’t enough: phishing via the Microsoft identity platform | 1.c      |
| Threats    | Device Code Phishing: Turning a Convenience Feature Into an MFA Bypass | Trend M | 1.d      |
| Threats    | Microsoft 365 device code phishing campaign bypasses password stealing | RL Blog | 1.e      |
| Threats    | Operation HookedWing: 4-Year Campaign Compromises 500 Orgs - Phishing            | 1.f      |
| Threats    | Massive “TrustTrap” Phishing Campaign Exploits Human Perception, Targets Governm | 1.g      |
| Threats    | Energy/Infrastructure Enterprises Targeted by HTML Phishing Campaign             | 1.h      |
| Threats    | CVE-2026-83711                                                                   | 1.b      |
| Threats    | CVE-2026-85595                                                                   | 1.b      |
| Threats    | CVE-2026-62916                                                                   | 1.b      |
| Threats    | CVE-2026-80465                                                                   | 1.b      |
| Threats    | CVE-2026-85596                                                                   | 1.b      |
| Threats    | CVE-2026-84831                                                                   | 1.b      |
| Threats    | CVE-2026-85238                                                                   | 1.b      |
| Threats    | CVE-2026-8862                                                                    | 1.b      |
| Threats    | CVE-2026-53603                                                                   | 1.b      |
| Threats    | CVE-2026-85700                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.a**

Source: ketch Published: 2026-09-04

This campaign represents a major escalation in threat actor sophistication, shifting from static scripts to fully AI-driven infrastructure and end-to-end automation. Building on the Storm-2372 campaign from early 2025, attackers now leverage machine learning to dynamically generate phishing pages, optimize delivery timing, and evade detection. IT defenders must prioritize monitoring for automated device code requests, implement conditional access policies that restrict device code flows, and dep

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.b**

Source: ketch Published: 2026-09-04

Device code phishing continues to mature as a primary vector for identity takeover, bypassing traditional multi-factor authentication by leveraging legitimate OAuth 2.0 device authorization flows. Attackers trick users into entering codes on malicious sites, granting them direct access to corporate accounts without passwords or MFA prompts. Defenders should audit OAuth consent grants, enforce strict device code policies, and educate users on recognizing legitimate Microsoft/Google device code pr

___________________________________


# **[When checking the URL isn’t enough: phishing via the Microsoft identity platform | Securelist](https://securelist.com/microsoft-device-code-phishing-attack/120350/)**

**PIR: 1.c**

Source: ketch Published: 2026-09-04

Modern phishing campaigns increasingly exploit the Microsoft identity platform’s legitimate endpoints, making URL inspection insufficient for detection. Attackers host malicious pages on trusted domains or use URL shorteners and redirect chains that resolve to authentic Microsoft login flows. Security teams must shift from perimeter-based URL filtering to behavioral analytics, monitoring for anomalous authentication patterns, and implementing strict conditional access rules to mitigate identity 

___________________________________


# **[Device Code Phishing: Turning a Convenience Feature Into an MFA Bypass | Trend Micro (US)](https://www.trendmicro.com/en_us/research/26/g/device-code-phishing.html)**

**PIR: 1.d**

Source: ketch Published: 2026-09-04

Originally designed for seamless cross-device authentication, the device code flow has been weaponized to circumvent MFA protections. Threat actors distribute malicious links prompting users to visit legitimate authentication portals and enter generated codes, effectively handing over session tokens. Infrastructure defenders should disable unnecessary device code grants, enforce risk-based authentication, and deploy real-time alerting for high-privilege account logins originating from device cod

___________________________________


# **[Microsoft 365 device code phishing campaign bypasses password stealing | RL Blog](https://www.reversinglabs.com/blog/device-code-phishing-campaign)**

**PIR: 1.e**

Source: ketch Published: 2026-09-04

This campaign demonstrates a strategic pivot away from traditional credential harvesting toward direct session token acquisition via device code phishing. By targeting Microsoft 365 environments, attackers bypass password-based defenses and MFA entirely, gaining immediate access to email, files, and collaboration tools. Defenders must prioritize zero-trust identity controls, monitor for unusual OAuth token issuance, and implement automated response playbooks to revoke compromised sessions instan

___________________________________


# **[Operation HookedWing: 4-Year Campaign Compromises 500 Orgs - Phishing](https://dailysecurityreview.com/phishing/operation-hookedwing-4-year-campaign-compromises-500-orgs/)**

**PIR: 1.f**

Source: ketch Published: 2026-09-04

Operation HookedWing reveals a persistent, multi-year phishing campaign that successfully infiltrated over 500 organizations through carefully crafted social engineering and infrastructure reuse. The threat actors maintained low visibility by rotating domains, leveraging compromised legitimate services, and targeting mid-tier employees with high-privilege access. Defenders should focus on threat hunting for dormant credentials, implementing continuous authentication monitoring, and conducting re

___________________________________


# **[Massive “TrustTrap” Phishing Campaign Exploits Human Perception, Targets Government Services Across US, India, and Beyond](https://cyberp1.com/massive-trusttrap-phishing-campaign-exploits-human-perception-targets-government-services-across-us-india-and-beyond/)**

**PIR: 1.g**

Source: ketch Published: 2026-09-04

The TrustTrap campaign leverages advanced visual spoofing and psychological manipulation to mimic official government portals, successfully harvesting credentials from public sector employees across multiple regions. By exploiting cognitive biases and trusted branding, attackers bypass traditional security awareness training. Infrastructure teams should deploy AI-driven visual similarity detection, enforce strict domain reputation filtering, and implement multi-layered identity verification for 

___________________________________


# **[Energy/Infrastructure Enterprises Targeted by HTML Phishing Campaign](https://cofense.com/blog/energy-infrastructure-enterprises-targeted-by-html-phishing-campaign)**

**PIR: 1.h**

Source: ketch Published: 2026-09-04

This campaign specifically targets critical energy and infrastructure sectors using sophisticated HTML-based phishing pages that dynamically load malicious payloads based on user interaction. Attackers exploit sector-specific compliance workflows and vendor communication patterns to increase click-through rates. Defenders must prioritize email security gateways with advanced HTML sandboxing, enforce strict web content filtering, and conduct sector-tailored phishing simulations to reduce suscepti

___________________________________


# **[CVE-2026-83711](https://nvd.nist.gov/vuln/detail/CVE-2026-83711)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-03

Authorization bypass through user-controlled key in Microsoft Azure Active Directory B2C allows an unauthorized attacker to elevate privileges over a network.

___________________________________


# **[CVE-2026-85595](https://nvd.nist.gov/vuln/detail/CVE-2026-85595)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-04

Traefik versions before v2.11.55 contain an authentication bypass vulnerability in the digestAuth middleware where unknown usernames receive an empty secret instead of rejection. Attackers can compute a valid digest response using the empty secret and arbitrary credentials to bypass authentication on any digestAuth-protected route without a valid username or password.

___________________________________


# **[CVE-2026-62916](https://nvd.nist.gov/vuln/detail/CVE-2026-62916)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-03

Authentication bypass using an alternate path or channel in Microsoft Entra ID allows an unauthorized attacker to elevate privileges over a network.

___________________________________


# **[CVE-2026-80465](https://nvd.nist.gov/vuln/detail/CVE-2026-80465)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-03

A vulnerability has been identified in Mendix SAML (Mendix 10 compatible) (All versions < V4.2.3), Mendix SAML (Mendix 11 compatible) (All versions < V4.2.3), Mendix SAML (Mendix 9.24 compatible) (All versions < V3.6.27). Affected versions of the module do not properly validate the SAML response signature. This could allow unauthenticated remote attackers to hijack an account (session) in specific SSO configurations.

___________________________________


# **[CVE-2026-85596](https://nvd.nist.gov/vuln/detail/CVE-2026-85596)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-04

Traefik versions >= v3.7.0 and <= v3.7.10 contain an authentication bypass in the Kubernetes Ingress NGINX provider. The TLS option generated for an Ingress carrying the nginx.ingress.kubernetes.io/auth-tls-secret annotation was named after the Ingress namespace and name. As a result, two Ingress objects sharing the same host, the same client CA secret, and the same client-authentication mode produced two distinct TLS option names for that host. Traefik treats this as a TLS options conflict and 

___________________________________


# **[CVE-2026-84831](https://nvd.nist.gov/vuln/detail/CVE-2026-84831)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-03

SEPPmail Secure Email Gateway before 15.0.7 creates a fully privileged session before required multi-factor authentication enrollment is completed. An attacker with the password for an MFA-required but unenrolled account can access protected functionality without providing a second factor.

___________________________________


# **[CVE-2026-85238](https://nvd.nist.gov/vuln/detail/CVE-2026-85238)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-03

MISP contains a session fixation vulnerability in the CustomAuth authentication (a custom configuration) flow. When a user was successfully authenticated through CustomAuth, MISP stored the authenticated user identity in the existing session without first rotating the session identifier.


As a result, if an attacker can cause a victim to use a session identifier known to the attacker before authentication, that same session identifier remains valid after the victim successfully authenticates. T

___________________________________


# **[CVE-2026-8862](https://nvd.nist.gov/vuln/detail/CVE-2026-8862)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-03

IBM Netezza Software 11.3.0.3 through Interim Fix 002 has credentials that are hardcoded in the application source code, allowing unauthorized access to the container registry. The exposed secret enables attackers to pull private container images, potentially revealing proprietary code, configuration details, and other sensitive information.

___________________________________


# **[CVE-2026-53603](https://nvd.nist.gov/vuln/detail/CVE-2026-53603)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-04

nebula-mesh is a self-hosted control plane for Slack Nebula mesh VPN. Prior to version 0.3.8, Operator session tokens are stored in plaintext in the operator_sessions table (the token column is the PRIMARY KEY). The session token is a 32-byte random hex value sent directly in a cookie and valid for 24 hours. Anyone who can read the database (backup, snapshot, file copy, or SQL-level disclosure) obtains every active session token and can hijack operator sessions directly, with no further authenti

___________________________________


# **[CVE-2026-85700](https://nvd.nist.gov/vuln/detail/CVE-2026-85700)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-04

Onyx 4.6.6 fails to properly restrict access to custom tool credentials stored in custom_headers, allowing any authenticated user to read admin-defined API keys. Attackers with basic authentication can call GET /tool/{tool_id} or GET /tool endpoints to retrieve plaintext authorization headers and third-party API credentials, then use them to directly access upstream APIs.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-18658 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-18658)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-04

Core enterprise decision engine (BRMS) underpinning regulated Finance (fraud/credit) and Government (benefits/compliance) workflows, with unauthenticated RCE risk.

*Deep dive: `TIER_2_CVE-2026-18658.md`*

___________________________________


# **[CVE-2026-61686 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-61686)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-04

Finance sector relevance: open-source invoicing platform handling billing, payment tracking, and client financial data with potential RCE via authenticated deserialization.

*Deep dive: `TIER_2_CVE-2026-61686.md`*

___________________________________


# **[CVE-2026-85184 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-85184)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-04

Critical authentication bypass in a foundational Node.js web framework plugin, impacting General Infrastructure and Digital Identity controls for public-facing APIs and regulated services.

*Deep dive: `TIER_2_CVE-2026-85184.md`*

___________________________________


# **[CVE-2026-85398 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-85398)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-04

Direct Healthcare sector impact via unauthenticated SQLi in a Hospital Information System, risking patient data breaches and regulatory compliance failures.

*Deep dive: `TIER_2_CVE-2026-85398.md`*

___________________________________


# **[CVE-2026-85689 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-85689)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-04

SQLi in enterprise RAG framework threatens financial contract data and government compliance workflows, bypassing internal data scoping controls.

*Deep dive: `TIER_2_CVE-2026-85689.md`*

___________________________________


# **[CVE-2026-18221 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-18221)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-04

Tier 2 remote authentication bypass in IBM i mainframe OS, a foundational enterprise stack widely deployed in regulated finance and government environments.

*Deep dive: `TIER_2_CVE-2026-18221.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine