# **Infrastructure Daily Brief: 2026-08-31**

**Infrastructure Daily Report TLP:GREEN Alert Id: 5a25e409 2026-09-01 12:23:08**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-17615 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-82801 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-72001 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-82877 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-82957 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-82397 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-82921 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-82922 (Tier 2)                                                          | 3.k      |
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.f      |
| Threats    | A New Era Of Social Engineering: The Device Code Phishing Boom                   | 1.f      |
| Threats    | The Device Code Phishing Tsunami: What We’re Seeing in the Wild                  | 1.f      |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover                        | 1.j      |
| Threats    | Device Code Phishing — The Attack That Makes MFA Irrelevant                      | 1.e      |
| Threats    | EvilTokens Abuses Microsoft Device Codes to Hijack Accounts Without Stealing Pas | 1.f      |
| Threats    | Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA                  | 1.g      |
| Threats    | Three Active Microsoft 365 Phishing Campaigns Targeting Schools and Government A | 1.a      |
| Threats    | CVE-2026-82859                                                                   | 1.b      |
| Threats    | CVE-2026-82857                                                                   | 1.b      |
| Threats    | CVE-2026-81888                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.f**

Source: ketch Published: 2026-08-31

Threat actors are leveraging AI to automate device code phishing campaigns, generating live authentication codes on demand to bypass MFA. This evolution enables sustained post-compromise access and higher success rates. Defenders must monitor OAuth consent grants, implement conditional access policies, and deploy AI-driven detection to identify anomalous device code flows before account takeover occurs.

___________________________________


# **[A New Era Of Social Engineering: The Device Code Phishing Boom](https://coalitioninc.com/blog/security-labs/a-new-era-of-social-engineering-the-device-code-phishing-boom)**

**PIR: 1.f**

Source: ketch Published: 2026-08-31

The surge in device code phishing represents a paradigm shift in social engineering, moving from static credential harvesting to dynamic, automated authentication interception. Attackers exploit legitimate OAuth flows to trick users into entering codes, effectively neutralizing traditional MFA. Infrastructure teams should prioritize monitoring for suspicious device code requests, restrict app consent permissions, and educate users on recognizing dynamic code prompts.

___________________________________


# **[The Device Code Phishing Tsunami: What We’re Seeing in the Wild](https://www.levelblue.com/blogs/spiderlabs-blog/the-device-code-phishing-tsunami-what-were-seeing-in-the-wild)**

**PIR: 1.f**

Source: ketch Published: 2026-08-31

Recent telemetry reveals a massive wave of device code phishing attacks targeting enterprise environments. Unlike traditional phishing, these campaigns abuse legitimate authentication endpoints to harvest active sessions. Security operations centers must enhance logging for OAuth device code endpoints, implement strict conditional access rules, and deploy behavioral analytics to detect rapid, automated code validation attempts.

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.j**

Source: ketch Published: 2026-08-31

Device code phishing has evolved into a primary vector for identity takeover, allowing attackers to bypass password resets and MFA challenges. By hijacking legitimate authentication flows, threat actors gain persistent access to cloud environments. Defenders should enforce least-privilege access, monitor for unusual OAuth token issuance, and implement continuous authentication monitoring to mitigate identity compromise risks.

___________________________________


# **[Device Code Phishing — The Attack That Makes MFA Irrelevant](https://cybergrind.org/blog/2026-06-02-device-code-phishing)**

**PIR: 1.e**

Source: ketch Published: 2026-08-31

This analysis details how device code phishing renders traditional MFA ineffective by intercepting authentication at the consent stage. Attackers no longer need passwords or push approvals, instead leveraging automated scripts to validate device codes instantly. IT infrastructure teams must transition to phishing-resistant MFA methods, restrict legacy authentication protocols, and deploy real-time alerting for device code endpoint abuse.

___________________________________


# **[EvilTokens Abuses Microsoft Device Codes to Hijack Accounts Without Stealing Passwords](https://gbhackers.com/microsoft-device-codes-abuse/amp)**

**PIR: 1.f**

Source: ketch Published: 2026-08-31

The EvilTokens campaign demonstrates how attackers abuse Microsoft device codes to hijack accounts without ever capturing passwords. By automating the device code flow, threat actors generate valid access tokens that bypass standard security controls. Defenders should audit OAuth application permissions, monitor for anomalous token generation patterns, and implement strict conditional access policies to prevent silent account takeover.

___________________________________


# **[Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA](https://tempmail.ninja/blog/laundry-bear-zimbra-phishing)**

**PIR: 1.g**

Source: ketch Published: 2026-08-31

CISA has issued a warning regarding the Laundry Bear campaign, which exploits a zero-click vulnerability in Zimbra email servers to deliver phishing payloads. This attack requires no user interaction, making it highly dangerous for unpatched infrastructure. Administrators must immediately apply vendor patches, segment email servers, and deploy network-level detection rules to identify exploitation attempts before lateral movement occurs.

___________________________________


# **[Three Active Microsoft 365 Phishing Campaigns Targeting Schools and Government Agencies](https://forsyteit.com/three-active-microsoft-365-phishing-campaigns-targeting-schools-and-government-agencies)**

**PIR: 1.a**

Source: ketch Published: 2026-08-31

Three active Microsoft 365 phishing campaigns are currently targeting educational and government sectors, leveraging tailored lures to harvest credentials and deploy malware. These campaigns exploit sector-specific workflows to increase click-through rates. Defenders should implement email authentication protocols, deploy URL sandboxing, and conduct targeted user awareness training to mitigate sector-focused phishing threats.

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


# **[CVE-2026-81888](https://nvd.nist.gov/vuln/detail/CVE-2026-81888)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-31

@hono/oauth-providers is Authentication middleware for Hono. Prior to version 0.8.6, the built-in social login providers accept an OAuth callback even when the `state` value is absent on both sides, so the anti-CSRF check passes for a callback that never came from a genuine login attempt. This defeats the `state`-based CSRF protection under default usage. Version 0.8.6 has a patch.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-17615 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-17615)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-31

Directly impacts Keycloak IdAM deployments and core enterprise middleware, risking unauthenticated exposure of identity credentials and token signing keys across government, finance, and healthcare sectors.

*Deep dive: `TIER_2_CVE-2026-17615.md`*

___________________________________


# **[CVE-2026-82801 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-82801)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-31

Unauthenticated SSRF in NASA's public Earthdata Search portal enables internal network mapping and backend access, directly impacting Government digital infrastructure.

*Deep dive: `TIER_2_CVE-2026-82801.md`*

___________________________________


# **[CVE-2026-72001 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-72001)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-31

TIER 2 authentication bypass in Pangolin remote access platform undermines SSO and token verification, directly impacting Digital Identity and Government sector access controls.

*Deep dive: `TIER_2_CVE-2026-72001.md`*

___________________________________


# **[CVE-2026-82877 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-82877)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-31

Impacts government and public-sector education infrastructure via authenticated credential theft in widely deployed LMS platforms.

*Deep dive: `TIER_2_CVE-2026-82877.md`*

___________________________________


# **[CVE-2026-82957 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-82957)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-31

Enterprise blockchain middleware (Hyperledger Firefly) with SSRF risk, explicitly noted for deployment in Finance and Government digital infrastructure contexts.

*Deep dive: `TIER_2_CVE-2026-82957.md`*

___________________________________


# **[CVE-2026-82397 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-82397)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-31

Foundational web framework DoS threatens availability of public-facing APIs and backend services underpinning government, finance, and healthcare digital infrastructure.

*Deep dive: `TIER_2_CVE-2026-82397.md`*

___________________________________


# **[CVE-2026-82921 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-82921)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-31

Finance sector relevance: e-commerce platform handling payments and customer financial data faces public RCE risk via unrestricted file upload.

*Deep dive: `TIER_2_CVE-2026-82921.md`*

___________________________________


# **[CVE-2026-82922 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-82922)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-31

Finance sector relevance: unauthenticated SQLi in a public-facing e-commerce platform directly threatens payment processing, customer accounts, and transactional data integrity.

*Deep dive: `TIER_2_CVE-2026-82922.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine