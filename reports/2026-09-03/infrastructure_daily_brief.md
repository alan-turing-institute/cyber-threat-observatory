# **Infrastructure Daily Brief: 2026-09-03**

**Infrastructure Daily Report TLP:GREEN Alert Id: a61a471a 2026-09-04 13:39:23**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-53728 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-63219 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-80465 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-83711 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-85394 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-58400 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-67398 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-80098 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-85089 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-85393 (Tier 2)                                                          | 3.k      |
| Threats    | OAuth Device Code Phishing: 37x Surge in Enterprise ATO                          | 1.j.3    |
| Threats    | Device Code Phishing — The Attack That Makes MFA Irrelevant                      | 1.j.3    |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover                        | 1.j.3    |
| Threats    | Device Code Phishing: Stealing Tokens via Real Login                             | 1.j.3    |
| Threats    | A New Era Of Social Engineering: The Device Code Phishing Boom                   | 1.j.3    |
| Threats    | The Illicit Consent Grant Part 2: Device-Code Phishing and the AI PhaaS Wave | S | 1.f      |
| Threats    | Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA      | 1.g      |
| Threats    | Russian State-Supported Cyber Actors Conduct Phishing Campaign ... - CISA        | 1.a      |
| Threats    | CVE-2026-19117                                                                   | 1.b      |
| Threats    | CVE-2026-84699                                                                   | 1.b      |
| Threats    | CVE-2026-62916                                                                   | 1.b      |
| Threats    | CVE-2026-84668                                                                   | 1.b      |
| Threats    | CVE-2026-84672                                                                   | 1.b      |
| Threats    | CVE-2026-84831                                                                   | 1.b      |
| Threats    | CVE-2026-85238                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[OAuth Device Code Phishing: 37x Surge in Enterprise ATO](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/04/CSA_research_note_oauth-device-code-phishing-surge_20260405-csa-styled.pdf)**

**PIR: 1.j.3**

Source: ketch Published: 2026-09-03

Documents a massive 37-fold increase in enterprise account takeovers driven by OAuth device code phishing. Attackers trick users into entering device codes on malicious sites, granting them valid tokens that bypass traditional MFA controls and compromise identity infrastructure.

___________________________________


# **[Device Code Phishing — The Attack That Makes MFA Irrelevant](https://cybergrind.org/blog/2026-06-02-device-code-phishing)**

**PIR: 1.j.3**

Source: ketch Published: 2026-09-03

Breaks down the technical mechanics of device code phishing and explains why it effectively neutralizes multi-factor authentication. Provides actionable mitigation strategies for infrastructure defenders, including token monitoring, conditional access hardening, and identity telemetry integration.

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.j.3**

Source: ketch Published: 2026-09-03

Positions device code phishing as a critical evolution in identity compromise tactics. By capturing valid OAuth tokens during the device authorization flow, attackers achieve persistent access while evading standard MFA alerts and conditional access policies.

___________________________________


# **[Device Code Phishing: Stealing Tokens via Real Login](https://kayssel.substack.com/p/device-code-phishing-stealing-tokens)**

**PIR: 1.j.3**

Source: ketch Published: 2026-09-03

Explains how device code phishing leverages legitimate authentication endpoints to harvest valid access tokens. Unlike traditional credential harvesting, this method captures real-time session data, making detection reliant on advanced identity telemetry and token lifecycle monitoring.

___________________________________


# **[A New Era Of Social Engineering: The Device Code Phishing Boom](https://coalitioninc.com/blog/security-labs/a-new-era-of-social-engineering-the-device-code-phishing-boom)**

**PIR: 1.j.3**

Source: ketch Published: 2026-09-03

Examines the rapid proliferation of device code phishing as a primary social engineering vector. The report details how attackers adapt messaging templates to target IT administrators and developers, leveraging legitimate OAuth flows to steal session tokens.

___________________________________


# **[The Illicit Consent Grant Part 2: Device-Code Phishing and the AI PhaaS Wave | SlashID Blog](https://slashid.com/blog/illicit-consent-grant-part-2)**

**PIR: 1.f**

Source: ketch Published: 2026-09-03

Continues the analysis of illicit consent grants, focusing on device-code phishing and the emergence of AI-driven Phishing-as-a-Service platforms. Highlights how automated infrastructure scales attacks and complicates identity governance for enterprise defenders.

___________________________________


# **[Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA](https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns)**

**PIR: 1.g**

Source: ketch Published: 2026-09-03

Explores how threat actors leverage cloud-native services like serverless functions, object storage, and dynamic DNS to host phishing infrastructure. This evasion technique bypasses traditional domain reputation filters and complicates takedown efforts for security teams.

___________________________________


# **[Russian State-Supported Cyber Actors Conduct Phishing Campaign ... - CISA](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-204a)**

**PIR: 1.a**

Source: ketch Published: 2026-09-03

CISA advisory on Russian state-sponsored actors targeting Zimbra Collaboration Suite users. The campaign employs spear-phishing emails with malicious attachments and links to harvest credentials and deploy backdoors across Western government and commercial networks.

___________________________________


# **[CVE-2026-19117](https://nvd.nist.gov/vuln/detail/CVE-2026-19117)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-02

Under specific conditions, an attacker can register an attacker-controlled FIDO2 credential against a target account and then authenticate as
that user. This issue affects on-premises deployments only.

___________________________________


# **[CVE-2026-84699](https://nvd.nist.gov/vuln/detail/CVE-2026-84699)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-02

Team Password Manager before 14.184.308 fails to enforce authentication requirements in the local account password reset flow. Unauthenticated attackers can reset local account passwords and authenticate as those users to gain unauthorized access.

___________________________________


# **[CVE-2026-62916](https://nvd.nist.gov/vuln/detail/CVE-2026-62916)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-03

Authentication bypass using an alternate path or channel in Microsoft Entra ID allows an unauthorized attacker to elevate privileges over a network.

___________________________________


# **[CVE-2026-84668](https://nvd.nist.gov/vuln/detail/CVE-2026-84668)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-02

Jenkins SAML Plugin 4.618.v441a_27fa_46d2 and earlier allows overwriting the SAML identity provider metadata file through Stapler data binding, allowing attackers to replace it with attacker-controlled content and authenticate as any user.

___________________________________


# **[CVE-2026-84672](https://nvd.nist.gov/vuln/detail/CVE-2026-84672)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-02

Jenkins Microsoft Entra ID (previously Azure AD) Plugin 710.v0b_ff8e9cc2d2 and earlier grants Entra group permissions using both the group's unique object ID and its display name, allowing attackers who can create an Entra group with a colliding display name to gain the permissions configured for a privileged group.

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



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-53728 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-53728)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-03

TIER 2 OAuth redirect flaw in Medplum healthcare platform enables full account takeover and PHI exposure, directly impacting Healthcare and Digital Identity sectors.

*Deep dive: `TIER_2_CVE-2026-53728.md`*

___________________________________


# **[CVE-2026-63219 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-63219)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-03

Unauthenticated file upload in GeoNetwork, a foundational platform for national Spatial Data Infrastructures and government geoportals, enabling RCE on public-facing civic systems.

*Deep dive: `TIER_2_CVE-2026-63219.md`*

___________________________________


# **[CVE-2026-80465 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-80465)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-03

Directly impacts Digital Identity infrastructure by allowing unauthenticated SAML signature bypass and session hijacking in enterprise SSO deployments.

*Deep dive: `TIER_2_CVE-2026-80465.md`*

___________________________________


# **[CVE-2026-83711 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-83711)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-03

Critical unauthenticated authorization bypass in Microsoft Entra ID B2C, a core cloud-native Digital Identity and Access Management (IdAM) platform.

*Deep dive: `TIER_2_CVE-2026-83711.md`*

___________________________________


# **[CVE-2026-85394 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-85394)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-03

Critical default authentication bypass in a foundational JWT library directly impacts Digital Identity, SSO gateways, and enterprise/public-sector access control systems.

*Deep dive: `TIER_2_CVE-2026-85394.md`*

___________________________________


# **[CVE-2026-58400 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-58400)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-03

Critical RCE in GeoNetwork, a foundational platform for national Spatial Data Infrastructures and government geoportals, requiring urgent patching for public-sector deployments.

*Deep dive: `TIER_2_CVE-2026-58400.md`*

___________________________________


# **[CVE-2026-67398 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-67398)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-03

Finance sector relevance: unauthenticated PII disclosure in a widely deployed payment gateway and billing platform (WHMCS), impacting regulated transaction processing and customer account management.

*Deep dive: `TIER_2_CVE-2026-67398.md`*

___________________________________


# **[CVE-2026-80098 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-80098)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-03

Critical privilege escalation in Microsoft Copilot Studio's internet-facing APIs, directly impacting government agencies and public-sector AI service automation.

*Deep dive: `TIER_2_CVE-2026-80098.md`*

___________________________________


# **[CVE-2026-85089 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-85089)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-03

TIER 2 authenticated credential leak in FreeRDP remote access proxies, directly impacting Digital Identity and government/enterprise session security.

*Deep dive: `TIER_2_CVE-2026-85089.md`*

___________________________________


# **[CVE-2026-85393 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-85393)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-03

Directly impacts Digital Identity infrastructure by enabling signature forgery in JWT, OAuth/OIDC, and SAML token validation for identity providers and API gateways.

*Deep dive: `TIER_2_CVE-2026-85393.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine