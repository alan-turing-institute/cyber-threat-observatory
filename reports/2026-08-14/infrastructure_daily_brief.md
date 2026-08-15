# **Infrastructure Daily Brief: 2026-08-14**

**Infrastructure Daily Report TLP:GREEN Alert Id: ef55e214 2026-08-15 03:22:58**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-19764 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-19870 (Tier 2)                                                          | 3.k      |
| Threats    | OAuth Device Code Phishing: 37x Surge in Enterprise ATO                          | 1.e      |
| Threats    | Device Code Phishing — The Attack That Makes MFA Irrelevant                      | 1.f      |
| Threats    | The Illicit Consent Grant Part 2: Device-Code Phishing and the AI PhaaS Wave | S | 1.e      |
| Threats    | The Device Code Phishing Tsunami: What We’re Seeing in the Wild                  | 1.f      |
| Threats    | Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA      | 1.g      |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover                        | 1.f      |
| Threats    | The Microsoft 365 Account Takeover That Leaves No Trace                          | 1.d      |
| Threats    | Anatomy of a Modern Phishing Campaign                                            | 1.a      |
| Threats    | CVE-2026-28008                                                                   | 1.b      |
| Threats    | CVE-2026-61967                                                                   | 1.b      |
| Threats    | CVE-2026-73644                                                                   | 1.b      |
| Threats    | CVE-2026-73302                                                                   | 1.b      |
| Threats    | CVE-2026-72856                                                                   | 1.b      |
| Threats    | CVE-2026-0299                                                                    | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[OAuth Device Code Phishing: 37x Surge in Enterprise ATO](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/04/CSA_research_note_oauth-device-code-phishing-surge_20260405-csa-styled.pdf)**

**PIR: 1.e**

Source: ketch Published: 2026-08-14

Highlights a 37-fold increase in enterprise account takeovers leveraging OAuth device code flows. Attackers bypass traditional MFA by prompting users to authorize malicious apps via short alphanumeric codes. The report details infrastructure-level indicators, compromised client IDs, and mitigation strategies for identity providers and cloud administrators.

___________________________________


# **[Device Code Phishing — The Attack That Makes MFA Irrelevant](https://cybergrind.org/blog/2026-06-02-device-code-phishing)**

**PIR: 1.f**

Source: ketch Published: 2026-08-14

Explores how device code phishing neutralizes multi-factor authentication by exploiting legitimate OAuth authorization endpoints. The analysis covers attacker infrastructure, phishing page hosting patterns, and real-world campaign timelines. Provides actionable detection rules for SIEM and identity governance platforms to block illicit consent grants and protect enterprise directories.

___________________________________


# **[The Illicit Consent Grant Part 2: Device-Code Phishing and the AI PhaaS Wave | SlashID Blog](https://slashid.com/blog/illicit-consent-grant-part-2)**

**PIR: 1.e**

Source: ketch Published: 2026-08-14

Details the evolution of illicit consent grants combined with AI-generated phishing-as-a-service platforms. Attackers automate credential harvesting and OAuth abuse at scale, targeting enterprise identity ecosystems. The article provides technical breakdowns of malicious app registrations, token theft mechanisms, and defensive controls for identity architects and security operations teams.

___________________________________


# **[The Device Code Phishing Tsunami: What We’re Seeing in the Wild](https://www.levelblue.com/blogs/spiderlabs-blog/the-device-code-phishing-tsunami-what-were-seeing-in-the-wild)**

**PIR: 1.f**

Source: ketch Published: 2026-08-14

Provides field observations of the device code phishing surge, detailing attacker infrastructure, domain registration patterns, and phishing kit distributions. The report emphasizes the operational impact on enterprise identity platforms and offers technical guidance for blocking malicious OAuth flows, monitoring consent logs, and implementing conditional access policies.

___________________________________


# **[Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA](https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns)**

**PIR: 1.g**

Source: ketch Published: 2026-08-14

Examines threat actors leveraging cloud-native services like serverless functions, object storage, and CDN networks to host phishing infrastructure. The research maps deployment patterns, cost-optimization tactics, and evasion techniques used to bypass traditional URL filtering. Offers infrastructure defenders guidance on cloud security posture management and automated takedown workflows.

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.f**

Source: ketch Published: 2026-08-14

Traces the tactical shift from traditional credential phishing to device code-based identity takeover campaigns. The analysis highlights how attackers exploit user trust in legitimate authorization prompts to bypass security controls. Includes infrastructure indicators, campaign attribution, and strategic recommendations for identity threat detection and user awareness programs.

___________________________________


# **[The Microsoft 365 Account Takeover That Leaves No Trace](https://deafnews.it/en/article/the-microsoft-365-account-takeover-that-leaves-no-trace)**

**PIR: 1.d**

Source: ketch Published: 2026-08-14

Analyzes stealthy Microsoft 365 account takeover techniques that evade standard logging and alerting mechanisms. Attackers exploit legacy authentication protocols, token replay, and shadow IT integrations to maintain persistent access. The report outlines forensic artifacts, detection queries for Microsoft Sentinel, and hardening recommendations for enterprise email and collaboration platforms.

___________________________________


# **[Anatomy of a Modern Phishing Campaign](https://ransomnews.com/anatomy-of-a-modern-phishing-campaign)**

**PIR: 1.a**

Source: ketch Published: 2026-08-14

Breaks down the full lifecycle of contemporary phishing operations, from initial reconnaissance and infrastructure provisioning to payload delivery and data exfiltration. The article highlights emerging evasion tactics, infrastructure reuse patterns, and defensive strategies for network and email security teams to improve early detection and incident response capabilities.

___________________________________


# **[CVE-2026-28008](https://nvd.nist.gov/vuln/detail/CVE-2026-28008)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-13

Unauthenticated Broken Authentication in OAuth Single Sign On – SSO (OAuth Client) <= 7.0.0 versions.

___________________________________


# **[CVE-2026-61967](https://nvd.nist.gov/vuln/detail/CVE-2026-61967)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-13

Unauthenticated Privilege Escalation in miniorange otp verification <= 5.5.1 versions.

___________________________________


# **[CVE-2026-73644](https://nvd.nist.gov/vuln/detail/CVE-2026-73644)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-13

OpenDJ is an LDAPv3 compliant directory service. Prior to 5.1.2, the SASL PLAIN authorization identity path in opendj-server-legacy/src/main/java/org/opends/server/extensions/PlainSASLMechanismHandler.java checked the PROXIED_AUTH privilege but did not evaluate the mayProxy proxy ACI scope when an authzid resolved to a different user. Both dn: and u: or bare authzid forms could therefore let an authenticated account holding PROXIED_AUTH assume any resolvable non-root identity outside the identit

___________________________________


# **[CVE-2026-73302](https://nvd.nist.gov/vuln/detail/CVE-2026-73302)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-13

Budibase is an open-source low-code platform. Prior to 3.39.30, the OIDC flow in packages/backend-core/src/middleware/passport/sso/oidc.ts resolved an email without getEmailVerified or an email_verified requirement, and packages/backend-core/src/middleware/passport/sso/sso.ts then used users.getGlobalUserByEmail as a fallback account-linking key. An attacker who can authenticate through a configured identity provider that asserts a victim email as unverified can have a fresh provider identity me

___________________________________


# **[CVE-2026-72856](https://nvd.nist.gov/vuln/detail/CVE-2026-72856)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-13

Budibase versions before 3.40.0 contain an authorization/authentication bypass in the PUT /api/global/users/tenant/owner (changeTenantOwnerEmail) endpoint. On self-hosted instances (SELF_HOSTED or DISABLE_ACCOUNT_PORTAL set), the cloudRestricted middleware is a no-op and the route is protected only by a general authentication check, so any authenticated user — including a lowest-privilege BASIC app user — can reassign the tenant account-holder (top-privilege admin) email to an attacker-controlle

___________________________________


# **[CVE-2026-0299](https://nvd.nist.gov/vuln/detail/CVE-2026-0299)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-13

Local privilege escalation vulnerabilities in the Palo Alto Networks GlobalProtect™ app enable a local user to escalate their privileges to NT AUTHORITY\SYSTEM on Windows, and root on macOS and Linux. This enables a non-administrative user to execute arbitrary commands with administrative privileges.

The GlobalProtect app on iOS, Android, and Chrome OS is not affected.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-19764 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-19764)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-14

Unauthenticated SQLi in a government/public safety dispatch platform enables credential theft and lateral movement within critical state telecom infrastructure.

*Deep dive: `TIER_2_CVE-2026-19764.md`*

___________________________________


# **[CVE-2026-19870 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-19870)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-14

Finance sector relevance: cross-tenant authorization bypass in a CRM payroll module exposes sensitive salary and banking (IBAN) data, threatening financial integrity and regulatory compliance.

*Deep dive: `TIER_2_CVE-2026-19870.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine