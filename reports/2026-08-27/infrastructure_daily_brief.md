# **Infrastructure Daily Brief: 2026-08-27**

**Infrastructure Daily Report TLP:GREEN Alert Id: 9e061145 2026-08-28 13:14:58**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-59316 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-59354 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-18965 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-54718 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-54721 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-81679 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-18885 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-18886 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-6876 (Tier 2)                                                           | 3.k      |
| Cyber News | CVE-2026-74820 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-74848 (Tier 2)                                                          | 3.k      |
| Threats    | OAuth Device Code Phishing: 37x Surge in Enterprise ATO                          | 1.c      |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover                        | 1.c      |
| Threats    | The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations         | 1.d      |
| Threats    | Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA      | 1.e      |
| Threats    | Device Code Phishing — The Attack That Makes MFA Irrelevant                      | 1.b      |
| Threats    | EvilTokens Abuses Microsoft Device Codes to Hijack Accounts Without Stealing Pas | 1.c      |
| Threats    | Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA                  | 1.f      |
| Threats    | PhantomEnigma: How a Malware Crew Turned Brazilian Government Sites Into Trusted | 1.g      |
| Threats    | CVE-2026-65956                                                                   | 1.b      |
| Threats    | CVE-2026-64632                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[OAuth Device Code Phishing: 37x Surge in Enterprise ATO](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/04/CSA_research_note_oauth-device-code-phishing-surge_20260405-csa-styled.pdf)**

**PIR: 1.c**

Source: ketch Published: 2026-08-27

This research note documents a 37-fold increase in enterprise account takeover attacks leveraging OAuth device code flows. Attackers bypass traditional MFA by tricking users into entering authorization codes on malicious domains. The report details technical indicators, affected cloud providers, and mitigation strategies for identity architects, emphasizing the need for conditional access policies and device code flow monitoring.

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.c**

Source: ketch Published: 2026-08-27

Proofpoint analyzes how device code phishing has evolved from opportunistic scams into a structured identity takeover methodology. The article breaks down the OAuth 2.0 device authorization flow exploitation, highlighting how threat actors harvest tokens without credential theft. It provides actionable detection rules for SIEM platforms and recommends architectural changes to limit token scope and enforce continuous authentication.

___________________________________


# **[The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations](https://itsecurityguru.org/2026/05/27/the-ai-phishing-revolution-from-spray-and-pray-to-autonomous-operations)**

**PIR: 1.d**

Source: ketch Published: 2026-08-27

This report examines the shift from manual, high-volume phishing to AI-driven, autonomous campaigns. Generative models now craft context-aware lures, dynamically adapt to user responses, and automate infrastructure provisioning. Defenders are advised to implement behavioral analytics, deploy AI-resistant email authentication, and prioritize zero-trust identity validation over perimeter-based filtering.

___________________________________


# **[Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA](https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns)**

**PIR: 1.e**

Source: ketch Published: 2026-08-27

CYFIRMA details how threat actors abuse serverless functions, container registries, and ephemeral cloud resources to host phishing infrastructure. These campaigns evade traditional IP-based blocking by leveraging legitimate cloud APIs. The analysis provides infrastructure defenders with detection patterns for anomalous cloud resource creation, DNS tunneling indicators, and cloud-native security posture recommendations.

___________________________________


# **[Device Code Phishing — The Attack That Makes MFA Irrelevant](https://cybergrind.org/blog/2026-06-02-device-code-phishing)**

**PIR: 1.b**

Source: ketch Published: 2026-08-27

CyberGrind explores how device code phishing effectively neutralizes multi-factor authentication by intercepting valid OAuth tokens. The article explains the technical mechanics of token hijacking, demonstrates real-world attack chains, and outlines defensive controls including token binding, certificate-based authentication, and strict conditional access rules to protect enterprise identity perimeters.

___________________________________


# **[EvilTokens Abuses Microsoft Device Codes to Hijack Accounts Without Stealing Passwords](https://gbhackers.com/microsoft-device-codes-abuse/amp)**

**PIR: 1.c**

Source: ketch Published: 2026-08-27

This technical breakdown reveals how the EvilTokens group exploits Microsoft’s device code authentication to hijack accounts without capturing passwords. By leveraging legitimate OAuth endpoints, attackers obtain long-lived access tokens that bypass standard MFA prompts. The report includes network traffic analysis, token lifecycle details, and mitigation steps for Microsoft 365 administrators.

___________________________________


# **[Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA](https://tempmail.ninja/blog/laundry-bear-zimbra-phishing)**

**PIR: 1.f**

Source: ketch Published: 2026-08-27

CISA warns of a zero-click phishing campaign targeting Zimbra email servers, attributed to the Laundry Bear threat group. The attack exploits unpatched server vulnerabilities to inject malicious payloads directly into user inboxes, requiring no user interaction. Infrastructure teams are urged to apply critical patches, monitor for anomalous server-side scripting, and isolate affected mail clusters immediately.

___________________________________


# **[PhantomEnigma: How a Malware Crew Turned Brazilian Government Sites Into Trusted Malware Hubs](https://securebulletin.com/phantomenigma-how-a-malware-crew-turned-brazilian-government-sites-into-trusted-malware-hubs)**

**PIR: 1.g**

Source: ketch Published: 2026-08-27

SecureBulletin investigates how the PhantomEnigma crew compromised Brazilian government websites to distribute malware under trusted domains. By exploiting legacy CMS vulnerabilities and weak hosting configurations, attackers bypassed reputation-based security controls. The report outlines infrastructure hardening practices, DNS monitoring techniques, and supply chain validation steps for public-facing web assets.

___________________________________


# **[CVE-2026-65956](https://nvd.nist.gov/vuln/detail/CVE-2026-65956)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-26

KubePi is a Kubernetes multi-cluster management panel. In versions up to and including 1.6.15, the SSO configuration API endpoints are exposed on the same public routing boundary as the SSO login and callback endpoints, so SSO, OIDC, and SAML management operations can be reached without administrator authorization. Because reading, creating, and updating the global SSO configuration is not restricted to administrators, an unauthorized or low-privileged user can inspect or alter the authenticatio

___________________________________


# **[CVE-2026-64632](https://nvd.nist.gov/vuln/detail/CVE-2026-64632)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-26

A vulnerability allowing a low-privileged user to capture the NTLM credentials of the Reporter service account.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-59316 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-59316)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-27

Digital Identity: Stored XSS in Spring Authorization Server's default consent page compromises OAuth2/OIDC identity flows and session trust boundaries.

*Deep dive: `TIER_2_CVE-2026-59316.md`*

___________________________________


# **[CVE-2026-59354 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-59354)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-27

Critical flaw in Spring Security OAuth2 Authorization Server impacts foundational Digital Identity infrastructure, enabling stored XSS, SSRF, and privilege escalation in enterprise IdP deployments.

*Deep dive: `TIER_2_CVE-2026-59354.md`*

___________________________________


# **[CVE-2026-18965 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-18965)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-27

Finance sector relevance: unauthenticated API flaw in a cloud payment processing platform exposes IoT transaction terminals and disrupts cashless payment infrastructure.

*Deep dive: `TIER_2_CVE-2026-18965.md`*

___________________________________


# **[CVE-2026-54718 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-54718)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-27

Authenticated RCE via SSTI in Silverstripe CMS workflow module, widely deployed across government and public-sector websites.

*Deep dive: `TIER_2_CVE-2026-54718.md`*

___________________________________


# **[CVE-2026-54721 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-54721)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-27

Authenticated RCE in Silverstripe CMS UserForms module, widely deployed across government and public-sector digital infrastructure.

*Deep dive: `TIER_2_CVE-2026-54721.md`*

___________________________________


# **[CVE-2026-81679 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-81679)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-27

Cross-tenant data leakage in OpenRemote IoT broker impacts smart city and municipal infrastructure deployments, breaking civic data isolation and compliance boundaries.

*Deep dive: `TIER_2_CVE-2026-81679.md`*

___________________________________


# **[CVE-2026-18885 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-18885)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-27

TIER 2 unauthenticated RCE in ServiceNow AI platform; classified as general infrastructure that indirectly supports DPI operations across regulated enterprise environments.

*Deep dive: `TIER_2_CVE-2026-18885.md`*

___________________________________


# **[CVE-2026-18886 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-18886)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-27

Critical unauthenticated privilege escalation in ServiceNow AI Platform, a core enterprise workflow system widely deployed across government, healthcare, and finance sectors.

*Deep dive: `TIER_2_CVE-2026-18886.md`*

___________________________________


# **[CVE-2026-6876 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-6876)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-27

Unauthenticated RCE in ServiceNow Now Platform, a core enterprise ITSM/portal stack widely deployed across government, finance, and healthcare for public-facing service delivery.

*Deep dive: `TIER_2_CVE-2026-6876.md`*

___________________________________


# **[CVE-2026-74820 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-74820)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-27

General infrastructure vulnerability in ServiceNow AI Platform affecting widely deployed enterprise ITSM/HR workflows across regulated and public-sector environments.

*Deep dive: `TIER_2_CVE-2026-74820.md`*

___________________________________


# **[CVE-2026-74848 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-74848)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-27

General infrastructure API gateway flaw enabling cross-user response poisoning and data leakage, impacting edge deployments across regulated sectors.

*Deep dive: `TIER_2_CVE-2026-74848.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine