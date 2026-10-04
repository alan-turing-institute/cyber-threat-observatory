# **Infrastructure Daily Brief: 2026-10-03**

**Infrastructure Daily Report TLP:GREEN Alert Id: 38060262 2026-10-04 11:17:53**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-105115 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-105119 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-105105 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-71886 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-71887 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-71889 (Tier 2)                                                          | 3.k      |
| Threats    | Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Se | 1.c.1    |
| Threats    | Tracking BigBear 2.0 Evilginx2 Phishing Campaign | CloudSEK                      | 1.b.2    |
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.d.1    |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover                        | 1.c.2    |
| Threats    | We Need to Talk About Device Code Phishing | Huntress                            | 1.c.3    |
| Threats    | Exposed Server Reveals Three Microsoft 365 Phishing Campaigns                    | 1.e.1    |
| Threats    | Operation HookedWing: 4 Years, 500 Organizations, 2,000 Credentials              | 1.a.1    |
| Threats    | Access granted: phishing with device code authorization for account takeover | P | 1.c.4    |
| Threats    | CVE-2026-88779                                                                   | 1.b      |
| Threats    | CVE-2026-105120                                                                  | 1.b      |
| Threats    | CVE-2026-105121                                                                  | 1.b      |
| Threats    | CVE-2026-105116                                                                  | 1.b      |
| Threats    | CVE-2026-105114                                                                  | 1.b      |
| Threats    | CVE-2026-105117                                                                  | 1.b      |
| Threats    | CVE-2026-105122                                                                  | 1.b      |
| Threats    | CVE-2026-104638                                                                  | 1.b      |
| Threats    | CVE-2026-105118                                                                  | 1.b      |
| Threats    | CVE-2026-103877                                                                  | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/)**

**PIR: 1.c.1**

Source: ketch Published: 2026-10-03

Microsoft researchers dissect the EvilTokens campaign, detailing how threat actors abuse OAuth device code flows to bypass MFA and harvest valid access tokens. The report outlines infrastructure indicators, token validation bypass techniques, and defensive strategies for identity administrators. IT defenders can leverage these findings to harden conditional access policies, monitor for anomalous device code authorizations, and implement token lifetime restrictions to mitigate identity takeover r

___________________________________


# **[Tracking BigBear 2.0 Evilginx2 Phishing Campaign | CloudSEK](https://www.cloudsek.com/blog/tracking-bigbear-2-0-evilginx2-phishing-campaign)**

**PIR: 1.b.2**

Source: ketch Published: 2026-10-03

CloudSEK analyzes the BigBear 2.0 campaign leveraging Evilginx2 to conduct sophisticated proxy-based phishing attacks. The threat group targets enterprise users by hosting malicious reverse proxies that capture session cookies and MFA tokens in real-time. Infrastructure defenders should review proxy logs, implement certificate pinning, and deploy browser isolation solutions. The article provides actionable IOCs and network-level detection rules to block Evilginx2 infrastructure and disrupt crede

___________________________________


# **[Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.d.1**

Source: ketch Published: 2026-10-03

This Microsoft Security Blog post reveals how adversaries integrate generative AI to automate device code phishing at scale. AI models dynamically generate convincing login prompts and adapt to user behavior, significantly increasing success rates. The analysis covers campaign infrastructure, AI prompt engineering techniques, and detection gaps in traditional email security. Defenders are advised to enhance identity monitoring, restrict device code grant types, and deploy behavioral analytics to

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.c.2**

Source: ketch Published: 2026-10-03

Proofpoint examines the tactical shift toward device code phishing as a primary vector for identity compromise. Unlike traditional credential harvesting, this method captures valid OAuth tokens that often bypass step-up authentication. The report details attacker infrastructure, token reuse patterns, and mitigation strategies for cloud identity platforms. IT teams should prioritize monitoring for unusual device code flows, enforce strict conditional access rules, and educate users on recognizing

___________________________________


# **[We Need to Talk About Device Code Phishing | Huntress](https://www.huntress.com/blog/tradecraft-tuesday-device-code-phishing-explained)**

**PIR: 1.c.3**

Source: ketch Published: 2026-10-03

Huntress breaks down the tradecraft behind device code phishing, explaining why it poses a severe threat to modern identity architectures. The article walks through the OAuth 2.0 device authorization flow, highlighting how attackers exploit legitimate endpoints to steal tokens. Defenders gain insights into detection methodologies, including SIEM queries for anomalous device code events and recommendations for tightening identity provider configurations to reduce attack surface.

___________________________________


# **[Exposed Server Reveals Three Microsoft 365 Phishing Campaigns](https://breachnews.com/research/exposed-phishing-infrastructure-reveals-three-active-microsoft-365-campaigns/)**

**PIR: 1.e.1**

Source: ketch Published: 2026-10-03

BreachNews investigates a misconfigured server that inadvertently exposed infrastructure supporting three active Microsoft 365 phishing campaigns. The analysis reveals shared hosting patterns, domain registration tactics, and payload delivery mechanisms targeting enterprise email users. Infrastructure teams can use these findings to improve asset visibility, enforce strict server hardening standards, and implement DNS sinkholing to disrupt campaign infrastructure before user impact.

___________________________________


# **[Operation HookedWing: 4 Years, 500 Organizations, 2,000 Credentials](https://www.gblock.app/articles/operation-hookedwing-four-year-phishing-500-orgs-may-2026)**

**PIR: 1.a.1**

Source: ketch Published: 2026-10-03

GBLOCK details a persistent phishing operation that successfully harvested credentials from hundreds of organizations over four years. The campaign utilized customized landing pages, domain spoofing, and credential stuffing follow-ups. The report provides a comprehensive breakdown of attacker infrastructure, TTP evolution, and defensive recommendations. Identity defenders should focus on credential monitoring, implement passwordless authentication, and deploy real-time alerting for compromised a

___________________________________


# **[Access granted: phishing with device code authorization for account takeover | Proofpoint US](https://www.proofpoint.com/us/blog/threat-insight/access-granted-phishing-device-code-authorization-account-takeover)**

**PIR: 1.c.4**

Source: ketch Published: 2026-10-03

Proofpoint explores the mechanics of device code authorization phishing, demonstrating how attackers trick users into granting access to malicious applications. The article outlines the technical workflow, token persistence risks, and detection challenges for security operations centers. IT infrastructure defenders are guided through implementing token revocation strategies, enhancing user training for authorization prompts, and configuring identity providers to limit device code grant exposure.

___________________________________


# **[CVE-2026-88779](https://nvd.nist.gov/vuln/detail/CVE-2026-88779)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-04

Vulnerability in NetScaler ADC and NetScaler Gateway.

This issue affects ADC: before 14.1-73.41, before 13.1-64.28, before 14.1-73.41 FIPS, and before 13.1-37.282; Gateway: before 14.1-73.41 and before 13.1-64.28.

___________________________________


# **[CVE-2026-105120](https://nvd.nist.gov/vuln/detail/CVE-2026-105120)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-03

OpenAM before 16.1.3 contains an authorization bypass vulnerability in the sessions REST endpoint query operation that allows realm administrators to list sessions of every realm. Attackers holding delegated RealmAdmin privileges can supply a _queryFilter naming another realm to disclose usernames, universal IDs, and session handles across tenant boundaries.

___________________________________


# **[CVE-2026-105121](https://nvd.nist.gov/vuln/detail/CVE-2026-105121)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-03

OpenAM before 16.1.3 contains an improper authorization vulnerability that allows delegated administrators to destroy sessions outside their realms because realm checks use the requester's realm. Authenticated accounts holding the iplanet-am-session-destroy-sessions attribute can supply a target session identifier or handle to forcibly log out users in any realm.

___________________________________


# **[CVE-2026-105116](https://nvd.nist.gov/vuln/detail/CVE-2026-105116)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-03

OpenAM before 16.1.3 contains a latent cross-site scripting defect that places the SAML message, relay state and target URL unencoded into the load-balancer cookie bounce auto-submit page. If reachable with cookieHashRedirectEnabled set, crafted requests could execute script in the OpenAM origin, though an unrelated HTTP 500 failure prevents exploitation in released versions.

___________________________________


# **[CVE-2026-105114](https://nvd.nist.gov/vuln/detail/CVE-2026-105114)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-03

OpenAM before 16.1.3 contains a reflected cross-site scripting vulnerability that allows unauthenticated attackers to inject script by supplying crafted parameters rendered unencoded on the OAuth2 authorization error page. Attackers can lure victims to a crafted /oauth2/authorize link with repeated parameters to run JavaScript in the OpenAM origin, acting within existing sessions or redirecting to phishing pages.

___________________________________


# **[CVE-2026-105117](https://nvd.nist.gov/vuln/detail/CVE-2026-105117)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-03

OpenAM before 16.1.3 contains an email content injection vulnerability that allows unauthenticated attackers to control notification email wording via the forgotPassword and register actions on /json/{realm}/users. Attackers can supply subject and message fields to send phishing mail from the organisation's configured From address, or abuse register as a relay to arbitrary recipients.

___________________________________


# **[CVE-2026-105122](https://nvd.nist.gov/vuln/detail/CVE-2026-105122)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-03

OpenAM before 16.1.3 contains a server-side request forgery vulnerability that allows attackers able to register or modify OAuth 2.0 clients to make OpenAM fetch internal resources via an unvalidated jwks_uri. Attackers can trigger unauthenticated fetches through client-authentication and ID-token validation to probe internal hosts, metadata endpoints or local files, or exhaust request threads for denial of service.

___________________________________


# **[CVE-2026-104638](https://nvd.nist.gov/vuln/detail/CVE-2026-104638)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-02

A security vulnerability has been detected in onetwothreeneth HospitalManagementSystem up to 9ef91ed6007314b6473110ed699dff76d158f61d. The impacted element is an unknown function of the file php/sessions.php. The manipulation of the argument ID leads to improper authentication. Remote exploitation of the attack is possible. The exploit has been disclosed publicly and may be used. This product follows a rolling release approach for continuous delivery, so version details for affected or updated r

___________________________________


# **[CVE-2026-105118](https://nvd.nist.gov/vuln/detail/CVE-2026-105118)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-03

OpenAM before 16.1.3 contains an open redirect vulnerability that allows unauthenticated attackers to redirect users by supplying an unverified id_token_hint to the /oauth2/connect/endSession endpoint. Attackers can name any realm client in a forged hint to redirect victims to any registered post-logout URI, enabling phishing that borrows the OpenAM host's trust.

___________________________________


# **[CVE-2026-103877](https://nvd.nist.gov/vuln/detail/CVE-2026-103877)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-02

Deserialization of Untrusted Data vulnerability in Apache Directory LDAP API.



A rogue/compromised LDAP server (or pre-TLS MITM) can answer a client's loadSchema() subschema search with a schema object that contains a serialized Java class, allowing some potential RCE. 



This issue affects Apache Directory LDAP API: from 2.1.0 before 2.1.9.



Users are recommended to upgrade to version 2.1.9, which fixes the issue.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-105115 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-105115)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-03

Compromises default-deployed, unauthenticated endpoints on OpenAM, a core IdAM/SSO platform critical to government, healthcare, and finance digital identity infrastructure.

*Deep dive: `TIER_2_CVE-2026-105115.md`*

___________________________________


# **[CVE-2026-105119 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-105119)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-03

Directly impacts core Identity Provider (IdP) infrastructure by bypassing PKCE in OAuth/OIDC hybrid flows, enabling session hijacking and token theft in digital identity systems.

*Deep dive: `TIER_2_CVE-2026-105119.md`*

___________________________________


# **[CVE-2026-105105 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-105105)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-03

Critical unauthenticated command injection in NASA's AIT-Core ground data system, directly impacting government space infrastructure and mission control operations.

*Deep dive: `TIER_2_CVE-2026-105105.md`*

___________________________________


# **[CVE-2026-71886 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-71886)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-03

Impacts Digital Identity by enabling OpenPGP trust chain manipulation and identity spoofing in cryptographic libraries used for citizen/service authentication and document signing.

*Deep dive: `TIER_2_CVE-2026-71886.md`*

___________________________________


# **[CVE-2026-71887 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-71887)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-03

Impacts OpenPGP signature verification and identity attribution, a foundational trust mechanism for digital identity and secure communications.

*Deep dive: `TIER_2_CVE-2026-71887.md`*

___________________________________


# **[CVE-2026-71889 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-71889)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-03

Foundational cryptographic library underpinning PKI/TLS trust for regulated sectors; bypasses X.509 NameConstraints impacting mTLS and API authentication in enterprise/government deployments.

*Deep dive: `TIER_2_CVE-2026-71889.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine