# **Infrastructure Daily Brief: 2026-10-04**

**Infrastructure Daily Report TLP:GREEN Alert Id: 053c1608 2026-10-05 03:18:24**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-105207 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-105208 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-105209 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-105210 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-105211 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-105212 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-105213 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-105215 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-105216 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-88779 (Tier 2)                                                          | 3.k      |
| Threats    | Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Se | 1.b.2    |
| Threats    | Tracking BigBear 2.0 Evilginx2 Phishing Campaign | CloudSEK                      | 1.a.1    |
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.d.1    |
| Threats    | Exposed Server Reveals Three Microsoft 365 Phishing Campaigns                    | 1.c.1    |
| Threats    | We Need to Talk About Device Code Phishing | Huntress                            | 1.b.1    |
| Threats    | CodeStorm - A Microsoft 365 AiTM Phishing Kit with Storm-1167 Overlap - Hexastri | 1.a.2    |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover                        | 1.b.3    |
| Threats    | Massive “TrustTrap” Phishing Campaign Exploits Human Perception, Targets Governm | 1.e.1    |
| Threats    | CVE-2026-105115                                                                  | 1.b      |
| Threats    | CVE-2026-105119                                                                  | 1.b      |
| Threats    | CVE-2026-105120                                                                  | 1.b      |
| Threats    | CVE-2026-105121                                                                  | 1.b      |
| Threats    | CVE-2026-105116                                                                  | 1.b      |
| Threats    | CVE-2026-105114                                                                  | 1.b      |
| Threats    | CVE-2026-105117                                                                  | 1.b      |
| Threats    | CVE-2026-105122                                                                  | 1.b      |
| Threats    | CVE-2026-105118                                                                  | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/)**

**PIR: 1.b.2**

Source: ketch Published: 2026-10-04

Microsoft researchers dissect the EvilTokens infrastructure, revealing how threat actors automate device code phishing to bypass MFA. The report details token validation endpoints, session hijacking techniques, and defensive strategies for identity protection teams to detect anomalous authorization requests and block malicious redirect URIs.

___________________________________


# **[Tracking BigBear 2.0 Evilginx2 Phishing Campaign | CloudSEK](https://www.cloudsek.com/blog/tracking-bigbear-2-0-evilginx2-phishing-campaign)**

**PIR: 1.a.1**

Source: ketch Published: 2026-10-04

CloudSEK analyzes the BigBear 2.0 campaign leveraging Evilginx2 to conduct advanced-in-the-middle attacks. Defenders learn how the proxy harvests session cookies and MFA tokens simultaneously, with actionable IOCs and network-level blocking rules to mitigate credential theft across enterprise environments.

___________________________________


# **[Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.d.1**

Source: ketch Published: 2026-10-04

Microsoft Security details a novel campaign using AI to dynamically generate phishing prompts and adapt device code requests. The report highlights evasion techniques against automated scanners, provides telemetry for identity protection tools, and outlines mitigation steps for securing OAuth endpoints.

___________________________________


# **[Exposed Server Reveals Three Microsoft 365 Phishing Campaigns](https://breachnews.com/research/exposed-phishing-infrastructure-reveals-three-active-microsoft-365-campaigns/)**

**PIR: 1.c.1**

Source: ketch Published: 2026-10-04

BreachNews uncovers a compromised server hosting three active M365 phishing campaigns. The analysis highlights shared infrastructure, login page cloning techniques, and email header anomalies. IT teams can use the provided domains and IP ranges to update proxy filters and monitor for unauthorized OAuth app registrations.

___________________________________


# **[We Need to Talk About Device Code Phishing | Huntress](https://www.huntress.com/blog/tradecraft-tuesday-device-code-phishing-explained)**

**PIR: 1.b.1**

Source: ketch Published: 2026-10-04

Huntress breaks down the mechanics of device code phishing, explaining how attackers exploit the OAuth 2.0 device authorization flow to bypass traditional email filters. The guide offers practical detection rules for SIEM platforms, user training recommendations, and architectural changes to limit device code abuse.

___________________________________


# **[CodeStorm - A Microsoft 365 AiTM Phishing Kit with Storm-1167 Overlap - Hexastrike Cybersecurity](https://hexastrike.com/resources/blog/threat-intelligence/codestorm-a-microsoft-365-aitm-phishing-kit-with-storm-1167-overlap/)**

**PIR: 1.a.2**

Source: ketch Published: 2026-10-04

Hexastrike examines the CodeStorm kit, noting its overlap with Storm-1167 infrastructure. The report details how the kit automates AiTM attacks against M365 tenants, providing defenders with YARA rules, network signatures, and identity governance controls to disrupt the campaign’s token harvesting pipeline.

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.b.3**

Source: ketch Published: 2026-10-04

Proofpoint explores how device code phishing represents a tactical shift from email-borne lures to direct endpoint exploitation. The article outlines threat actor workflows, detection gaps in legacy email security, and recommends conditional access policies and user behavior analytics to strengthen identity perimeter defenses.

___________________________________


# **[Massive “TrustTrap” Phishing Campaign Exploits Human Perception, Targets Government Services Across US, India, and Beyond](https://cyberp1.com/massive-trusttrap-phishing-campaign-exploits-human-perception-targets-government-services-across-us-india-and-beyond/)**

**PIR: 1.e.1**

Source: ketch Published: 2026-10-04

CyberP1 investigates a large-scale campaign exploiting cognitive biases to target government and enterprise services. The analysis covers domain generation algorithms, landing page obfuscation, and cross-border targeting patterns. Infrastructure defenders gain insights into DNS sinkholing strategies and threat intelligence sharing.

___________________________________


# **[CVE-2026-105115](https://nvd.nist.gov/vuln/detail/CVE-2026-105115)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-03

OpenAM before 16.1.3 contains an unauthenticated arbitrary class instantiation vulnerability in the legacy JAX-RPC SOAP interface that allows remote attackers to load classes without authentication. Attackers can send SOAP requests to /jaxrpc/* with an unverified session identifier and a chosen class name, crashing the server, probing the classpath, or potentially reaching code execution via gadget chains.

___________________________________


# **[CVE-2026-105119](https://nvd.nist.gov/vuln/detail/CVE-2026-105119)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-03

OpenAM before 16.1.3 applies its OAuth2 Provider PKCE enforcement only to authorization requests whose response_type is exactly code, so codes issued through OpenID Connect hybrid flows (code token, code id_token, code token id_token) carry no bound challenge. An attacker who intercepts such a code can redeem it for a public client's tokens with any non-empty code_verifier.

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


# **[CVE-2026-105118](https://nvd.nist.gov/vuln/detail/CVE-2026-105118)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-03

OpenAM before 16.1.3 contains an open redirect vulnerability that allows unauthenticated attackers to redirect users by supplying an unverified id_token_hint to the /oauth2/connect/endSession endpoint. Attackers can name any realm client in a forged hint to redirect victims to any registered post-logout URI, enabling phishing that borrows the OpenAM host's trust.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-105207 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-105207)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-04

Critical authentication bypass in ZITADEL IdAM platform enables unauthenticated account takeover, directly impacting Digital Identity and federated SSO infrastructure.

*Deep dive: `TIER_2_CVE-2026-105207.md`*

___________________________________


# **[CVE-2026-105208 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-105208)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-04

Core open-source IdAM platform vulnerability enabling session hijacking and external IdP token theft, directly impacting the Digital Identity sector.

*Deep dive: `TIER_2_CVE-2026-105208.md`*

___________________________________


# **[CVE-2026-105209 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-105209)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-04

Critical cross-tenant authorization bypass in ZITADEL IdP enables account takeover across organizations, directly threatening centralized Digital Identity infrastructure and multi-tenant IdAM deployments.

*Deep dive: `TIER_2_CVE-2026-105209.md`*

___________________________________


# **[CVE-2026-105210 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-105210)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-04

Directly impacts the Digital Identity sector by compromising MFA enrollment, phone verification, and session integrity in ZITADEL, a core open-source IdAM platform for public and regulated services.

*Deep dive: `TIER_2_CVE-2026-105210.md`*

___________________________________


# **[CVE-2026-105211 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-105211)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-04

Critical authentication bypass and MFA interception in ZITADEL, an open-source Identity Provider, enabling unauthenticated account takeover and directly impacting the Digital Identity sector.

*Deep dive: `TIER_2_CVE-2026-105211.md`*

___________________________________


# **[CVE-2026-105212 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-105212)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-04

Directly compromises core IdAM authentication and MFA/passkey enrollment in public-facing identity providers, posing systemic risk to digital identity infrastructure.

*Deep dive: `TIER_2_CVE-2026-105212.md`*

___________________________________


# **[CVE-2026-105213 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-105213)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-04

Core open-source Identity Provider (ZITADEL) allows deactivated organization users to bypass access revocation via Login V2, directly impacting digital identity lifecycle and incident response controls.

*Deep dive: `TIER_2_CVE-2026-105213.md`*

___________________________________


# **[CVE-2026-105215 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-105215)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-04

Directly compromises core IdAM authentication flows (OIDC/SAML/SSO) in ZITADEL, enabling account pre-hijacking and bypassing identity verification for public-facing services.

*Deep dive: `TIER_2_CVE-2026-105215.md`*

___________________________________


# **[CVE-2026-105216 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-105216)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-04

Foundational microservices framework with insecure TLS defaults impacting service-to-service authentication across Digital Identity, Finance, Healthcare, and Government deployments.

*Deep dive: `TIER_2_CVE-2026-105216.md`*

___________________________________


# **[CVE-2026-88779 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-88779)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-04

Targets SAML authentication in widely deployed Citrix edge gateways, directly impacting federated identity and SSO infrastructure across government, finance, and healthcare sectors.

*Deep dive: `TIER_2_CVE-2026-88779.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine