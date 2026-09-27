# **Infrastructure Daily Brief: 2026-09-26**

**Infrastructure Daily Report TLP:GREEN Alert Id: 0e80ea43 2026-09-27 11:32:26**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-100612 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-100661 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-100666 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-100662 (Tier 2)                                                         | 3.k      |
| Threats    | Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Se | 1.j.3    |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover | Proofpoint           | 1.b      |
| Threats    | Cloudflare participates in global operation to disrupt EvilTokens Phishing-as-a- | 1.c      |
| Threats    | Inside HarvestGate: Device-Code Phishing Kit Analysis | Vega                     | 1.j.3    |
| Threats    | Inside an AI‑enabled device code phishing campaign | Microsoft                   | 1.a      |
| Threats    | Storm-2372 conducts device code phishing campaign | Microsoft                    | 1.a      |
| Threats    | Tracking BigBear 2.0 Evilginx2 Phishing Campaign | CloudSEK                      | 1.a      |
| Threats    | Device Code Phishing Hits 340+ Microsoft 365 Orgs Across Five Countries ... | Th | 1.j.3    |
| Threats    | CVE-2026-92609                                                                   | 1.b      |
| Threats    | CVE-2026-100684                                                                  | 1.b      |
| Threats    | CVE-2026-100607                                                                  | 1.b      |
| Threats    | CVE-2026-100606                                                                  | 1.b      |
| Threats    | CVE-2026-100709                                                                  | 1.b      |
| Threats    | CVE-2026-97846                                                                   | 1.b      |
| Threats    | CVE-2026-96448                                                                   | 1.b      |
| Threats    | CVE-2026-92289                                                                   | 1.b      |
| Threats    | CVE-2026-92288                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/)**

**PIR: 1.j.3**

Source: ketch Published: 2026-09-26

Microsoft Security researchers dissect the EvilTokens campaign, revealing how threat actors exploit device code authentication flows to bypass multi-factor authentication. The report details infrastructure patterns, token harvesting techniques, and defensive strategies for IT administrators to detect and block OAuth abuse in enterprise environments.

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover | Proofpoint](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.b**

Source: ketch Published: 2026-09-26

Proofpoint examines the rapid proliferation of device code phishing, driven by publicly available toolkits and PhaaS offerings. The report highlights emerging techniques that adapt to corporate validation workflows, providing IT defenders with threat landscape trends, risk assessments, and architectural recommendations to harden identity infrastructure against token hijacking.

___________________________________


# **[Cloudflare participates in global operation to disrupt EvilTokens Phishing-as-a-Service | Cloudflare](https://www.cloudflare.com/threat-intelligence/research/report/cloudflare-participates-in-global-operation-to-disrupt-eviltokens-phishing-as-a-service/)**

**PIR: 1.c**

Source: ketch Published: 2026-09-26

Cloudflare joins international law enforcement and security vendors to dismantle the EvilTokens Phishing-as-a-Service infrastructure. The operation highlights how PhaaS platforms lower the barrier for identity theft campaigns, offering actionable intelligence on domain registration patterns, hosting infrastructure, and mitigation tactics for network defenders.

___________________________________


# **[Inside HarvestGate: Device-Code Phishing Kit Analysis | Vega](https://vega.io/blog/inside-harvestgate-device-code-phishing)**

**PIR: 1.j.3**

Source: ketch Published: 2026-09-26

Vega researchers reverse-engineer the HarvestGate phishing kit, exposing its automated device code generation and victim tracking capabilities. The analysis reveals how attackers streamline identity takeover workflows, offering infrastructure teams technical insights into kit deployment, C2 communication patterns, and proactive blocking strategies for OAuth endpoints.

___________________________________


# **[Inside an AI‑enabled device code phishing campaign | Microsoft](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.a**

Source: ketch Published: 2026-09-26

Microsoft details a novel campaign where threat actors use AI to automate device code generation and victim interaction at scale. The report explains how end-to-end automation increases compromise success rates and sustains post-breach access, offering infrastructure defenders guidance on detecting AI-driven phishing infrastructure and implementing adaptive authentication controls.

___________________________________


# **[Storm-2372 conducts device code phishing campaign | Microsoft](https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/)**

**PIR: 1.a**

Source: ketch Published: 2026-09-26

Microsoft Threat Intelligence tracks Storm-2372’s long-running device code phishing operations, which mimic popular messaging apps to trick users into authorizing malicious tokens. The report outlines the actor’s infrastructure evolution, lure customization tactics, and defensive measures for IT teams to detect and mitigate APT-driven identity compromise campaigns.

___________________________________


# **[Tracking BigBear 2.0 Evilginx2 Phishing Campaign | CloudSEK](https://www.cloudsek.com/blog/tracking-bigbear-2-0-evilginx2-phishing-campaign)**

**PIR: 1.a**

Source: ketch Published: 2026-09-26

CloudSEK analyzes the BigBear 2.0 campaign leveraging Evilginx2, a sophisticated reverse-proxy phishing tool that captures session cookies and bypasses MFA. The report provides infrastructure defenders with IOCs, proxy architecture breakdowns, and detection rules to identify and block credential harvesting attempts targeting enterprise identity providers.

___________________________________


# **[Device Code Phishing Hits 340+ Microsoft 365 Orgs Across Five Countries ... | The Hacker News](https://thehackernews.com/2026/03/device-code-phishing-hits-340-microsoft.html)**

**PIR: 1.j.3**

Source: ketch Published: 2026-09-26

The Hacker News reports on a widespread device code phishing campaign targeting over 340 Microsoft 365 organizations. By abusing OAuth consent flows, attackers achieve persistent token hijacking and account takeover. The article provides infrastructure teams with incident response insights, affected service patterns, and recommendations for monitoring anomalous authentication requests.

___________________________________


# **[CVE-2026-92609](https://nvd.nist.gov/vuln/detail/CVE-2026-92609)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-25

Session fixation in HTTP management authentication allows remote attackers to gain unauthorized access to an authenticated management session via reuse of a session identifier retained across successful authentication.

This issue affects Apache Qpid Broker-J: through 10.1.0.

Users are recommended to upgrade to version 10.1.1, which fixes the issue.

___________________________________


# **[CVE-2026-100684](https://nvd.nist.gov/vuln/detail/CVE-2026-100684)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-26

Budibase versions 3.41.0 before 3.45.0 contain an authentication bypass in the OIDC/SSO login path of @budibase/server. In sso.authenticate, when no existing user matches the incoming SSO subject, the server looks up pending user invites by the IdP-asserted email address alone — without validating an invite code and without an email_verified check (the email_verified gate protects only the existing-account lookup). An attacker who can register at an IdP that the tenant trusts for OIDC and assert

___________________________________


# **[CVE-2026-100607](https://nvd.nist.gov/vuln/detail/CVE-2026-100607)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-26

Flowise through 3.1.4 resolves SSO and local-password users solely by email without storing provider or subject identifier bindings, allowing attackers to authenticate as any existing user by claiming their email at any configured SSO provider. Attackers can gain complete account access including chatflows, credentials, and API keys by authenticating through a different SSO provider or local password than the victim's original registration method.

___________________________________


# **[CVE-2026-100606](https://nvd.nist.gov/vuln/detail/CVE-2026-100606)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-26

Flowise through 3.1.4 (Enterprise/platform mode with SSO enabled) contains an authentication bypass in the SSO login path. When an SSO callback arrives with an email matching a user whose status is INVITED, verifyAndLogin (SSOBase.ts:80-94) copies the user record from the database — including the server-stored single-use invitation tempToken — into the data passed to AccountService.register(). The register handler's token lookup, email match, and expiry checks therefore pass trivially against th

___________________________________


# **[CVE-2026-100709](https://nvd.nist.gov/vuln/detail/CVE-2026-100709)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-26

Froxlor through 2.3.10 stores only a numeric user ID in remembered-2FA tokens (panel_2fa_tokens) without recording the account namespace, and the remembered-token lookup during login is not constrained to the customer or administrator account type. Because customer and administrator IDs are allocated from separate namespaces, a remembered-2FA token legitimately issued to a customer with a given ID also matches an administrator with the same ID. An attacker who controls a customer account with a 

___________________________________


# **[CVE-2026-97846](https://nvd.nist.gov/vuln/detail/CVE-2026-97846)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-25

Keycloak provides a feature called mTLS holder-of-key binding which ensures that a token can only be used by the client that originally requested it by binding it to their digital certificate. A flaw was discovered where the new Standard Token Exchange V2 feature does not check for this certificate. This allows an attacker with stolen client credentials to obtain a standard, unrestricted token that bypasses these security protections.

___________________________________


# **[CVE-2026-96448](https://nvd.nist.gov/vuln/detail/CVE-2026-96448)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-25

A flaw was found in the Fine-Grained Admin Permissions (FGAP v2) feature of Keycloak, an identity and access management solution. The issue occurs when the system checks if a delegated administrator has permission to assign a specific role to a user. Because the check does not look inside composite roles to see what other permissions they contain, an administrator with limited rights can assign a role that secretly includes full administrative control. This allows the attacker to gain complete m

___________________________________


# **[CVE-2026-92289](https://nvd.nist.gov/vuln/detail/CVE-2026-92289)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-25

Lemonldap::NG::Portal versions from 2.23.0 before 2.23.4 for Perl allow a PKCE bypass for public Relying Parties in "PKCE or secret" mode because checkEndPointAuthenticationCredentials does not verify the client secret.

With oidcRPMetaDataOptionsRequirePKCE set to 2, the authorization endpoint issues a code even when the request carries no code_challenge, and token() admits the exchange as long as a challenge was stored or an authentication method was returned for the caller. checkEndPointAuthe

___________________________________


# **[CVE-2026-92288](https://nvd.nist.gov/vuln/detail/CVE-2026-92288)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-25

Lemonldap::NG::Portal versions from 2.20.0 before 2.21.6, from 2.22.0 before 2.23.4 for Perl allow unauthenticated OAuth2 token introspection because checkEndPointAuthenticationCredentials does not verify the client secret of a public Relying Party.

checkEndPointAuthenticationCredentials() skips the secret comparison for a Relying Party marked public and still returns the authentication method deduced from the request, client_secret_basic or client_secret_post. introspection() rejects a caller 

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-100612 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-100612)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-26

Digital Identity sector: directly compromises SSO trust anchors and identity federation in enterprise IdAM stacks, enabling vertical privilege escalation to full org owner control.

*Deep dive: `TIER_2_CVE-2026-100612.md`*

___________________________________


# **[CVE-2026-100661 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-100661)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-26

Foundational Java networking library (Netty) underpinning public-facing API gateways and microservices across Finance, Government, and Healthcare, with unauthenticated DoS risk in default HTTP/3 configurations.

*Deep dive: `TIER_2_CVE-2026-100661.md`*

___________________________________


# **[CVE-2026-100666 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-100666)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-26

Core Java networking library (Netty) underpins public-facing APIs and microservices across finance, healthcare, and government sectors.

*Deep dive: `TIER_2_CVE-2026-100666.md`*

___________________________________


# **[CVE-2026-100662 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-100662)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-26

Foundational Java networking library (Netty) underpins public-facing APIs and edge proxies; unauthenticated HTTP/3 DoS threatens availability of regulated and civic digital services.

*Deep dive: `TIER_2_CVE-2026-100662.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine