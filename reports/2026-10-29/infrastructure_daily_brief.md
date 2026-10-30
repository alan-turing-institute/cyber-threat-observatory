# **Infrastructure Daily Brief: 2026-10-29**

**Infrastructure Daily Report TLP:GREEN Alert Id: 4b2aeeee 2026-10-30 13:35:19**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-112256 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-119127 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-119128 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-119129 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-119283 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-62374 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-114358 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-114488 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-119049 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-119144 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-42922 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-84295 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-90868 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-93757 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-66090 (Tier 2)                                                          | 3.k      |
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.a      |
| Threats    | IR Trends Q2 2026: Phishing and weaponized remote management tools ...           | 1.a      |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover                        | 1.a      |
| Threats    | MadApe: The Code That Opens the Door                                             | 1.a      |
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.a      |
| Threats    | Unmasking EvilTokens: Getting to the root of device code phishing                | 1.a      |
| Threats    | Untitled                                                                         | 1.a      |
| Threats    | Email scammers posed as DOT officials in phishing messages focused on $1 trillio | 1.a      |
| Threats    | CVE-2026-92744                                                                   | 1.b      |
| Threats    | CVE-2026-59185                                                                   | 1.b      |
| Threats    | CVE-2026-118669                                                                  | 1.b      |
| Threats    | CVE-2025-14260                                                                   | 1.b      |
| Threats    | CVE-2026-45049                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.a**

Source: ketch Published: 2026-10-29

This campaign is distinct because it moves away from static, manual scripts toward an AI-driven infrastructure and multiple automations end-to-end. This activity marks a significant escalation in threat actor sophistication since the Storm-2372 device code phishing campaign observed in February 2025.

___________________________________


# **[IR Trends Q2 2026: Phishing and weaponized remote management tools ...](https://blog.talosintelligence.com/ir-trends-q2-2026/)**

**PIR: 1.a**

Source: ketch Published: 2026-10-29

QR phishing campaign leverages trusted infrastructure to target Australian organizations Starting in April, we observed a persistent QR code phishing campaign targeting primarily Australian organizations that leverages compromised Microsoft 365 accounts to harvest credentials and propagate the attack via internal contact lists. The campaign, which remained ongoing as of late June 2026, employs ...

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover](https://proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.a**

Source: ketch Published: 2026-10-29



___________________________________


# **[MadApe: The Code That Opens the Door](https://group-ib.com/blog/madape-microsoft-device-code-phishing-kit)**

**PIR: 1.a**

Source: ketch Published: 2026-10-29



___________________________________


# **[Inside an AI‑enabled device code phishing campaign](https://microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026)**

**PIR: 1.a**

Source: ketch Published: 2026-10-29



___________________________________


# **[Unmasking EvilTokens: Getting to the root of device code phishing](https://aka.ms/EvilTokens-PhaaS)**

**PIR: 1.a**

Source: ketch Published: 2026-10-29



___________________________________


# **[Untitled](https://cyberalberta.ca/system/files/CAA-2026-0018%20Device%20Code%20Phishing%20Attacks%20Abuse%20Legitimate%20Authentication%20Methods%20to%20Bypass%20MFA.pdf)**

**PIR: 1.a**

Source: ketch Published: 2026-10-29



___________________________________


# **[Email scammers posed as DOT officials in phishing messages focused on $1 trillion bill | CyberScoop](https://develop.cyberscoop.com/inky-dot-infrastructure-bill-phishing-bid)**

**PIR: 1.a**

Source: ketch Published: 2026-10-29



___________________________________


# **[CVE-2026-92744](https://nvd.nist.gov/vuln/detail/CVE-2026-92744)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-29

Under certain conditions, privilege manager agent allows a remote unauthenticated attacker to execute
arbitrary code as LocalSystem.

___________________________________


# **[CVE-2026-59185](https://nvd.nist.gov/vuln/detail/CVE-2026-59185)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-28

identrail is a machine identity security platform for AWS, GitHub/OIDC, and Kubernetes. Prior to 1.0.2, the default-on `POST /v1/workspaces/:workspace_id/projects/:project_id/github/connect/complete` endpoint in `internal/api/router.go` accepts `installation_id` from the request body or `X-GitHub-Installation-ID` header without verifying the installation belongs to the caller's workspace. `CompleteGitHubConnection` in `internal/api/github_connect.go` rigorously binds `state` to the caller's tena

___________________________________


# **[CVE-2026-118669](https://nvd.nist.gov/vuln/detail/CVE-2026-118669)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-28

OAuthLib is an implementation of the OAuth request-signing logic for Python 3.6+. Prior to 4.0.0, the client_credentials and Resource Owner Password Credentials token grant handlers can authenticate request.client as one confidential client while retaining an attacker-supplied request.client_id for validate_grant_type and validate_scopes. A lower-privilege authenticated client can therefore cause grant and scope authorization to use another client's identity when an application validator relies 

___________________________________


# **[CVE-2025-14260](https://nvd.nist.gov/vuln/detail/CVE-2025-14260)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-28

Due to the improper implementation of access control rules, the WSO2 product accepts user-supplied input related to resource location without enforcing expected validation constraints. This can be exploited by an unauthenticated actor to direct the server to make requests to arbitrary network locations.

Exploiting this vulnerability allows a malicious actor to access both internal and external resources, available through the network or filesystem, that are reachable by the WSO2 product. This c

___________________________________


# **[CVE-2026-45049](https://nvd.nist.gov/vuln/detail/CVE-2026-45049)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-29

Open Access Management (OpenAM) is an access management solution. Prior to 16.1.1, the `Cross-Domain Single Sign-On` (`CDSSO`) servlet allows a logged-in user's raw OpenAM session token to be POSTed to an attacker-controlled URL. An attacker who induces an authenticated victim to visit a crafted URL can receive the session credential and potentially hijack the session. Deployments must have `CDSSO` enabled, as is common in multi-domain deployments, and exploitation is additionally gated on a non

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-112256 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-112256)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-29

Critical unauthenticated authentication bypass in OpenText Advanced Authentication Server directly compromises enterprise IdP/MFA gateways, fully matching the Digital Identity sector criteria.

*Deep dive: `TIER_2_CVE-2026-112256.md`*

___________________________________


# **[CVE-2026-119127 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-119127)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-29

Core Identity Provider (ZITADEL) host header injection enables full account takeover via poisoned credential recovery links, directly impacting Digital Identity infrastructure.

*Deep dive: `TIER_2_CVE-2026-119127.md`*

___________________________________


# **[CVE-2026-119128 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-119128)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-29

Critical authentication bypass in ZITADEL IdAM platform enables unauthenticated account takeover, directly impacting the Digital Identity sector and zero-trust architectures.

*Deep dive: `TIER_2_CVE-2026-119128.md`*

___________________________________


# **[CVE-2026-119129 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-119129)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-29

Core IAM/IdP flaw enabling account takeover via OAuth 2.0 Device Authorization bypass, directly impacting Digital Identity infrastructure.

*Deep dive: `TIER_2_CVE-2026-119129.md`*

___________________________________


# **[CVE-2026-119283 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-119283)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-29

Core JWT/JWE processing library for identity providers; unauthenticated DoS directly threatens authentication and session management services in public-sector and enterprise digital identity stacks.

*Deep dive: `TIER_2_CVE-2026-119283.md`*

___________________________________


# **[CVE-2026-62374 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-62374)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-29

Directly impacts Digital Identity infrastructure by compromising SD-JWT verification, a core component of the EU Digital Identity Wallet and government verifiable credential systems.

*Deep dive: `TIER_2_CVE-2026-62374.md`*

___________________________________


# **[CVE-2026-114358 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-114358)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-29

Unauthenticated SQLi in an M2M platform deployed for smart city utilities and public transport telemetry, directly impacting Government and critical infrastructure resilience.

*Deep dive: `TIER_2_CVE-2026-114358.md`*

___________________________________


# **[CVE-2026-114488 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-114488)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-29

TIER 2 authentication bypass in JBoss/WildFly middleware impacts Red Hat SSO (Keycloak-based IdAM) and enterprise backends widely deployed across government, finance, and healthcare.

*Deep dive: `TIER_2_CVE-2026-114488.md`*

___________________________________


# **[CVE-2026-119049 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-119049)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-29

Digital Identity: Authorization bypass in a public temp-mail service enables theft of OTPs and verification codes, directly undermining identity assurance and 2FA flows.

*Deep dive: `TIER_2_CVE-2026-119049.md`*

___________________________________


# **[CVE-2026-119144 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-119144)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-29

SSTI in Frappe Framework enables RCE in enterprise ERP systems widely deployed for financial operations, payroll, and government citizen services.

*Deep dive: `TIER_2_CVE-2026-119144.md`*

___________________________________


# **[CVE-2026-42922 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-42922)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-29

TIER 2 unauthenticated RCE in FUXA SCADA/HMI platform impacts Government/Critical Infrastructure sectors (energy, water, transport) under national security oversight.

*Deep dive: `TIER_2_CVE-2026-42922.md`*

___________________________________


# **[CVE-2026-84295 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-84295)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-29

Unauthenticated credential theft in enterprise FTP infrastructure explicitly tied to regulated data exchanges and government procurement portals.

*Deep dive: `TIER_2_CVE-2026-84295.md`*

___________________________________


# **[CVE-2026-90868 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-90868)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-29

Critical RCE in enterprise FTP gateways widely deployed for Finance, Healthcare, and Government B2B/civic data pipelines.

*Deep dive: `TIER_2_CVE-2026-90868.md`*

___________________________________


# **[CVE-2026-93757 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-93757)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-29

Strong Digital Identity relevance due to SSO authentication bypass and account binding flaw in a widely deployed WordPress plugin used by public and regulated sectors.

*Deep dive: `TIER_2_CVE-2026-93757.md`*

___________________________________


# **[CVE-2026-66090 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-66090)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-29

Authenticated XXE/SSRF in openEQUELLA ePortfolio platforms widely deployed by public universities and government-funded educational institutions (Government sector).

*Deep dive: `TIER_2_CVE-2026-66090.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine