# **Infrastructure Daily Brief: 2026-11-09**

**Infrastructure Daily Report TLP:GREEN Alert Id: 6d2acb7d 2026-11-10 02:04:28**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-124554 (Tier 2)                                                         | 3.k      |
| Threats    | The Infrastructure Behind Phishing | Zerot Security Research                     | 1.e      |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover                        | 1.d      |
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.f      |
| Threats    | Joint advisory: state-sponsored spear-phishing campaigns targeting critical infr | 1.h      |
| Threats    | GhostCode: Dissecting a Novel Device Code Phishing Kit                           | 1.d      |
| Threats    | Device Code Phishing: Turning a Convenience Feature Into an MFA Bypass           | 1.d      |
| Threats    | Foreign Threat Actor Conducting Large-Scale Spearphishing Campaign with RDP Atta | 1.i      |
| Threats    | 5,000 Election Phishing Domains Pre-Stage US Midterm Attacks                     | 1.g      |
| Threats    | CVE-2026-123551                                                                  | 1.b      |
| Threats    | CVE-2026-123550                                                                  | 1.b      |
| Threats    | CVE-2026-123549                                                                  | 1.b      |
| Threats    | CVE-2026-8639                                                                    | 1.b      |
| Threats    | CVE-2026-123542                                                                  | 1.b      |
| Threats    | CVE-2026-123538                                                                  | 1.b      |
| Threats    | CVE-2026-123545                                                                  | 1.b      |
| Threats    | CVE-2026-123553                                                                  | 1.b      |
| Threats    | CVE-2026-123544                                                                  | 1.b      |
| Threats    | CVE-2026-123552                                                                  | 1.b      |
| Threats    | CVE-2026-123546                                                                  | 1.b      |
| Threats    | CVE-2026-121825                                                                  | 1.b      |
| Threats    | CVE-2026-123541                                                                  | 1.b      |
| Threats    | CVE-2026-123537                                                                  | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[The Infrastructure Behind Phishing | Zerot Security Research](https://research.zerot-security.com/the-infrastructure-behind-phishing/)**

**PIR: 1.e**

Source: ketch Published: 2026-11-09

Analyzes how cloud accounts, commercial phishing software, and shared technical services underpin modern phishing campaigns. Details Microsoft's October 2026 disruption efforts, offering defenders actionable insights on identifying and blocking shared malicious infrastructure.

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover](https://proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.d**

Source: ketch Published: 2026-11-09

Explores how device code phishing has evolved into a primary identity takeover vector. Highlights techniques used to bypass multi-factor authentication and provides mitigation strategies for enterprise identity providers and endpoint defenders.

___________________________________


# **[Inside an AI‑enabled device code phishing campaign](https://microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026)**

**PIR: 1.f**

Source: ketch Published: 2026-11-09

Microsoft researchers dissect an AI-driven device code phishing campaign from April 2026. Demonstrates how generative AI automates credential harvesting and MFA bypass, urging defenders to deploy behavioral analytics and conditional access policies.

___________________________________


# **[Joint advisory: state-sponsored spear-phishing campaigns targeting critical infrastructure - SUVAT](https://suvat.uk/blog/five-eyes-advisory.html)**

**PIR: 1.h**

Source: ketch Published: 2026-11-09

Five Eyes intelligence sharing outlines coordinated spear-phishing operations against critical infrastructure. Details TTPs, malicious payloads, and defensive playbooks for network segmentation, email filtering, and incident response coordination.

___________________________________


# **[GhostCode: Dissecting a Novel Device Code Phishing Kit](https://esentire.com/blog/ghostcode-dissecting-a-novel-device-code-phishing-kit)**

**PIR: 1.d**

Source: ketch Published: 2026-11-09

eSentire reverse-engineers the GhostCode phishing kit, revealing novel techniques for intercepting device codes and session tokens. Offers infrastructure defenders IOCs, YARA rules, and deployment guidance to block kit-based identity theft.

___________________________________


# **[Device Code Phishing: Turning a Convenience Feature Into an MFA Bypass](https://trendmicro.com/en_us/research/26/g/device-code-phishing.html)**

**PIR: 1.d**

Source: ketch Published: 2026-11-09

Trend Micro research details how legitimate device code authentication flows are weaponized to circumvent MFA. Provides technical breakdowns of phishing kits, network indicators, and architectural controls to harden identity verification processes.

___________________________________


# **[Foreign Threat Actor Conducting Large-Scale Spearphishing Campaign with RDP Attachments | CISA](https://www.cisa.gov/news-events/alerts/2024/10/31/foreign-threat-actor-conducting-large-scale-spearphishing-campaign-rdp-attachments)**

**PIR: 1.i**

Source: ketch Published: 2026-11-09

CISA alerts on widespread spear-phishing using malicious RDP attachments to establish remote access. Provides detection rules, email gateway configurations, and endpoint hardening steps to prevent unauthorized system access.

___________________________________


# **[5,000 Election Phishing Domains Pre-Stage US Midterm Attacks](https://dailysecurityreview.com/cyber-security/5000-election-phishing-domains-pre-stage-us-midterm-attacks/)**

**PIR: 1.g**

Source: ketch Published: 2026-11-09

Over 5,000 election-themed domains registered between April and May 2026 form phishing infrastructure targeting voters, campaign staff, and election workers. Defenders should monitor domain registration patterns and implement DNS sinkholing for known malicious TLDs.

___________________________________


# **[CVE-2026-123551](https://nvd.nist.gov/vuln/detail/CVE-2026-123551)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-08

OpenAM from 14.0.0 before 16.1.4 contains an information disclosure vulnerability that allows unauthenticated attackers to read live session tokens from the notification WebSocket. Attackers can bypass the agent-only check through an unvalidated internal forward on legacy Liberty ID-FF endpoints, collecting iPlanetDirectoryPro tokens to hijack user and administrator sessions.

___________________________________


# **[CVE-2026-123550](https://nvd.nist.gov/vuln/detail/CVE-2026-123550)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-08

OpenAM before 16.1.4 contains an authentication bypass vulnerability in its SAML v2.0 service provider that accepts unsigned assertions on the ECP (PAOS) and HTTP-Artifact bindings when WantAssertionsSigned is false. Unauthenticated remote attackers can submit forged assertions to obtain sessions as any mapped user, including administrators, and hijack single sign-on to dependent applications.

___________________________________


# **[CVE-2026-123549](https://nvd.nist.gov/vuln/detail/CVE-2026-123549)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-08

OpenAM before 16.1.4 fails to enforce the Valid Creation Attributes list during self-registration, allowing anonymous attackers to set restricted attributes including group membership. Attackers can register through the legacy self-service REST endpoint or User Self-Service flow to join administrative groups and gain full administrative control of OpenAM.

___________________________________


# **[CVE-2026-8639](https://nvd.nist.gov/vuln/detail/CVE-2026-8639)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-08

IBM Security Verify Directory 10.0.0 through 10.0.4 and IBM Verify Directory 11.0.0 is vulnerable to session fixation. An attacker can establish a session and, after the victim authenticates, hijack the authenticated session to gain unauthorized access to the directory management console.

___________________________________


# **[CVE-2026-123542](https://nvd.nist.gov/vuln/detail/CVE-2026-123542)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-08

OpenAM before 16.1.4 fails to enforce PKCE in the OAuth 2.0 device authorization flow, never validating the code verifier when device codes are exchanged for tokens. Attackers who obtain an approved device code from client logs or shared device storage can redeem it for access and ID tokens to impersonate the user.

___________________________________


# **[CVE-2026-123538](https://nvd.nist.gov/vuln/detail/CVE-2026-123538)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-08

OpenAM before 16.1.4 does not verify that a signed SAML 1.x assertion or response was signed by the partner named as its issuer, accepting a signature from any certificate in OpenAM's keystore. An attacker holding such a private key, such as a trusted SAML 1.x partner, can forge assertions claiming another partner's issuer and sign in as that partner's users, including privileged ones.

___________________________________


# **[CVE-2026-123545](https://nvd.nist.gov/vuln/detail/CVE-2026-123545)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-08

OpenAM from 14.5.1 before 16.1.4 contains a cross-site request forgery vulnerability in the OAuth 2.0 device authorization flow that allows attackers to approve device codes when consent is skipped for implied-consent clients. Attackers can start a device authorization and lure a logged-in user to a crafted page, obtaining access and ID tokens to call APIs as that user.

___________________________________


# **[CVE-2026-123553](https://nvd.nist.gov/vuln/detail/CVE-2026-123553)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-08

OpenAM before 16.1.4 ships built-in identities in the Top Level Realm (demo, anonymous, wsc, wsp, SecurityTokenService and agentAuth) with passwords that are identical on every installation, publicly known, and able to authenticate. Unauthenticated remote attackers can log in as these identities to obtain authenticated sessions, and the agent identities can read the configuration of other agent profiles.

___________________________________


# **[CVE-2026-123544](https://nvd.nist.gov/vuln/detail/CVE-2026-123544)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-08

OpenAM before 16.1.4 and its client SDK fail to sufficiently validate responses on the internal server-to-server SOAP channel, allowing network-positioned attackers to affect integrity and availability. Attackers who intercept unencrypted traffic or control a site server can crash receiving processes, tamper with writable files, and possibly execute code.

___________________________________


# **[CVE-2026-123552](https://nvd.nist.gov/vuln/detail/CVE-2026-123552)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-08

OpenAM before 16.1.4 contains a server-side request forgery vulnerability in certificate CRL checking that fetches CRLs from the distribution point named in a presented certificate without restricting the destination or verifying the downloaded CRL's signature. Attackers holding a trusted-CA-chained certificate can make OpenAM request internal hosts, capture configured CRL update credentials, overwrite stored revocation data to block certificate authentication for that CA, and tie up authenticat

___________________________________


# **[CVE-2026-123546](https://nvd.nist.gov/vuln/detail/CVE-2026-123546)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-08

OpenAM before 16.1.4 contains an open redirect and cross-site scripting vulnerability that allows remote attackers to control post-login and logout destinations via the goto and gotoOnFail parameters. Attackers can craft OpenAM login or logout links that redirect victims to phishing sites or run script in the XUI to steal session cookies.

___________________________________


# **[CVE-2026-121825](https://nvd.nist.gov/vuln/detail/CVE-2026-121825)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-09

OpenAM (OpenAM Consortium Edition) 14.0.5 and earlier contains an open redirect vulnerability (CWE-601) in the Liberty ID-FF service provider single sign-on flow. The goto parameter of the /preLogin endpoint is stored as the RelayState of the Liberty ID-FF authentication request without validation, and after the user completes single sign-on at the identity provider, the assertion consumer service redirects the browser to that value. A remote unauthenticated attacker can induce a user to access 

___________________________________


# **[CVE-2026-123541](https://nvd.nist.gov/vuln/detail/CVE-2026-123541)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-08

OpenAM before 16.1.4 contains an open redirect vulnerability that allows remote attackers to redirect users after SAML 1.x single sign-on by exploiting loose trusted-partner destination matching. Attackers can craft links to /SAMLAwareServlet or /SAMLPOSTProfileServlet with a destination host resembling a trusted partner to send authenticated users to attacker-controlled phishing sites.

___________________________________


# **[CVE-2026-123537](https://nvd.nist.gov/vuln/detail/CVE-2026-123537)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-08

OpenAM before 16.1.4 contains a server-side request forgery vulnerability that allows parties registering UMA resource sets to trigger internal requests through unvalidated scope description URLs. Attackers can register resource sets with scope URLs pointing to internal hosts or cloud metadata endpoints, which OpenAM fetches when sending pending-request notification emails, enabling internal network probing.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-124554 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-124554)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-09

Unauthenticated SQLi in JeecgBoot low-code platform, widely deployed in Chinese government and state-owned enterprise digital transformation projects.

*Deep dive: `TIER_2_CVE-2026-124554.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine