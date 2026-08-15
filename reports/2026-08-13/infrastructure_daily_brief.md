# **Infrastructure Daily Brief: 2026-08-13**

**Infrastructure Daily Report TLP:GREEN Alert Id: f76a6312 2026-08-15 01:57:48**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                          | PIR(s)   |
|------------|---------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-17206 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-49478 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-73302 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-73420 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-17101 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-17197 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-17220 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-18164 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-59109 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-61967 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-61979 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-73188 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-73421 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-73570 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-14456 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-48702 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-53793 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-73645 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-73665 (Tier 2)                                                         | 3.k      |
| Threats    | Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale | Microsoft | 1.b      |
| Threats    | Inside Kali365, a Device Code Phishing Ecosystem | Huntress                     | 1.c      |
| Threats    | New widespread EvilTokens kit: device code phishing as-a-service                | 1.d      |
| Threats    | Inside an AI‑enabled device code phishing campaign                              | 1.e      |
| Threats    | Access granted: phishing with device code authorization for account ...         | 1.c      |
| Threats    | Tycoon 2FA Takedown | Cloudflare                                                | 1.g      |
| Threats    | IronToll: Global Government-Impersonation PhaaS | PhishEye                      | 1.d      |
| Threats    | Device Code Phishing Hits 340+ Microsoft 365 Orgs Across Five Countries ...     | 1.c      |
| Threats    | CVE-2026-28008                                                                  | 1.b      |
| Threats    | CVE-2026-26035                                                                  | 1.b      |
| Threats    | CVE-2026-73644                                                                  | 1.b      |
| Threats    | CVE-2026-14525                                                                  | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale/)**

**PIR: 1.b**

Source: ketch Published: 2026-08-13

Microsoft Security researchers dissect the Tycoon2FA adversary-in-the-middle (AiTM) phishing kit, detailing its infrastructure, proxy mechanisms, and scale. The report provides actionable indicators of compromise, network-level detection strategies, and mitigation guidance for identity and infrastructure defenders managing cloud authentication flows.

___________________________________


# **[Inside Kali365, a Device Code Phishing Ecosystem | Huntress](https://www.huntress.com/blog/kali365-device-code-phishing-kit)**

**PIR: 1.c**

Source: ketch Published: 2026-08-13

Huntress analyzes the Kali365 ecosystem, a sophisticated device code phishing framework that abuses OAuth 2.0 flows to bypass MFA. The breakdown covers infrastructure patterns, token persistence techniques, and defensive controls for securing identity providers and monitoring anomalous authorization requests.

___________________________________


# **[New widespread EvilTokens kit: device code phishing as-a-service](https://www.sekoia.com/blog/new-widespread-eviltokens-kit-device-code-phishing-as-a-service-part-1)**

**PIR: 1.d**

Source: ketch Published: 2026-08-13

Sekoia.io reveals EvilTokens, a commercial device code phishing-as-a-service platform enabling low-skill actors to execute OAuth abuse campaigns. The analysis highlights infrastructure hosting patterns, automated token harvesting, and recommended identity governance policies to limit lateral movement post-compromise.

___________________________________


# **[Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.e**

Source: ketch Published: 2026-08-13

Microsoft documents a campaign leveraging AI to automate device code phishing, dynamically generating authentication prompts and scaling account compromises. Defenders gain insights into behavioral anomalies, AI-driven prompt engineering, and enhanced monitoring rules for OAuth consent and device authorization endpoints.

___________________________________


# **[Access granted: phishing with device code authorization for account ...](https://www.proofpoint.com/us/blog/threat-insight/access-granted-phishing-device-code-authorization-account-takeover)**

**PIR: 1.c**

Source: ketch Published: 2026-08-13

Proofpoint tracks multiple threat clusters exploiting the OAuth 2.0 device authorization grant flow to hijack M365 accounts. The analysis outlines infrastructure indicators, consent phishing patterns, and identity protection recommendations, including conditional access policies and token lifecycle management for enterprise environments.

___________________________________


# **[Tycoon 2FA Takedown | Cloudflare](https://www.cloudflare.com/threat-intelligence/research/report/tycoon-2fa-takedown/)**

**PIR: 1.g**

Source: ketch Published: 2026-08-13

Cloudflare details the infrastructure takedown of the Tycoon2FA phishing network, mapping domain registration patterns, CDN abuse, and proxy routing. The report offers network defenders actionable DNS and TLS telemetry, sinkholing strategies, and upstream filtering techniques to disrupt AiTM campaigns at the infrastructure layer.

___________________________________


# **[IronToll: Global Government-Impersonation PhaaS | PhishEye](https://phisheye.com/blog/irontoll-iron-man-phaas-campaign)**

**PIR: 1.d**

Source: ketch Published: 2026-08-13

PhishEye exposes IronToll, a phishing-as-a-service operation impersonating government agencies to harvest credentials and deploy malicious infrastructure. The report details campaign architecture, hosting infrastructure, and defensive playbooks for filtering impersonation domains and hardening email gateway rules.

___________________________________


# **[Device Code Phishing Hits 340+ Microsoft 365 Orgs Across Five Countries ...](https://thehackernews.com/2026/03/device-code-phishing-hits-340-microsoft.html)**

**PIR: 1.c**

Source: ketch Published: 2026-08-13

An overview of a widespread device code phishing wave impacting over 340 Microsoft 365 organizations. The article summarizes attack vectors, persistent token abuse, and high-level mitigation steps, providing infrastructure teams with context on campaign scale and recommended identity monitoring enhancements.

___________________________________


# **[CVE-2026-28008](https://nvd.nist.gov/vuln/detail/CVE-2026-28008)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-13

Unauthenticated Broken Authentication in OAuth Single Sign On – SSO (OAuth Client) <= 7.0.0 versions.

___________________________________


# **[CVE-2026-26035](https://nvd.nist.gov/vuln/detail/CVE-2026-26035)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-12

An Improper Authentication vulnerability [CWE-287] vulnerability in Fortinet FortiWeb 8.0.0 through 8.0.2, FortiWeb 7.6.0 through 7.6.6, FortiWeb 7.4.0 through 7.4.11, FortiWeb 7.2.0 through 7.2.12, FortiWeb 7.0.0 through 7.0.12 may allow a remote unauthenticated attacker to login into the Fortiweb GUI/CLI with a random username and password

___________________________________


# **[CVE-2026-73644](https://nvd.nist.gov/vuln/detail/CVE-2026-73644)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-13

OpenDJ is an LDAPv3 compliant directory service. Prior to 5.1.2, the SASL PLAIN authorization identity path in opendj-server-legacy/src/main/java/org/opends/server/extensions/PlainSASLMechanismHandler.java checked the PROXIED_AUTH privilege but did not evaluate the mayProxy proxy ACI scope when an authzid resolved to a different user. Both dn: and u: or bare authzid forms could therefore let an authenticated account holding PROXIED_AUTH assume any resolvable non-root identity outside the identit

___________________________________


# **[CVE-2026-14525](https://nvd.nist.gov/vuln/detail/CVE-2026-14525)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-13

IBM WebSphere Application Server - Liberty 17.0.0.3 through 26.0.0.8 IBM WebSphere Application Server Liberty is vulnerable to an authentication bypass when the rtcomm-1.0 or rtcommGateway-1.0 feature is enabled.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-17206 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-17206)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-13

TIER 2 RCE in IBM i host servers directly impacts Finance and Government sectors, where the OS underpins core banking systems, payment processing, and public sector transaction infrastructure.

*Deep dive: `TIER_2_CVE-2026-17206.md`*

___________________________________


# **[CVE-2026-49478 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-49478)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-13

Core Digital Identity infrastructure vulnerability compromising OIDC discovery, JWKS verification, and Kubernetes token handling in the Sigstore/Fulcio code-signing CA.

*Deep dive: `TIER_2_CVE-2026-49478.md`*

___________________________________


# **[CVE-2026-73302 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-73302)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-13

Critical OIDC SSO authentication bypass enabling full admin account takeover, directly impacting Digital Identity infrastructure and low-code platforms deployed across government, healthcare, and finance.

*Deep dive: `TIER_2_CVE-2026-73302.md`*

___________________________________


# **[CVE-2026-73420 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-73420)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-13

Critical authentication bypass in NextAuth.js enables full account takeover via magic-link misrouting, directly impacting Digital Identity and passwordless access systems.

*Deep dive: `TIER_2_CVE-2026-73420.md`*

___________________________________


# **[CVE-2026-17101 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-17101)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-13

TIER 2 remote code execution via authentication bypass in IBM i Navigator, a foundational OS console explicitly underpinning Finance, Government, and Healthcare workloads.

*Deep dive: `TIER_2_CVE-2026-17101.md`*

___________________________________


# **[CVE-2026-17197 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-17197)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-13

Remote authentication bypass in IBM i OS directly threatens core banking, hospital records, and government civic databases hosted on this foundational enterprise infrastructure.

*Deep dive: `TIER_2_CVE-2026-17197.md`*

___________________________________


# **[CVE-2026-17220 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-17220)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-13

Core enterprise OS (IBM i) widely deployed in Finance, Government, and Healthcare for legacy transaction processing; remote buffer overflow impacts authentication metadata and critical network services.

*Deep dive: `TIER_2_CVE-2026-17220.md`*

___________________________________


# **[CVE-2026-18164 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-18164)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-13

Healthcare sector: hard-coded credentials in an FDA-cleared brain stimulation device allow unauthenticated manipulation of therapy parameters, posing direct patient safety and clinical data integrity risks.

*Deep dive: `TIER_2_CVE-2026-18164.md`*

___________________________________


# **[CVE-2026-59109 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-59109)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-13

Finance sector: SQL injection in enterprise accounting software via PEPPOL e-invoices threatens financial integrity and B2B transaction security.

*Deep dive: `TIER_2_CVE-2026-59109.md`*

___________________________________


# **[CVE-2026-61967 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-61967)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-13

Unauthenticated privilege escalation in a widely deployed OTP/MFA WordPress plugin directly impacts Digital Identity infrastructure and public-facing access controls.

*Deep dive: `TIER_2_CVE-2026-61967.md`*

___________________________________


# **[CVE-2026-61979 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-61979)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-13

Unauthenticated privilege escalation in a widely deployed SAML SSO plugin directly compromises federated identity and access management workflows.

*Deep dive: `TIER_2_CVE-2026-61979.md`*

___________________________________


# **[CVE-2026-73188 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-73188)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-13

Unauthenticated exposure of protected health information (PHI) in a public-facing clinic management plugin, directly impacting healthcare data infrastructure and regulatory compliance.

*Deep dive: `TIER_2_CVE-2026-73188.md`*

___________________________________


# **[CVE-2026-73421 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-73421)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-13

Critical authentication bypass in NextAuth.js directly impacts Digital Identity by failing open on misconfigurations, exposing protected routes and user sessions.

*Deep dive: `TIER_2_CVE-2026-73421.md`*

___________________________________


# **[CVE-2026-73570 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-73570)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-13

Unauthenticated RCE in Zimbra Collaboration Suite impacts government and enterprise digital identity infrastructure, compromising authentication, account management, and sovereign email services.

*Deep dive: `TIER_2_CVE-2026-73570.md`*

___________________________________


# **[CVE-2026-14456 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-14456)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-13

Foundational cryptographic library underpinning secure communications across all DPI sectors; unauthenticated QUIC DoS risks availability of public-facing identity, finance, and government services.

*Deep dive: `TIER_2_CVE-2026-14456.md`*

___________________________________


# **[CVE-2026-48702 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-48702)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-13

Core software supply chain transparency log (Sigstore/Rekor) disruption halts artifact signing and verification, degrading digital trust infrastructure for regulated and public-sector CI/CD pipelines.

*Deep dive: `TIER_2_CVE-2026-48702.md`*

___________________________________


# **[CVE-2026-53793 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-53793)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-13

General infrastructure utility (rsync) critical for backup and data synchronization in government and financial systems; chroot escape breaks data integrity boundaries.

*Deep dive: `TIER_2_CVE-2026-53793.md`*

___________________________________


# **[CVE-2026-73645 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-73645)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-13

Finance sector relevance due to smart contract token wrapping and transaction integrity risks in DeFi infrastructure, though mitigated by extreme volume thresholds.

*Deep dive: `TIER_2_CVE-2026-73645.md`*

___________________________________


# **[CVE-2026-73665 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-73665)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-13

TIER 2 unauthenticated RCE in FreePBX UCP, a VoIP/PBX platform explicitly tied to enterprise and public-sector communications infrastructure.

*Deep dive: `TIER_2_CVE-2026-73665.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine