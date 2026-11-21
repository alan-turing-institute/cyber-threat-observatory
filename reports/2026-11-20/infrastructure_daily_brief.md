# **Infrastructure Daily Brief: 2026-11-20**

**Infrastructure Daily Report TLP:GREEN Alert Id: 68c9d34e 2026-11-21 22:49:26**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-129175 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-133705 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-55216 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-77326 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-129073 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-129177 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-131163 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-133872 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-133949 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-133968 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-14914 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-77309 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-77324 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-127027 (Tier 2)                                                         | 3.k      |
| Threats    | The hidden network: Inside the phishing infrastructure ecosystem ...             | 1.c      |
| Threats    | High volume phishing campaign uses Microsoft 365 outage lures to target ...      | 1.f      |
| Threats    | Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Se | 1.b      |
| Threats    | Inside an AI‑enabled device code phishing campaign | Microsoft Security Blog     | 1.e      |
| Threats    | Crafty Microsoft Teams Booking Flow Disguises Device Code Phishing | Huntress    | 1.b      |
| Threats    | Microsoft 365 device code phishing campaign bypasses password stealing | RL Blog | 1.b      |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US        | 1.b      |
| Threats    | CVE-2026-130235                                                                  | 1.b      |
| Threats    | CVE-2026-133659                                                                  | 1.b      |
| Threats    | CVE-2026-115342                                                                  | 1.b      |
| Threats    | CVE-2026-130151                                                                  | 1.b      |
| Threats    | CVE-2026-130179                                                                  | 1.b      |
| Threats    | CVE-2026-130236                                                                  | 1.b      |
| Threats    | CVE-2026-130234                                                                  | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[The hidden network: Inside the phishing infrastructure ecosystem ...](https://www.microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime/)**

**PIR: 1.c**

Source: ketch Published: 2026-11-20

Microsoft uncovered a Chinese-language cybercriminal ecosystem featuring interconnected phishing kit operators (Storm-2990) and an illicit marketplace (Storm-3119) selling tools for large-scale phishing. Collaborating with global law enforcement, Microsoft’s Digital Crimes Unit facilitated a major disruption of this infrastructure, offering critical insights for defenders monitoring underground tool distribution and phishing-as-a-service networks.

___________________________________


# **[High volume phishing campaign uses Microsoft 365 outage lures to target ...](https://www.microsoft.com/en-us/security/blog/2026/11/16/high-volume-phishing-campaign-uses-microsoft-365-outage-lures-target-multiple-industry-sectors-2/)**

**PIR: 1.f**

Source: ketch Published: 2026-11-20

Threat actors launched a coordinated, high-volume phishing campaign exploiting Microsoft 365 service-health notifications. By disguising malicious emails as legitimate outage alerts, attackers targeted organizations across multiple sectors. Infrastructure defenders should monitor for spoofed service-status domains and reinforce email authentication controls to mitigate this widespread credential-harvesting tactic.

___________________________________


# **[Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/)**

**PIR: 1.b**

Source: ketch Published: 2026-11-20

Microsoft researchers dissect the EvilTokens campaign, revealing the underlying mechanics of device code phishing that bypasses traditional credential theft. The analysis provides technical indicators, attacker infrastructure details, and defensive recommendations. Infrastructure teams should implement strict OAuth consent policies, monitor for suspicious device code approvals, and deploy token lifecycle management controls.

___________________________________


# **[Inside an AI‑enabled device code phishing campaign | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.e**

Source: ketch Published: 2026-11-20

This analysis details a sophisticated phishing campaign leveraging artificial intelligence to automate and personalize device code requests. By bypassing traditional password theft, attackers directly target OAuth authorization flows. Defenders must review conditional access policies, monitor for anomalous device code approvals, and deploy AI-aware detection rules to counter this evolving identity threat.

___________________________________


# **[Crafty Microsoft Teams Booking Flow Disguises Device Code Phishing | Huntress](https://www.huntress.com/blog/crafty-microsoft-teams-booking-flow-disguises-device-code-phishing)**

**PIR: 1.b**

Source: ketch Published: 2026-11-20

Huntress researchers uncover a novel phishing technique that disguises device code requests within legitimate-looking Microsoft Teams booking flows. This tactic exploits user trust in familiar collaboration tools to bypass security awareness. Infrastructure defenders should monitor Teams API abuse, validate booking flow integrations, and educate users on recognizing disguised authorization prompts.

___________________________________


# **[Microsoft 365 device code phishing campaign bypasses password stealing | RL Blog](https://www.reversinglabs.com/blog/device-code-phishing-campaign)**

**PIR: 1.b**

Source: ketch Published: 2026-11-20

ReversingLabs details a widespread Microsoft 365 phishing campaign that sidesteps password harvesting by exploiting device code authorization flows. The article provides actionable detection rules, infrastructure indicators, and configuration hardening steps. Defenders should audit M365 consent policies, restrict device code usage to approved applications, and enhance monitoring for anomalous authentication patterns.

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.b**

Source: ketch Published: 2026-11-20

Proofpoint examines how device code phishing has evolved into a primary method for identity takeover, circumventing multi-factor authentication and password-based defenses. The report outlines attacker tactics, infrastructure patterns, and mitigation strategies. IT defenders should prioritize monitoring OAuth consent grants and implementing device code approval workflows to secure enterprise identity perimeters.

___________________________________


# **[CVE-2026-130235](https://nvd.nist.gov/vuln/detail/CVE-2026-130235)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-19

In the Okta .NET SDK Abstractions library, outbound HTTP requests are not restricted to the configured Okta organization domain when processing certain URL formats. If a URL parameter is modified to specify an external host, the library may transmit the configured SSWS API token to that unintended destination.

___________________________________


# **[CVE-2026-133659](https://nvd.nist.gov/vuln/detail/CVE-2026-133659)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-20

Flowintel contains multiple SSO identity and organisation trust boundary violations that collectively allow account takeover, privilege escalation, and unauthorized access to private case data.

- Keycloak SSO accepted unverified email claims, and all SSO providers (Keycloak, Entra ID, SimpleSAML) could resolve a claimed email address to an existing account that was created via a different sign-in method, enabling cross-provider account collision and unauthorized access to another user's account

___________________________________


# **[CVE-2026-115342](https://nvd.nist.gov/vuln/detail/CVE-2026-115342)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-19

Argument injection in OpenVPN version 2.4.0 through 2.6.23 and 2.7_alpha1 through 2.7.8 on Windows allows local authenticated users to bypass interactive service option validation and add arbitrary configuration options via a crafted command line.

___________________________________


# **[CVE-2026-130151](https://nvd.nist.gov/vuln/detail/CVE-2026-130151)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-19

Okta Privileged Access (OPA) Gateway includes a version of the FreeRDP library affected by memory management issues in its smartcard redirection handling. When an RDP session is established meeting specific session criteria, command execution within the context of the local Gateway service account may be allowed.

___________________________________


# **[CVE-2026-130179](https://nvd.nist.gov/vuln/detail/CVE-2026-130179)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-19

The Okta .NET SDK Abstractions library systematically writes per-request authentication credentials to a shared HTTP client instance, rather than being isolated to individual outbound request objects. When using scoped child clients, a subsequent scoped request can overwrite the shared client configuration. Because the original parent client credential has not been restored, subsequent outbound requests may be transmitted using the newly written credential, which can result in subsequent actions

___________________________________


# **[CVE-2026-130236](https://nvd.nist.gov/vuln/detail/CVE-2026-130236)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-19

In the Auth0 Authorization Extension, request authentication handling can process claims from query parameters independently of header validation. Under specific preconditions, this may allow an authenticated tenant user to issue requests to the extension's administrative endpoints. Also, input handling during rule generation may permit modification of the tenant login rule published by the extension.

___________________________________


# **[CVE-2026-130234](https://nvd.nist.gov/vuln/detail/CVE-2026-130234)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-19

The Okta Swift Management SDK does not percent-encode forward slash (/) characters during path parameter interpolation. If an application supplies input containing relative path sequences (e.g., ../) to an SDK method, standard URL normalization may direct the outbound request to an alternative Okta Management API endpoint.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-129175 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-129175)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-20

Critical unauthenticated SQL injection in a U.S. Department of the Interior web portal, directly impacting federal land management and government digital infrastructure.

*Deep dive: `TIER_2_CVE-2026-129175.md`*

___________________________________


# **[CVE-2026-133705 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-133705)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-20

TIER 2 SAML open redirect in Hanko IdP enables full account takeover via token exfiltration, directly impacting Digital Identity and enterprise SSO infrastructure.

*Deep dive: `TIER_2_CVE-2026-133705.md`*

___________________________________


# **[CVE-2026-55216 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-55216)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-20

Core open-source IdAM platform vulnerability enabling full account takeover via unverified OAuth/Azure AD social connectors, directly impacting digital identity verification and session integrity.

*Deep dive: `TIER_2_CVE-2026-55216.md`*

___________________________________


# **[CVE-2026-77326 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-77326)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-20

Impacts Government and General Infrastructure by exposing internet-facing public GIS/WMS endpoints (land registries, emergency routing, census data) to unauthenticated DoS and potential RCE.

*Deep dive: `TIER_2_CVE-2026-77326.md`*

___________________________________


# **[CVE-2026-129073 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-129073)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-20

Directly impacts Digital Identity infrastructure by bypassing OTP/2FA controls on public-facing WordPress deployments, enabling unauthorized account takeover.

*Deep dive: `TIER_2_CVE-2026-129073.md`*

___________________________________


# **[CVE-2026-129177 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-129177)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-20

Unauthenticated account creation in a U.S. Department of the Interior application directly impacts Government sector digital infrastructure and data integrity.

*Deep dive: `TIER_2_CVE-2026-129177.md`*

___________________________________


# **[CVE-2026-131163 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-131163)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-20

Finance sector relevance: stored XSS in a payment plugin enables API redirection and session takeover, risking interception of financial transaction data.

*Deep dive: `TIER_2_CVE-2026-131163.md`*

___________________________________


# **[CVE-2026-133872 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-133872)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-20

Impacts self-hosted credential stores and JWT authentication endpoints, enabling brute-force account takeover in Digital Identity infrastructure.

*Deep dive: `TIER_2_CVE-2026-133872.md`*

___________________________________


# **[CVE-2026-133949 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-133949)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-20

Foundational Python package manager vulnerability enabling supply chain compromise via MitM, impacting CI/CD and server-side deployments across all regulated sectors.

*Deep dive: `TIER_2_CVE-2026-133949.md`*

___________________________________


# **[CVE-2026-133968 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-133968)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-20

Healthcare sector relevance: medical imaging AI platform deployed on clinical/research networks, risking patient data privacy and workflow disruption via unauthenticated RCE.

*Deep dive: `TIER_2_CVE-2026-133968.md`*

___________________________________


# **[CVE-2026-14914 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-14914)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-20

Unauthenticated RCE in enterprise contact center software widely deployed by government, finance, and healthcare sectors for public-facing service operations.

*Deep dive: `TIER_2_CVE-2026-14914.md`*

___________________________________


# **[CVE-2026-77309 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-77309)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-20

Unauthenticated RCE in NASA's AIT-GUI mission operations framework directly impacts government space and aerospace critical infrastructure.

*Deep dive: `TIER_2_CVE-2026-77309.md`*

___________________________________


# **[CVE-2026-77324 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-77324)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-20

Unauthenticated DoS in MapServer, a foundational open-source GIS platform widely deployed by government agencies for national Spatial Data Infrastructures and public mapping portals.

*Deep dive: `TIER_2_CVE-2026-77324.md`*

___________________________________


# **[CVE-2026-127027 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-127027)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-20

Unauthenticated RCE in a widely deployed self-hosted mail server impacts foundational email infrastructure used by enterprises and government agencies.

*Deep dive: `TIER_2_CVE-2026-127027.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine