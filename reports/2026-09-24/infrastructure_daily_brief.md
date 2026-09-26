# **Infrastructure Daily Brief: 2026-09-24**

**Infrastructure Daily Report TLP:GREEN Alert Id: 6f42d5ae 2026-09-26 02:25:50**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-56739 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-63203 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-85056 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-85057 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-88907 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-91187 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-94606 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-94611 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-94612 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-94613 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-13016 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-56744 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-86858 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-86859 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-86860 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-93782 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-97404 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-57178 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-78312 (Tier 2)                                                          | 3.k      |
| Threats    | Microsoft 365: Block Device Code Flow Against GhostCode                          | 1.d      |
| Threats    | Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA      | 1.a      |
| Threats    | AI-Generated Lures Behind Microsoft Cloud Account Takeovers                      | 1.c      |
| Threats    | AI-Enabled Device Code Phishing Campaign Abuses Device Code Sign-In Flow         | 1.g      |
| Threats    | Device Code Phishing: The MFA Bypass Without a Fake Login                        | 1.d.2    |
| Threats    | Tycoon2FA Returns: PhaaS Platform Survives Law Enforcement Disruption            | 1.b      |
| Threats    | EvilTokens made phishing-as-a-service look easy. Then it got taken down          | 1.f      |
| Threats    | Microsoft Warns of EvilTokens AI Phishing Service Hijacking Thousands of Account | 1.e      |
| Threats    | CVE-2026-94609                                                                   | 1.b      |
| Threats    | CVE-2026-97846                                                                   | 1.b      |
| Threats    | CVE-2026-96445                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Microsoft 365: Block Device Code Flow Against GhostCode](https://windowsforum.com/news/microsoft-365-block-device-code-flow-against-ghostcode.444973?amp=1)**

**PIR: 1.d**

Source: ketch Published: 2026-09-24

Microsoft recommends disabling the device code flow in Microsoft 365 to counter GhostCode, a threat actor leveraging OAuth 2.0 device authorization grants to bypass MFA. Attackers redirect authentication to legitimate desktop or mobile apps, capturing valid tokens. Infrastructure administrators should restrict device code flow usage, implement token lifetime policies, and monitor for suspicious app registrations.

___________________________________


# **[Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA](https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns)**

**PIR: 1.a**

Source: ketch Published: 2026-09-24

Attackers increasingly leverage serverless functions, containerized environments, and ephemeral cloud resources to host phishing infrastructure, evading traditional perimeter defenses. This report details TTPs for cloud-native abuse, including automated resource provisioning and DNS tunneling. Defenders must implement cloud workload protection platforms, enforce strict IAM policies, and monitor for anomalous resource creation patterns to disrupt these campaigns before they scale.

___________________________________


# **[AI-Generated Lures Behind Microsoft Cloud Account Takeovers](https://labs.cloudsecurityalliance.org/research/csa-research-note-genai-passkey-phishing-msft-20260914-csa-s)**

**PIR: 1.c**

Source: ketch Published: 2026-09-24

Generative AI is now crafting highly personalized phishing lures that successfully bypass traditional email security gateways, leading to widespread Microsoft cloud account takeovers. The campaign exploits AI-generated passkey prompts and contextual social engineering. Defenders must deploy AI-aware content inspection, enforce conditional access policies, and monitor for anomalous authentication patterns to mitigate identity compromise.

___________________________________


# **[AI-Enabled Device Code Phishing Campaign Abuses Device Code Sign-In Flow](https://captechgroup.com/threat-intelligence-center/ai-enabled-device-code-phishing-campaign-abuses-de-81a334)**

**PIR: 1.g**

Source: ketch Published: 2026-09-24

A new campaign abuses the OAuth 2.0 device code sign-in flow using AI-generated prompts that perfectly mimic Microsoft authentication interfaces. Attackers exploit the flow’s lack of traditional web login pages to capture valid tokens. Infrastructure teams must restrict device code flow permissions, implement application allowlisting, and deploy behavioral analytics to detect automated authentication requests.

___________________________________


# **[Device Code Phishing: The MFA Bypass Without a Fake Login](https://securityboulevard.com/2026/09/device-code-phishing-the-mfa-bypass-without-a-fake-login)**

**PIR: 1.d.2**

Source: ketch Published: 2026-09-24

Device code phishing enables attackers to bypass MFA without deploying fake login pages by leveraging legitimate OAuth 2.0 device authorization grants. The technique redirects users to authenticate via trusted apps, capturing session tokens. Defenders should disable unnecessary device code flows, enforce phishing-resistant MFA, and monitor authentication logs for anomalous device code usage patterns.

___________________________________


# **[Tycoon2FA Returns: PhaaS Platform Survives Law Enforcement Disruption](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/03/CSA_research_note_Tycoon2FA-PhaaS-resurrection-MaaS-resilience-20260326-csa-styled.pdf)**

**PIR: 1.b**

Source: ketch Published: 2026-09-24

Following law enforcement disruption, the Tycoon2FA PhaaS platform rapidly migrated to alternative cloud providers, demonstrating remarkable infrastructure resilience. The analysis covers criminal MaaS adaptation, domain generation algorithms, and payment obfuscation. Infrastructure teams should prioritize continuous threat hunting, implement automated takedown workflows, and monitor for infrastructure reuse patterns to counter persistent PhaaS ecosystems.

___________________________________


# **[EvilTokens made phishing-as-a-service look easy. Then it got taken down](https://securityaffairs.com/199593/cyber-crime/eviltokens-made-phishing-as-a-service-look-easy-then-it-got-taken-down.html)**

**PIR: 1.f**

Source: ketch Published: 2026-09-24

EvilTokens streamlined phishing-as-a-service by offering pre-built token-stealing campaigns, significantly lowering the barrier for credential harvesting. Following its takedown, threat actors rapidly forked the infrastructure. Defenders must focus on session token lifecycle management, implement strict conditional access rules, and monitor for anomalous token issuance to prevent account takeover.

___________________________________


# **[Microsoft Warns of EvilTokens AI Phishing Service Hijacking Thousands of Accounts](https://gbhackers.com/eviltokens-ai-phishing/amp)**

**PIR: 1.e**

Source: ketch Published: 2026-09-24

Microsoft warns that EvilTokens leverages AI automation to hijack thousands of enterprise accounts through sophisticated phishing campaigns. The service combines machine learning-driven lure generation with scalable infrastructure. IT defenders should prioritize identity protection solutions, enforce multi-factor authentication with phishing-resistant methods, and conduct regular access reviews to detect compromised credentials.

___________________________________


# **[CVE-2026-94609](https://nvd.nist.gov/vuln/detail/CVE-2026-94609)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-24

authentik is an open-source identity provider. Prior to 2026.2.7, 2026.5.7, and 2026.8.2, an account with delegated permission to manage a group, group membership, or a user can grant superuser status to an account or assign an existing role to a group without holding the permissions that gate those privileges. Group hierarchy checks do not consistently account for superuser status inherited from ancestor groups, and role assignment to a group lacks the required authorization check. Only deploym

___________________________________


# **[CVE-2026-97846](https://nvd.nist.gov/vuln/detail/CVE-2026-97846)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-25

Keycloak provides a feature called mTLS holder-of-key binding which ensures that a token can only be used by the client that originally requested it by binding it to their digital certificate. A flaw was discovered where the new Standard Token Exchange V2 feature does not check for this certificate. This allows an attacker with stolen client credentials to obtain a standard, unrestricted token that bypasses these security protections.

___________________________________


# **[CVE-2026-96445](https://nvd.nist.gov/vuln/detail/CVE-2026-96445)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-23

A flaw was found in the Conditional OTP authenticator of Keycloak, an identity and access management solution. The issue occurs when the system evaluates specific HTTP headers to determine if a one-time password (OTP) should be skipped, but fails to verify if those headers came from a trusted source. This could allow an attacker who already has a user's password to bypass the second-factor authentication by providing a specially crafted header in their request.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-56739 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-56739)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-24

Directly impacts Digital Identity infrastructure via SSRF in OAuth2/OIDC connectors and webhooks, risking token leakage and cloud metadata theft in public-facing IdP deployments.

*Deep dive: `TIER_2_CVE-2026-56739.md`*

___________________________________


# **[CVE-2026-63203 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-63203)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-24

Digital Identity: Bypasses OAuth scope enforcement in open-source IdPs, exposing federated SSO tokens and enabling lateral movement to upstream identity providers.

*Deep dive: `TIER_2_CVE-2026-63203.md`*

___________________________________


# **[CVE-2026-85056 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-85056)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-24

Digital Identity sector: directly impacts open-source IdPs (ZITADEL) used in regulated/public infrastructure, enabling MFA bypass via OIDC/SAML session reuse.

*Deep dive: `TIER_2_CVE-2026-85056.md`*

___________________________________


# **[CVE-2026-85057 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-85057)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-24

Digital Identity sector: Compromises core IdP/SSO infrastructure (ZITADEL), breaking multi-tenant isolation and exposing authentication credentials.

*Deep dive: `TIER_2_CVE-2026-85057.md`*

___________________________________


# **[CVE-2026-88907 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-88907)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-24

Authentication bypass in Turkey's national academic SSO (Yetkim) integration undermines Digital Identity and Government/public research infrastructure trust.

*Deep dive: `TIER_2_CVE-2026-88907.md`*

___________________________________


# **[CVE-2026-91187 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-91187)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-24

Critical JWT signature bypass in a Cloudflare Zero Trust integration library, directly compromising authentication and identity verification for public-facing digital services.

*Deep dive: `TIER_2_CVE-2026-91187.md`*

___________________________________


# **[CVE-2026-94606 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-94606)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-24

Directly impacts Digital Identity infrastructure by enabling MFA hijacking and full account takeover in the authentik open-source IdP/SSO gateway.

*Deep dive: `TIER_2_CVE-2026-94606.md`*

___________________________________


# **[CVE-2026-94611 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-94611)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-24

Core open-source IdAM/SSO platform (authentik) exposes stored credentials/secrets to authenticated users with view permissions, impacting Digital Identity infrastructure.

*Deep dive: `TIER_2_CVE-2026-94611.md`*

___________________________________


# **[CVE-2026-94612 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-94612)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-24

Authentication bypass in authentik's SAML Source allows assertion replay and audience restriction bypass, directly impacting enterprise and government digital identity infrastructure.

*Deep dive: `TIER_2_CVE-2026-94612.md`*

___________________________________


# **[CVE-2026-94613 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-94613)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-24

TIER 2 DoS in authentik IdAM platform disrupts SAML authentication workflows, directly impacting Digital Identity infrastructure.

*Deep dive: `TIER_2_CVE-2026-94613.md`*

___________________________________


# **[CVE-2026-13016 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-13016)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-24

Foundational enterprise ITSM platform with unauthenticated SQLi impacting cross-sector DPI deployments across government, finance, and healthcare.

*Deep dive: `TIER_2_CVE-2026-13016.md`*

___________________________________


# **[CVE-2026-56744 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-56744)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-24

Finance sector: silent fund redirection in cryptocurrency wallet infrastructure via compromised storage provider.

*Deep dive: `TIER_2_CVE-2026-56744.md`*

___________________________________


# **[CVE-2026-86858 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-86858)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-24

Unauthenticated data manipulation in ServiceNow AI Platform threatens data integrity for Government and Finance deployments handling citizen services and operational workflows.

*Deep dive: `TIER_2_CVE-2026-86858.md`*

___________________________________


# **[CVE-2026-86859 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-86859)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-24

Unauthenticated authorization bypass in ServiceNow AI Platform, extensively deployed across government agencies for citizen services and ITSM, with secondary relevance to finance and healthcare.

*Deep dive: `TIER_2_CVE-2026-86859.md`*

___________________________________


# **[CVE-2026-86860 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-86860)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-24

Unauthenticated privilege escalation in ServiceNow AI Platform impacts Government, Finance, and Healthcare deployments relying on it for IT service management and automation.

*Deep dive: `TIER_2_CVE-2026-86860.md`*

___________________________________


# **[CVE-2026-93782 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-93782)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-24

Foundational Linux kernel hypervisor flaw enabling guest-to-host escape, directly impacting cloud and government IT infrastructure resilience.

*Deep dive: `TIER_2_CVE-2026-93782.md`*

___________________________________


# **[CVE-2026-97404 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-97404)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-24

OpenStack Zaqar authentication bypass impacts cloud infrastructure widely deployed in government, healthcare, and finance sectors.

*Deep dive: `TIER_2_CVE-2026-97404.md`*

___________________________________


# **[CVE-2026-57178 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-57178)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-24

Impacts Digital Identity via authentication bypass in a widely used social login library, enabling arbitrary account takeover through flawed OAuth2 callback verification.

*Deep dive: `TIER_2_CVE-2026-57178.md`*

___________________________________


# **[CVE-2026-78312 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-78312)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-24

Impacts industrial energy management systems deployed by government utilities and critical infrastructure operators, posing lateral movement risks in OT networks.

*Deep dive: `TIER_2_CVE-2026-78312.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine