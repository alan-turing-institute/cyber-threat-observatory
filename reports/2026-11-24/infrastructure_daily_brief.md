# **Infrastructure Daily Brief: 2026-11-24**

**Infrastructure Daily Report TLP:GREEN Alert Id: 251c3536 2026-11-25 18:58:54**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-136132 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-112732 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-123266 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-124284 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-132697 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-132734 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-132735 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-135796 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-136190 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-109484 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-116382 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-123256 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-132726 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-135792 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-135794 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-136183 (Tier 2)                                                         | 3.k      |
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.j.3    |
| Threats    | Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale              | 1.i      |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover                        | 1.j      |
| Threats    | The hidden network: Inside the phishing infrastructure ecosystem powering global | 1.e      |
| Threats    | Resurgence of a multi‑stage AiTM phishing and BEC campaign abusing SharePoint    | 1.f      |
| Threats    | Joint advisory: state-sponsored spear-phishing campaigns targeting critical infr | 1.a      |
| Threats    | Microsoft 365 Device Code Phishing Campaign Bypasses Password Theft ...          | 1.j      |
| Threats    | High volume phishing campaign uses Microsoft 365 outage lures to target multiple | 1.a      |
| Threats    | CVE-2026-135300                                                                  | 1.b      |
| Threats    | CVE-2026-135163                                                                  | 1.b      |
| Threats    | CVE-2026-136165                                                                  | 1.b      |
| Threats    | CVE-2026-117593                                                                  | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Inside an AI‑enabled device code phishing campaign](https://microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign)**

**PIR: 1.j.3**

Source: ketch Published: 2026-11-24

This campaign leverages AI to automate the generation and delivery of Microsoft Device Authorization Grant codes, enabling seamless account takeover without traditional password theft. Attackers use machine learning to mimic legitimate device code prompts and scale operations across thousands of targets. Defenders should monitor OAuth consent logs for suspicious device code grants, enforce app consent policies, and restrict interactive device code flows to approved corporate devices.

___________________________________


# **[Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale](https://microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale)**

**PIR: 1.i**

Source: ketch Published: 2026-11-24

Tycoon2FA is a sophisticated Adversary-in-the-Middle phishing kit that intercepts multi-factor authentication tokens in real-time. It proxies user sessions to legitimate login portals, capturing cookies and session tokens to bypass MFA. Infrastructure teams must implement phishing-resistant MFA, monitor for anomalous proxy traffic patterns, and deploy conditional access policies that restrict token reuse across disparate IP geolocations.

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.j**

Source: ketch Published: 2026-11-24

Device code phishing is rapidly evolving as a primary identity takeover vector, driven by publicly available toolkits and Phishing-as-a-Service models. Attackers exploit OAuth 2.0 device authorization flows to bypass traditional password-based defenses. Security teams should implement strict OAuth consent policies, monitor for high-frequency device code requests, and deploy identity-aware proxies to validate authentication contexts before granting access.

___________________________________


# **[The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime](https://microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime)**

**PIR: 1.e**

Source: ketch Published: 2026-11-24

Threat actors leverage a decentralized, resilient phishing infrastructure ecosystem that dynamically provisions domains, email services, and hosting to evade takedowns. This report details architectural patterns, including abuse of cloud providers and bulletproof hosting, enabling rapid campaign scaling. Infrastructure defenders should monitor for newly registered domains with shared ASN footprints, analyze DNS tunneling indicators, and implement proactive sinkholing strategies to disrupt the un

___________________________________


# **[Resurgence of a multi‑stage AiTM phishing and BEC campaign abusing SharePoint](https://microsoft.com/en-us/security/blog/2026/01/21/multistage-aitm-phishing-bec-campaign-abusing-sharepoint)**

**PIR: 1.f**

Source: ketch Published: 2026-11-24

A multi-stage campaign combines AiTM phishing with Business Email Compromise by abusing SharePoint file sharing permissions. Attackers harvest credentials, then manipulate SharePoint access controls to exfiltrate sensitive documents and pivot laterally. IT infrastructure defenders must audit SharePoint sharing settings, enforce least-privilege access, monitor for anomalous file permission changes, and integrate identity threat detection with cloud storage telemetry.

___________________________________


# **[Joint advisory: state-sponsored spear-phishing campaigns targeting critical infrastructure - SUVAT](https://suvat.uk/blog/five-eyes-advisory.html)**

**PIR: 1.a**

Source: ketch Published: 2026-11-24

Five Eyes agencies issue a joint advisory on state-sponsored spear-phishing campaigns targeting critical infrastructure sectors. Threat actors use highly tailored lures, compromised legitimate credentials, and advanced evasion techniques to infiltrate networks. Defenders should prioritize threat intelligence sharing, implement strict email authentication, monitor for lateral movement indicators, and ensure incident response playbooks address state-level adversary TTPs.

___________________________________


# **[Microsoft 365 Device Code Phishing Campaign Bypasses Password Theft ...](https://cybersecuritynews.com/microsoft-365-device-code-phishing-campaign/)**

**PIR: 1.j**

Source: ketch Published: 2026-11-24

Analysts document a campaign utilizing Microsoft’s Device Authorization Grant flow to achieve near-invisible account takeover. By combining realistic business lures with polished phishing kits, attackers bypass password theft entirely. Infrastructure defenders must audit Azure AD sign-in logs for device code authentication events, restrict OAuth app permissions, and implement continuous authentication monitoring to detect token hijacking attempts.

___________________________________


# **[High volume phishing campaign uses Microsoft 365 outage lures to target multiple industry sectors](https://microsoft.com/en-us/security/blog/2026/11/16/high-volume-phishing-campaign-uses-microsoft-365-outage-lures)**

**PIR: 1.a**

Source: ketch Published: 2026-11-24

A high-volume campaign exploits Microsoft 365 service outage notifications to trick users into credential submission. Attackers use spoofed sender addresses and urgent language to bypass initial email filters. Defenders should review mail flow rules for spoofed internal domains, enforce DMARC/DKIM/SPF strict alignment, and deploy user awareness training focused on service status verification via official channels rather than email links.

___________________________________


# **[CVE-2026-135300](https://nvd.nist.gov/vuln/detail/CVE-2026-135300)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-23

Pomerium from 0.30.0 before 0.34.0 contains an authentication bypass vulnerability in the MCP token endpoint that skips client secret verification for client_secret_basic clients. Attackers holding an intercepted authorization code or refresh token can redeem it at /.pomerium/mcp/token with any secret to obtain the victim's access tokens.

___________________________________


# **[CVE-2026-135163](https://nvd.nist.gov/vuln/detail/CVE-2026-135163)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-23

Okou API before 1.762.0 contains a missing authentication vulnerability in its Microsoft Teams, legacy Slack, and GitHub App integration OAuth flows that trusts caller-supplied userId and orgId values. Unauthenticated attackers who know a member's identifiers can complete the flow with their own external account to bind that identity or installation to the victim's Okou user and organization.

___________________________________


# **[CVE-2026-136165](https://nvd.nist.gov/vuln/detail/CVE-2026-136165)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-24

Fider before 0.40.0 contains an account takeover vulnerability that allows unauthenticated attackers to sign in as existing users by linking OAuth identities through unverified email matches. Attackers can use a Google account carrying an unverified copy of a victim's email, including a tenant administrator's, to bind their identity via the OAuthToken handler and obtain persistent session access.

___________________________________


# **[CVE-2026-117593](https://nvd.nist.gov/vuln/detail/CVE-2026-117593)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-24

Weak Password Recovery Mechanism for Forgotten Password vulnerability in ITG Bilgisayar Teknoloji Grubu Tic. Ltd. Şti. VSRM allows Password Recovery Exploitation.

This issue affects vSRM: from v14.08.3 before v14.08.5.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-136132 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-136132)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-24

Critical authentication bypass in a zero-trust identity gateway (Pangolin) that handles SSO, MFA, and OIDC, directly compromising digital identity and access management infrastructure.

*Deep dive: `TIER_2_CVE-2026-136132.md`*

___________________________________


# **[CVE-2026-112732 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-112732)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-24

Critical unauthenticated RCE in Microsoft Exchange/Visio indexing service poses direct risk to government email infrastructure and public sector communications.

*Deep dive: `TIER_2_CVE-2026-112732.md`*

___________________________________


# **[CVE-2026-123266 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-123266)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-24

Critical code injection in Adobe Experience Manager, a widely deployed CMS for government and financial public-facing portals, requiring patching to prevent server compromise.

*Deep dive: `TIER_2_CVE-2026-123266.md`*

___________________________________


# **[CVE-2026-124284 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-124284)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-24

Critical authentication bypass in enterprise SSO/federation flows (OIDC, SAML, AD FS) impacting Digital Identity infrastructure.

*Deep dive: `TIER_2_CVE-2026-124284.md`*

___________________________________


# **[CVE-2026-132697 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-132697)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-24

Bypasses 2FA in MediaWiki's EmailAuth extension, directly impacting Digital Identity and Government/public-sector wiki deployments reliant on secondary authentication.

*Deep dive: `TIER_2_CVE-2026-132697.md`*

___________________________________


# **[CVE-2026-132734 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-132734)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-24

TIER 2 flaw in widely deployed MediaWiki platforms enables unauthenticated file reads, exposing LDAP directories and database credentials critical to Digital Identity and public-sector infrastructure.

*Deep dive: `TIER_2_CVE-2026-132734.md`*

___________________________________


# **[CVE-2026-132735 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-132735)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-24

Directly compromises 2FA/TOTP and session management in MediaWiki, enabling account takeover and aligning with Digital Identity sector criteria for authentication bypass.

*Deep dive: `TIER_2_CVE-2026-132735.md`*

___________________________________


# **[CVE-2026-135796 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-135796)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-24

Critical root RCE in Volans NGFW management UI, a foundational perimeter security component explicitly tied to Government, Finance, and Healthcare infrastructure protection.

*Deep dive: `TIER_2_CVE-2026-135796.md`*

___________________________________


# **[CVE-2026-136190 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-136190)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-24

Directly compromises SSO/OIDC identity infrastructure by exposing client secrets and allowing provider manipulation, impacting Digital Identity services.

*Deep dive: `TIER_2_CVE-2026-136190.md`*

___________________________________


# **[CVE-2026-109484 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-109484)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-24

Tier 2 critical flaw in Azure App Service for Linux, a foundational cloud PaaS explicitly noted to support public-sector and enterprise workloads.

*Deep dive: `TIER_2_CVE-2026-109484.md`*

___________________________________


# **[CVE-2026-116382 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-116382)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-24

Foundational runtime for telecom, finance, and government backends; node-wide crash impacts regulated enterprise infrastructure.

*Deep dive: `TIER_2_CVE-2026-116382.md`*

___________________________________


# **[CVE-2026-123256 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-123256)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-24

Enterprise CMS flaw impacting public-facing portals across Government, Finance, and Healthcare sectors; enables unauthorized content/configuration writes via low-privilege accounts.

*Deep dive: `TIER_2_CVE-2026-123256.md`*

___________________________________


# **[CVE-2026-132726 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-132726)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-24

MediaWiki powers internal knowledge management and documentation across government, healthcare, and finance sectors, making this RCE vulnerability relevant to regulated enterprise infrastructure.

*Deep dive: `TIER_2_CVE-2026-132726.md`*

___________________________________


# **[CVE-2026-135792 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-135792)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-24

Unauthenticated root RCE in Panabit network gateways widely deployed in government and telecom infrastructure for bandwidth management and authentication.

*Deep dive: `TIER_2_CVE-2026-135792.md`*

___________________________________


# **[CVE-2026-135794 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-135794)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-24

General infrastructure vulnerability in enterprise/government network gateways enabling persistent root RCE and traffic policy manipulation.

*Deep dive: `TIER_2_CVE-2026-135794.md`*

___________________________________


# **[CVE-2026-136183 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-136183)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-24

Exposes payment and tax details in a multi-tenant e-commerce framework, impacting merchant financial operations and aligning with Finance sector criteria.

*Deep dive: `TIER_2_CVE-2026-136183.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine