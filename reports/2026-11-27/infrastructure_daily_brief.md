# **Infrastructure Daily Brief: 2026-11-27**

**Infrastructure Daily Report TLP:GREEN Alert Id: 4a45e551 2026-11-28 04:55:56**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-124981 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-137746 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-123757 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-123761 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-133940 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-137738 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-138026 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-59103 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-85252 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-138034 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-80472 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-137724 (Tier 2)                                                         | 3.k      |
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.j.3    |
| Threats    | Unmasking EvilTokens: Getting to the root of device code phishing                | 1.b      |
| Threats    | Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale              | 1.a      |
| Threats    | Resurgence of a multi‑stage AiTM phishing and BEC campaign abusing SharePoint    | 1.c      |
| Threats    | Microsoft 365 Device Code Phishing Campaign Bypasses Password Theft ...          | 1.b      |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover                        | 1.b      |
| Threats    | The hidden network: Inside the phishing infrastructure ecosystem powering global | 1.d      |
| Threats    | Sophisticated Spearphishing Campaign Targets Government Organizations, IGOs, and | 1.e      |
| Threats    | CVE-2026-123903                                                                  | 1.b      |
| Threats    | CVE-2026-135384                                                                  | 1.b      |
| Threats    | CVE-2026-137523                                                                  | 1.b      |
| Threats    | CVE-2026-137478                                                                  | 1.b      |
| Threats    | CVE-2026-137552                                                                  | 1.b      |
| Threats    | CVE-2026-137457                                                                  | 1.b      |
| Threats    | CVE-2026-124842                                                                  | 1.b      |
| Threats    | CVE-2026-80500                                                                   | 1.b      |
| Threats    | CVE-2026-52803                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.j.3**

Source: ketch Published: 2026-11-27

Threat actors are now leveraging AI to automate device code phishing campaigns, generating live authentication codes on demand and sustaining post-compromise access. This analysis highlights the integration of machine learning for dynamic lure generation and real-time session management. Defenders must adopt AI-driven detection models, enforce strict conditional access, and monitor for automated consent patterns.

___________________________________


# **[Unmasking EvilTokens: Getting to the root of device code phishing](https://microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing?trk=article-ssr-frontend-pulse_little-text-block)**

**PIR: 1.b**

Source: ketch Published: 2026-11-27

EvilTokens exploits Microsoft’s Device Authorization Grant flow to silently steal authentication tokens without requiring password entry. This breakdown reveals how threat actors automate device code generation and token exchange. Defenders should review OAuth consent policies, monitor for anomalous device code approvals, and enforce conditional access rules to block unauthorized token issuance.

___________________________________


# **[Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale](https://microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale)**

**PIR: 1.a**

Source: ketch Published: 2026-11-27

Tycoon2FA represents a sophisticated Adversary-in-the-Middle phishing kit designed to bypass multi-factor authentication at scale. This report details its reverse proxy architecture, session hijacking mechanisms, and deployment tactics. Infrastructure teams can leverage these findings to implement advanced proxy detection, certificate pinning, and behavioral analytics to mitigate AiTM threats.

___________________________________


# **[Resurgence of a multi‑stage AiTM phishing and BEC campaign abusing SharePoint](https://microsoft.com/en-us/security/blog/2026/01/21/multistage-aitm-phishing-bec-campaign-abusing-sharepoint)**

**PIR: 1.c**

Source: ketch Published: 2026-11-27

This campaign combines AiTM proxy techniques with Business Email Compromise tactics, specifically abusing SharePoint for credential harvesting and lateral movement. The multi-stage approach demonstrates how attackers pivot from initial compromise to persistent access. IT teams must strengthen SharePoint security configurations, enforce strict MFA, and deploy email authentication protocols to disrupt these workflows.

___________________________________


# **[Microsoft 365 Device Code Phishing Campaign Bypasses Password Theft ...](https://cybersecuritynews.com/microsoft-365-device-code-phishing-campaign/)**

**PIR: 1.b**

Source: ketch Published: 2026-11-27

ReversingLabs documents an active campaign exploiting Microsoft 365’s Device Authorization Grant to bypass traditional password theft. By combining realistic business lures with polished phishing kits, attackers achieve near-invisible account takeovers. Infrastructure defenders should audit OAuth app permissions, disable unnecessary device code flows, and deploy advanced email filtering to block these sophisticated lures.

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.b**

Source: ketch Published: 2026-11-27

Device code phishing has surged due to publicly available toolkits and phishing-as-a-service models. This threat intelligence report outlines the operational shift from traditional credential harvesting to token-based identity takeover. Security leaders should prioritize monitoring OAuth consent logs, educating users on device code prompts, and implementing zero-trust identity validation to counter this evolving vector.

___________________________________


# **[The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime](https://microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime)**

**PIR: 1.d**

Source: ketch Published: 2026-11-27

This analysis dissects the underground infrastructure ecosystem fueling global phishing operations. IT defenders will find critical insights into domain generation algorithms, bulletproof hosting networks, and proxy chaining techniques used to evade takedowns. Understanding these foundational layers is essential for proactive threat hunting and infrastructure hardening.

___________________________________


# **[Sophisticated Spearphishing Campaign Targets Government Organizations, IGOs, and NGOs | CISA](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-148a)**

**PIR: 1.e**

Source: ketch Published: 2026-11-27

CISA warns of a targeted spearphishing campaign focusing on government and international organizations. The attack leverages highly customized lures and malicious attachments to establish initial footholds. IT infrastructure teams should enhance email gateway rules, enforce application allowlisting, and conduct regular phishing simulations to strengthen human and technical defenses against state-sponsored threats.

___________________________________


# **[CVE-2026-123903](https://nvd.nist.gov/vuln/detail/CVE-2026-123903)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-26

VMware vCenter contains an authentication bypass vulnerability in the VMware Directory Service. Broadcom has evaluated the severity of this issue to be in the Critical severity range with a maximum CVSSv3 base score of 9.8.
Affected versions:
VMware vCenter Server 9.1.x.x: fixed in 9.1.2
VMware vCenter Server 9.0.x.x: fixed in 9.0.2.0300
VMware vCenter Server 8.0: fixed in 8.0 U3m
VMware Cloud Foundation 5.x: fixed in 5.2.5
VMware Telco Cloud Platform 3.0: fixed in KB463501
VMware Telco Cloud Pl

___________________________________


# **[CVE-2026-135384](https://nvd.nist.gov/vuln/detail/CVE-2026-135384)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-26

Improper authentication in OIDC bearer token verification in Canonical LXD before 5.0.12, 5.21.10, 6.10.2 allows a remote attacker holding a token signed by the configured identity provider to authenticate to the LXD API and gain unauthorized control or impersonate users via presenting tokens issued for other applications, ID tokens, or unverified email claims.

___________________________________


# **[CVE-2026-137523](https://nvd.nist.gov/vuln/detail/CVE-2026-137523)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-26

ToolJet before 3.21.96-LTS contains an authentication bypass in instance-level Google SSO because the id_token audience is not verified when no Google OAuth client ID is configured, the shipped default. Unauthenticated attackers can submit a Google-signed id_token minted for their own OAuth client to /api/sso/sign-in/common/google without an organizationId, obtaining a session as any existing user with the matching email.

___________________________________


# **[CVE-2026-137478](https://nvd.nist.gov/vuln/detail/CVE-2026-137478)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-26

Traefik before 2.11.62, 3.x before 3.7.18, and 3.8.0-rc.1 contain an authentication bypass in the ForwardAuth middleware because connection isolation for NTLM and Negotiate credentials checks only the Authorization header, not Proxy-Authorization. Unauthenticated attackers can send such credentials in Proxy-Authorization to reuse a shared authentication-server connection already authenticated by another user, receive that user's identity via authResponseHeaders, and access backends as that user.

___________________________________


# **[CVE-2026-137552](https://nvd.nist.gov/vuln/detail/CVE-2026-137552)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-26

Frappe Framework before 15.121.1 and 16.x before 16.35.0 accepts an undocumented OAuth2 Resource Owner Password Credentials (password) grant at its token endpoint, which does not enforce two-factor authentication or forced password resets. An attacker with a user's valid credentials can use this grant to obtain a full-access OAuth token, bypassing 2FA.

___________________________________


# **[CVE-2026-137457](https://nvd.nist.gov/vuln/detail/CVE-2026-137457)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-26

FreeRDP from 3.0.0 before 3.33.0 contains a missing authentication vulnerability in the shadow server's fast-path input handlers in fastpath.c that allows unauthenticated attackers to inject input before activation. Attackers can negotiate TLS-only RDP, skip Confirm Active, and send Fast-Path Input Event PDUs to inject keystrokes and mouse movement into the host X11 session via XTEST.

___________________________________


# **[CVE-2026-124842](https://nvd.nist.gov/vuln/detail/CVE-2026-124842)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-26

SEPPmail Secure Email Gateway before 15.1.2 exposes legacy GINA password-reset paths that can replace a registered account credential without authenticating the requester. A remote attacker who knows the account address can force a reset when a configured administrator or valid stored creator is present, disrupting access and revoking active API tokens; the replacement credential is sent only to a pre-existing trusted recipient.

___________________________________


# **[CVE-2026-80500](https://nvd.nist.gov/vuln/detail/CVE-2026-80500)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-27

Dell Secure Connect Gateway - Virtual Edition, versions prior to 5.36.00.16, contains an Improper Authentication vulnerability. An unauthenticated local attacker could potentially exploit this vulnerability, leading to Unauthorized access.

___________________________________


# **[CVE-2026-52803](https://nvd.nist.gov/vuln/detail/CVE-2026-52803)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-26

Gogs is an open source self-hosted Git service. Prior to 0.15.0, Gogs does not regenerate the session ID after successful authentication. An attacker who forces a victim to use a known session ID can hijack the session after the victim logs in and take over the account. This issue is fixed in version 0.15.0.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-124981 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-124981)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-27

Critical OIDC Provider flaw enables session hijacking via improper JWT validation, directly impacting Digital Identity infrastructure.

*Deep dive: `TIER_2_CVE-2026-124981.md`*

___________________________________


# **[CVE-2026-137746 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-137746)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-27

Critical 5G core network DoS vulnerability impacting national telecommunications infrastructure that underpins government, finance, and healthcare mobile services.

*Deep dive: `TIER_2_CVE-2026-137746.md`*

___________________________________


# **[CVE-2026-123757 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-123757)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-27

Foundational DNS infrastructure flaw causing service disruption; explicitly noted as critical for national digital public infrastructure resilience.

*Deep dive: `TIER_2_CVE-2026-123757.md`*

___________________________________


# **[CVE-2026-123761 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-123761)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-27

Foundational DNS infrastructure flaw impacting service resolution across all DPI sectors, classified as General Infrastructure with high integrity risk for public-facing deployments.

*Deep dive: `TIER_2_CVE-2026-123761.md`*

___________________________________


# **[CVE-2026-133940 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-133940)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-27

Exposes customer PII and password hashes in public-facing e-commerce stores, directly impacting Finance and Digital Identity sectors through credential theft and transaction data breaches.

*Deep dive: `TIER_2_CVE-2026-133940.md`*

___________________________________


# **[CVE-2026-137738 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-137738)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-27

Foundational remote access infrastructure supporting critical backend administration across Government, Healthcare, and Finance environments.

*Deep dive: `TIER_2_CVE-2026-137738.md`*

___________________________________


# **[CVE-2026-138026 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-138026)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-27

Finance sector relevance: unauthenticated access to blockchain transaction monitoring, wallet management, and financial API credit consumption.

*Deep dive: `TIER_2_CVE-2026-138026.md`*

___________________________________


# **[CVE-2026-59103 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-59103)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-27

Critical unauthenticated session forgery in a multi-tenant ERP platform directly compromises financial records and business operations across all hosted tenants.

*Deep dive: `TIER_2_CVE-2026-59103.md`*

___________________________________


# **[CVE-2026-85252 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-85252)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-27

SQLi in Apigee Edge Monetization API exposes revenue and billing data, directly impacting financial operations and government digital service tracking.

*Deep dive: `TIER_2_CVE-2026-85252.md`*

___________________________________


# **[CVE-2026-138034 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-138034)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-27

Finance sector relevance: unauthenticated MCP endpoints expose BigCommerce order, customer, and transaction data, impacting e-commerce financial operations and PII confidentiality.

*Deep dive: `TIER_2_CVE-2026-138034.md`*

___________________________________


# **[CVE-2026-80472 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-80472)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-27

General Infrastructure: Public-facing VPN gateway RCE impacts foundational remote-access networks used across regulated sectors for secure workforce connectivity.

*Deep dive: `TIER_2_CVE-2026-80472.md`*

___________________________________


# **[CVE-2026-137724 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-137724)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-27

Critical unauthenticated management bypass in enterprise PBX/UC infrastructure widely deployed across government and healthcare communications networks.

*Deep dive: `TIER_2_CVE-2026-137724.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine