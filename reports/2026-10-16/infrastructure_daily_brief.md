# **Infrastructure Daily Brief: 2026-10-16**

**Infrastructure Daily Report TLP:GREEN Alert Id: 1334e993 2026-10-18 21:26:47**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-111882 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-111924 (Tier 2)                                                         | 3.k      |
| Threats    | The hidden network: Inside the phishing infrastructure ecosystem powering global | 1.g.1    |
| Threats    | Inside an AI‑enabled device code phishing campaign | Microsoft Security Blog     | 1.i.1    |
| Threats    | Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Se | 1.f.1    |
| Threats    | Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale | Microsoft  | 1.e.1    |
| Threats    | Tracking BigBear 2.0 Evilginx2 Phishing Campaign | CloudSEK                      | 1.e.2    |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover                        | 1.f.2    |
| Threats    | SideWinder APT Credential Harvesting Campaign — PaaS Platform Abuse at Scale     | 1.g.2    |
| Threats    | Microsoft 365 Device Code Phishing Campaign Bypasses Password Theft ...          | 1.f.3    |
| Threats    | CVE-2026-111898                                                                  | 1.b      |
| Threats    | CVE-2026-111895                                                                  | 1.b      |
| Threats    | CVE-2026-104627                                                                  | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime/)**

**PIR: 1.g.1**

Source: ketch Published: 2026-10-16

Microsoft Security researchers dissect the sprawling infrastructure ecosystem fueling global phishing campaigns. The report details how threat actors leverage compromised domains, bulletproof hosting, and automated domain generation algorithms to evade takedowns. Infrastructure defenders will find actionable IOCs, architectural breakdowns of proxy networks, and mitigation strategies for disrupting these resilient criminal supply chains at the network level.

___________________________________


# **[Inside an AI‑enabled device code phishing campaign | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.i.1**

Source: ketch Published: 2026-10-16

Microsoft researchers expose a sophisticated campaign combining AI-generated lures with Microsoft’s Device Authorization Grant flow. Attackers use machine learning to craft highly personalized emails that trick users into entering device codes. The article provides detection queries for Entra ID, highlights behavioral anomalies in OAuth consent logs, and outlines policy hardening steps to block malicious approvals.

___________________________________


# **[Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/)**

**PIR: 1.f.1**

Source: ketch Published: 2026-10-16

This technical breakdown traces the EvilTokens toolkit to its core mechanisms, explaining how it exploits legitimate OAuth device code flows to steal valid access tokens. The report details the attacker’s infrastructure, token persistence techniques, and evasion tactics. IT defenders gain critical guidance on monitoring Azure AD sign-in logs, restricting device code grant policies, and deploying conditional access rules.

___________________________________


# **[Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale/)**

**PIR: 1.e.1**

Source: ketch Published: 2026-10-16

A deep dive into the Tycoon2FA adversary-in-the-middle phishing kit, revealing how attackers bypassed multi-factor authentication at scale. The analysis covers the kit’s reverse-proxy architecture, session hijacking techniques, and deployment patterns. Security teams can leverage these insights to configure WAF rules, monitor for suspicious proxy traffic, and implement certificate pinning to neutralize AiTM threats.

___________________________________


# **[Tracking BigBear 2.0 Evilginx2 Phishing Campaign | CloudSEK](https://www.cloudsek.com/blog/tracking-bigbear-2-0-evilginx2-phishing-campaign)**

**PIR: 1.e.2**

Source: ketch Published: 2026-10-16

CloudSEK tracks the BigBear 2.0 campaign leveraging the open-source Evilginx2 framework to conduct large-scale AiTM attacks. The analysis maps the campaign’s infrastructure, domain registration patterns, and target sectors. Defenders receive actionable network indicators, DNS sinkhole recommendations, and browser extension deployment strategies to intercept proxy-based credential harvesting before session tokens are exfiltrated.

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.f.2**

Source: ketch Published: 2026-10-16

Proofpoint examines the rapid proliferation of device code phishing, driven by publicly available toolkits and phishing-as-a-service models. The report highlights how attackers bypass traditional MFA by hijacking OAuth consent workflows. Infrastructure teams are advised to audit third-party app permissions, implement strict conditional access policies, and deploy user training focused on recognizing device code prompts.

___________________________________


# **[SideWinder APT Credential Harvesting Campaign — PaaS Platform Abuse at Scale](https://intel.breakglass.tech/post/sidewinder-mhil-zeabur)**

**PIR: 1.g.2**

Source: ketch Published: 2026-10-16

Breakglass Intelligence details how the SideWinder APT group abuses Platform-as-a-Service environments to host credential harvesting infrastructure at scale. The report outlines the group’s use of ephemeral cloud instances, automated domain provisioning, and legitimate SaaS integrations to evade detection. Defenders learn how to monitor cloud deployment logs, restrict PaaS permissions, and detect anomalous hosting patterns.

___________________________________


# **[Microsoft 365 Device Code Phishing Campaign Bypasses Password Theft ...](https://cybersecuritynews.com/microsoft-365-device-code-phishing-campaign/)**

**PIR: 1.f.3**

Source: ketch Published: 2026-10-16

ReversingLabs documents an active Microsoft 365 campaign that sidesteps traditional password harvesting by abusing the Device Authorization Grant flow. Attackers deploy polished, business-themed lures to trick users into authorizing malicious apps. The article provides email headers, phishing kit URLs, and Microsoft Graph API queries to identify compromised accounts and revoke unauthorized device code grants.

___________________________________


# **[CVE-2026-111898](https://nvd.nist.gov/vuln/detail/CVE-2026-111898)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-17

phpMyFAQ 4.2.0-alpha before 4.2.0-beta contains an authentication bypass vulnerability that allows Keycloak users to take over local accounts by matching preferred_username or email. Attackers controlling a Keycloak identity with a colliding username or unverified email can log in through /auth/keycloak/authorize to bind their subject and gain superadmin privileges.

___________________________________


# **[CVE-2026-111895](https://nvd.nist.gov/vuln/detail/CVE-2026-111895)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-17

phpMyFAQ 3.2.0 before 4.0.0 and 4.0.2 before 4.2.0-beta contains an authentication bypass in its Microsoft Entra ID login flow, which links users by the mutable preferred_username claim and whose AuthEntraId::create() ignores the duplicate-login exception while continuing with the existing local account. Attackers controlling an Entra identity in the configured tenant with a matching preferred_username can take over that local account, including super-admin accounts.

___________________________________


# **[CVE-2026-104627](https://nvd.nist.gov/vuln/detail/CVE-2026-104627)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-18

The Gitea OpenID association callback in the security settings accepted a positive OpenID 2.0 assertion without checking that the signed-in user had started the linking. Because OpenID 2.0 allows unsolicited assertions, an attacker-controlled OpenID provider could attach the attacker's identity to the account of a signed-in victim who opened a crafted link, and the attacker could then sign in as the victim through OpenID login, which does not apply the local TOTP or WebAuthn checks. The callback

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-111882 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-111882)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-16

Bypasses TOTP 2FA in SSO/OIDC flows (Keycloak/Entra ID), directly impacting enterprise Digital Identity and access management controls.

*Deep dive: `TIER_2_CVE-2026-111882.md`*

___________________________________


# **[CVE-2026-111924 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-111924)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-16

Enterprise MDM platform deployed in public sector IT; unauthenticated DoS could disrupt government device management and security compliance workflows.

*Deep dive: `TIER_2_CVE-2026-111924.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine