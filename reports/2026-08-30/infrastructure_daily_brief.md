# **Infrastructure Daily Brief: 2026-08-30**

**Infrastructure Daily Report TLP:GREEN Alert Id: 333155b8 2026-08-31 03:52:10**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-75759 (Tier 2)                                                          | 3.k      |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover                        | 1.f      |
| Threats    | Mirage2FA Phishing Kit Bypasses MFA to Hijack Microsoft 365 Sessions, Targeting  | 1.e      |
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.h      |
| Threats    | Chained Account Takeovers: AiTM Phishing Campaign Propagating Across Healthcare  | 1.d      |
| Threats    | Microsoft 365 Device Code Phishing Campaign Bypasses Password Theft ...          | 1.f      |
| Threats    | NovaCookies at scale: Inside the $320 Phishing Service Targeting Hundreds of Org | 1.g      |
| Threats    | Procurement-Themed AiTM Campaign Hijacks Microsoft 365 Sessions via Compromised  | 1.i      |
| Threats    | TIDALGUEST: A Self-Replicating Invitation Phishing Cluster | AegisAI             | 1.a      |
| Threats    | CVE-2026-82466                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Device Code Phishing is an Evolution in Identity Takeover](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.f**

Source: ketch Published: 2026-08-30

Device code phishing is rapidly evolving as a primary vector for identity compromise, driven by publicly available toolkits and phishing-as-a-service models. Attackers manipulate Microsoft’s Device Authorization Grant flow to trick users into approving malicious OAuth tokens. This technique bypasses password theft and traditional MFA. Infrastructure teams should monitor for unusual device code approvals, restrict OAuth app consent policies, and educate users on recognizing device code prompts.

___________________________________


# **[Mirage2FA Phishing Kit Bypasses MFA to Hijack Microsoft 365 Sessions, Targeting 3,500+ Organizations - Cyber Accord](https://www.cyberaccord.com/mirage2fa-phishing-kit-bypasses-mfa-to-hijack-microsoft-365-sessions-targeting-3500-organizations/)**

**PIR: 1.e**

Source: ketch Published: 2026-08-30

The Mirage2FA kit exploits Microsoft 365 authentication flows to bypass multi-factor authentication and steal active user sessions. Targeting over 3,500 organizations, the campaign uses real-time proxying to capture MFA tokens and session cookies. Infrastructure defenders must prioritize MFA fatigue detection, enforce phishing-resistant authentication methods like FIDO2, and monitor for impossible travel or concurrent session anomalies in Azure AD logs.

___________________________________


# **[Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.h**

Source: ketch Published: 2026-08-30

Microsoft researchers detail a campaign combining AI-generated lures with automated device code phishing to scale account compromises. Threat actors use end-to-end automation to generate live authentication codes on demand, significantly increasing success rates and maintaining persistent access. Defenders should leverage Microsoft Graph security APIs to detect anomalous consent grants, enforce just-in-time access, and deploy AI-driven email filtering to block synthetic phishing content.

___________________________________


# **[Chained Account Takeovers: AiTM Phishing Campaign Propagating Across Healthcare and Academic Medical Institutions - Security Risk Advisors](https://sra.io/blog/chained-account-takeovers-aitm-phishing-campaign-propagating-across-healthcare-and-academic-medical-institutions/)**

**PIR: 1.d**

Source: ketch Published: 2026-08-30

A sophisticated Adversary-in-the-Middle (AiTM) campaign is chaining account takeovers across healthcare and academic medical networks. Attackers use live proxying to capture credentials and MFA tokens, then pivot laterally using compromised Outlook accounts. Defenders should implement email authentication hardening, deploy AI-driven anomaly detection for login patterns, and restrict cross-tenant sharing to contain lateral movement.

___________________________________


# **[Microsoft 365 Device Code Phishing Campaign Bypasses Password Theft ...](https://cybersecuritynews.com/microsoft-365-device-code-phishing-campaign/)**

**PIR: 1.f**

Source: ketch Published: 2026-08-30

ReversingLabs analysts document an active campaign abusing Microsoft’s Device Authorization Grant flow to execute near-invisible account takeovers. The attack combines realistic business-themed lures with a polished phishing kit, tricking users into authorizing malicious OAuth tokens. This bypasses traditional credential harvesting. Infrastructure teams must audit registered OAuth applications, enforce user consent restrictions, and monitor for high-privilege token issuance in identity logs.

___________________________________


# **[NovaCookies at scale: Inside the $320 Phishing Service Targeting Hundreds of Organizations](https://www.island.io/blog/novacookies-at-scale-inside-the-320-phishing-service-targeting-hundreds-of-organizations)**

**PIR: 1.g**

Source: ketch Published: 2026-08-30

Threat actors are leveraging the NovaCookies phishing-as-a-service platform to conduct large-scale credential harvesting campaigns. Priced at just $320, this service enables low-skill attackers to target hundreds of organizations simultaneously. The infrastructure relies on automated proxying and real-time session interception, bypassing traditional email filters. Defenders should monitor for anomalous OAuth consent requests and implement strict conditional access policies to mitigate session hi

___________________________________


# **[Procurement-Themed AiTM Campaign Hijacks Microsoft 365 Sessions via Compromised Outlook Accounts | Mallory](https://mallory.ai/stories/019f864d-cd13-7094-9964-55c354477637)**

**PIR: 1.i**

Source: ketch Published: 2026-08-30

Attackers are deploying procurement-themed Adversary-in-the-Middle phishing kits to hijack Microsoft 365 sessions. By compromising initial Outlook accounts, threat actors send highly convincing vendor invoice lures that proxy real login portals. This enables seamless MFA bypass and session theft. IT defenders should implement strict email routing rules for procurement domains, monitor for session token reuse, and enforce phishing-resistant MFA for finance workflows.

___________________________________


# **[TIDALGUEST: A Self-Replicating Invitation Phishing Cluster | AegisAI](https://www.aegisai.ai/blog/tidalguest-invitation-phishing-cluster)**

**PIR: 1.a**

Source: ketch Published: 2026-08-30

The TIDALGUEST cluster utilizes self-replicating invitation phishing to infiltrate corporate networks. Compromised accounts automatically generate and distribute malicious calendar and meeting invites, propagating the campaign across domains. This technique exploits trust in internal communication channels. Defenders should monitor for anomalous calendar creation patterns, restrict external meeting invites, and deploy behavioral analytics to detect automated invitation generation.

___________________________________


# **[CVE-2026-82466](https://nvd.nist.gov/vuln/detail/CVE-2026-82466)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-29

Rodauth before 2.46.0 contains an authentication bypass vulnerability in the webauthn_login route that allows logged-in users to authenticate as any other account. Attackers can exploit improper account resolution logic that falls back to session account identifiers instead of validating the credential binding to complete authentication as arbitrary users.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-75759 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-75759)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-30

Compromises OpenID Connect token validation in the oidcc library, enabling account takeover and directly impacting Digital Identity federation infrastructure.

*Deep dive: `TIER_2_CVE-2026-75759.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine