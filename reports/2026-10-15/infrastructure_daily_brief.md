# **Infrastructure Daily Brief: 2026-10-15**

**Infrastructure Daily Report TLP:GREEN Alert Id: 0b6e08e7 2026-10-18 19:07:31**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-111923 (Tier 2)                                                         | 3.k      |
| Threats    | Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Se | 1.b      |
| Threats    | Inside an AI‑enabled device code phishing campaign | Microsoft Security Blog     | 1.j.3    |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US        | 1.b      |
| Threats    | Access granted: phishing with device code authorization for account takeover | P | 1.b      |
| Threats    | Storm-2372 conducts device code phishing campaign | Microsoft Security Blog      | 1.b      |
| Threats    | Foreign Threat Actor Conducting Large-Scale Spearphishing Campaign with RDP Atta | 1.d      |
| Threats    | Midnight Blizzard conducts large-scale spear-phishing campaign using RDP files | | 1.d      |
| Threats    | Sophisticated Spearphishing Campaign Targets Government Organizations, IGOs, and | 1.c      |
| Threats    | CVE-2026-111882                                                                  | 1.b      |
| Threats    | CVE-2026-111898                                                                  | 1.b      |
| Threats    | CVE-2026-111895                                                                  | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/)**

**PIR: 1.b**

Source: ketch Published: 2026-10-15

Microsoft investigates the EvilTokens infrastructure driving widespread device code phishing campaigns. The blog reveals how threat actors automate token harvesting at scale, exploiting legitimate OAuth flows to maintain persistent access. Recommendations include implementing token-bound policies, monitoring for suspicious device code requests, and deploying identity protection alerts to revoke compromised sessions immediately.

___________________________________


# **[Inside an AI‑enabled device code phishing campaign | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.j.3**

Source: ketch Published: 2026-10-15

Microsoft details a sophisticated campaign leveraging AI-generated lures to bypass traditional filters and trick users into authorizing device code flows. Attackers exploit OAuth consent mechanisms to silently harvest valid tokens, enabling persistent access without credential theft. Defenders should monitor for anomalous consent grants, enforce conditional access policies, and deploy AI-aware detection models to identify synthetic phishing infrastructure.

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.b**

Source: ketch Published: 2026-10-15

Proofpoint analyzes how device code phishing has matured into a primary vector for identity takeover. Unlike traditional credential harvesting, this method forces users to manually enter authorization codes, granting attackers direct token access. The report outlines TTPs, infrastructure patterns, and mitigation strategies including MFA fatigue defenses, token lifecycle management, and user awareness training focused on consent prompts.

___________________________________


# **[Access granted: phishing with device code authorization for account takeover | Proofpoint US](https://www.proofpoint.com/us/blog/threat-insight/access-granted-phishing-device-code-authorization-account-takeover)**

**PIR: 1.b**

Source: ketch Published: 2026-10-15

This analysis breaks down the mechanics of device code authorization phishing, where attackers host fake login portals prompting victims to input codes from secondary devices. Successful grants yield valid OAuth tokens that bypass MFA. The article provides detection rules for SIEM platforms, recommends restricting app consent permissions, and highlights the growing prevalence of this technique across enterprise environments.

___________________________________


# **[Storm-2372 conducts device code phishing campaign | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/)**

**PIR: 1.b**

Source: ketch Published: 2026-10-15

Microsoft attributes a targeted device code phishing campaign to the Storm-2372 threat group. The actors leverage customized landing pages and social engineering to trick users into authorizing malicious apps. The report details campaign infrastructure, targeted sectors, and defensive measures such as blocking unknown app registrations and enforcing strict conditional access rules for high-value accounts.

___________________________________


# **[Foreign Threat Actor Conducting Large-Scale Spearphishing Campaign with RDP Attachments | CISA](https://www.cisa.gov/news-events/alerts/2024/10/31/foreign-threat-actor-conducting-large-scale-spearphishing-campaign-rdp-attachments)**

**PIR: 1.d**

Source: ketch Published: 2026-10-15

CISA warns of a foreign threat actor distributing spearphishing emails containing malicious RDP files designed to establish unauthorized remote access. The campaign targets government and enterprise networks, exploiting weak endpoint protections. Defenders are advised to block RDP file execution via email gateways, monitor for unexpected remote connections, and enforce network segmentation to limit lateral movement.

___________________________________


# **[Midnight Blizzard conducts large-scale spear-phishing campaign using RDP files | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2024/10/29/midnight-blizzard-conducts-large-scale-spear-phishing-campaign-using-rdp-files/)**

**PIR: 1.d**

Source: ketch Published: 2026-10-15

Microsoft tracks Midnight Blizzard’s large-scale spearphishing campaign utilizing malicious RDP files to compromise enterprise networks. The threat actor leverages stolen credentials and remote access tools to establish persistence. Defenders should prioritize blocking RDP file downloads, monitoring for anomalous remote desktop sessions, and enforcing multi-factor authentication across all administrative accounts.

___________________________________


# **[Sophisticated Spearphishing Campaign Targets Government Organizations, IGOs, and NGOs | CISA](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-148a)**

**PIR: 1.c**

Source: ketch Published: 2026-10-15

CISA details a sophisticated spearphishing operation targeting government bodies, international organizations, and NGOs. Attackers use highly tailored lures and credential harvesting portals to gain initial access. The advisory recommends implementing email authentication protocols, restricting external sharing, and deploying advanced threat protection to detect and block malicious attachments and links.

___________________________________


# **[CVE-2026-111882](https://nvd.nist.gov/vuln/detail/CVE-2026-111882)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-17

phpMyFAQ 3.2.0-alpha before 4.1.9 and 4.2.0-alpha before 4.2.0-beta contains an authentication bypass vulnerability that allows IdP-authenticated users to skip TOTP two-factor authentication through the Keycloak and Entra ID SSO callbacks. Attackers holding a valid or phished IdP identity linked to a 2FA-enabled account can complete the OIDC flow and obtain a fully authenticated session, including administrator accounts.

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



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-111923 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-111923)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-15

Unauthenticated DoS on Fleet MDM disrupts device governance and compliance workflows across Government, Healthcare, and Finance sectors.

*Deep dive: `TIER_2_CVE-2026-111923.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine