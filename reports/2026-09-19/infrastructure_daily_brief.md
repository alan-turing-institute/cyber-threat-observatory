# **Infrastructure Daily Brief: 2026-09-19**

**Infrastructure Daily Report TLP:GREEN Alert Id: 934449fb 2026-09-20 04:14:23**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-94054 (Tier 2)                                                          | 3.k      |
| Threats    | GhostCode: Dissecting a Novel Device Code Phishing Kit | eSentire                | 1.f      |
| Threats    | Russian hacker group Laundry Bear exploits Zimbra zero-click flaw to target West | 1.j.3    |
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.g      |
| Threats    | When checking the URL isn’t enough: phishing via the Microsoft identity platform | 1.h      |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover                        | 1.f      |
| Threats    | Device Code Phishing: Turning a Convenience Feature Into an MFA Bypass | Trend M | 1.f      |
| Threats    | Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA      | 1.h      |
| Threats    | The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations         | 1.g      |
| Threats    | CVE-2026-75878                                                                   | 1.b      |
| Threats    | CVE-2026-94000                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[GhostCode: Dissecting a Novel Device Code Phishing Kit | eSentire](https://www.esentire.com/blog/ghostcode-dissecting-a-novel-device-code-phishing-kit)**

**PIR: 1.f**

Source: ketch Published: 2026-09-19

eSentire researchers dissect GhostCode, a novel device code phishing kit that automates Microsoft identity takeover. The kit leverages AI to generate convincing prompts, bypassing traditional URL validation. Infrastructure defenders should monitor for unauthorized OAuth consent grants and implement conditional access policies that restrict device code flows to managed devices.

___________________________________


# **[Russian hacker group Laundry Bear exploits Zimbra zero-click flaw to target Western government, critical infrastructure](https://industrialcyber.co/cisa/russian-hacker-group-laundry-bear-exploits-zimbra-zero-click-flaw-to-target-western-government-critical-infrastructure)**

**PIR: 1.j.3**

Source: ketch Published: 2026-09-19

Industrial Cyber details how the Russian group Laundry Bear exploits a zero-click Zimbra vulnerability to target Western government and critical infrastructure. The campaign requires no user interaction, automatically delivering payloads via compromised email servers. Infrastructure defenders should prioritize patching Zimbra instances, segment email systems, and monitor for lateral movement indicators.

___________________________________


# **[Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.g**

Source: ketch Published: 2026-09-19

Microsoft details an AI-enabled device code phishing campaign that dynamically adapts lures based on victim interaction. Attackers exploit the convenience of device code authentication to harvest valid tokens without triggering MFA prompts. Defenders must enforce strict conditional access rules, monitor for anomalous token issuance, and educate users on verifying device code requests.

___________________________________


# **[When checking the URL isn’t enough: phishing via the Microsoft identity platform | Securelist](https://securelist.com/microsoft-device-code-phishing-attack/120350/)**

**PIR: 1.h**

Source: ketch Published: 2026-09-19

Kaspersky Securelist explains why URL validation fails against modern Microsoft identity platform phishing. Attackers use legitimate OAuth endpoints to harvest credentials and tokens, making traditional link inspection ineffective. Infrastructure defenders must shift focus to token telemetry, conditional access policies, and behavioral analytics to detect identity compromise.

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.f**

Source: ketch Published: 2026-09-19

Proofpoint analyzes how device code phishing has evolved into a primary identity takeover vector. By redirecting users to legitimate Microsoft login pages, attackers bypass traditional phishing filters and MFA. IT teams should deploy token-based conditional access, restrict device code usage to corporate networks, and implement continuous authentication monitoring.

___________________________________


# **[Device Code Phishing: Turning a Convenience Feature Into an MFA Bypass | Trend Micro (US)](https://www.trendmicro.com/en_us/research/26/g/device-code-phishing.html)**

**PIR: 1.f**

Source: ketch Published: 2026-09-19

Trend Micro examines how device code phishing turns a user convenience feature into a reliable MFA bypass. Attackers trick users into entering codes on malicious sites, granting full account access. Defenders should disable unnecessary device code flows, enforce risk-based conditional access, and monitor for impossible travel or rapid token usage patterns.

___________________________________


# **[Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA](https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns)**

**PIR: 1.h**

Source: ketch Published: 2026-09-19

CYFIRMA reports on phishing campaigns abusing cloud-native infrastructure to host dynamic landing pages and evade takedowns. Attackers leverage serverless functions and CDN networks to scale operations rapidly. Infrastructure teams must implement DNS sinkholing, monitor cloud resource creation anomalies, and enforce strict egress filtering to disrupt campaign infrastructure.

___________________________________


# **[The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations](https://itsecurityguru.org/2026/05/27/the-ai-phishing-revolution-from-spray-and-pray-to-autonomous-operations)**

**PIR: 1.g**

Source: ketch Published: 2026-09-19

IT Security Guru explores the shift from mass phishing to autonomous, AI-driven campaigns. Machine learning models now generate personalized lures, optimize send times, and adapt to security controls in real time. Defenders must prioritize behavioral analytics, zero-trust identity architectures, and automated threat response to counter adaptive phishing ecosystems.

___________________________________


# **[CVE-2026-75878](https://nvd.nist.gov/vuln/detail/CVE-2026-75878)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-18

IBM Sterling File Gateway could allow a remote attacker to bypass authentication and obtain a fully authenticated session due to improper authentication via an unvalidated SSO header.

___________________________________


# **[CVE-2026-94000](https://nvd.nist.gov/vuln/detail/CVE-2026-94000)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-19

A flaw was found in the Admin REST API of Keycloak, an open-source identity and access management solution. The issue occurs in the group-membership endpoints where the system fails to check if a group grants administrative privileges before allowing a user to be added. This allows a delegated administrator with limited permissions to add themselves to a high-privilege group, potentially gaining full control over the entire realm.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-94054 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-94054)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-19

General infrastructure MTA widely deployed across enterprise and public sector environments, impacting email continuity for regulated services.

*Deep dive: `TIER_2_CVE-2026-94054.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine