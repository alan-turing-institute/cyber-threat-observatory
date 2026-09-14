# **Infrastructure Daily Brief: 2026-09-13**

**Infrastructure Daily Report TLP:GREEN Alert Id: 63495e09 2026-09-14 03:55:48**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.i      |
| Threats    | When checking the URL isn’t enough: phishing via the Microsoft identity platform | 1.j.3    |
| Threats    | Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA      | 1.h      |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover                        | 1.i      |
| Threats    | Device Code Phishing: Turning a Convenience Feature Into an MFA Bypass | Trend M | 1.d      |
| Threats    | Microsoft: Passkey Help Desk Calls Are Hijacking Cloud Accounts, Then Draining S | 1.e      |
| Threats    | PhantomEnigma: How a Malware Crew Turned Brazilian Government Sites Into Trusted | 1.h      |
| Threats    | The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations         | 1.f      |
| Threats    | CVE-2026-90474                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.i**

Source: ketch Published: 2026-09-13

Microsoft researchers detail a sophisticated campaign leveraging AI to automate device code phishing attacks, bypassing traditional password theft and MFA prompts. Attackers generate fake Microsoft login portals that prompt users to enter device codes, granting threat actors direct OAuth tokens. Defenders must educate users on legitimate device code flows, monitor for anomalous OAuth consent grants, and enforce application consent policies to block unauthorized token issuance.

___________________________________


# **[When checking the URL isn’t enough: phishing via the Microsoft identity platform | Securelist](https://securelist.com/microsoft-device-code-phishing-attack/120350/)**

**PIR: 1.j.3**

Source: ketch Published: 2026-09-13

Kaspersky Securelist reveals how attackers exploit the Microsoft identity platform to host phishing campaigns that appear legitimate, bypassing URL-based filtering. By leveraging trusted Microsoft domains and OAuth flows, threat actors trick users into granting access to malicious applications. Defenders must move beyond URL inspection, implement strict conditional access rules, monitor for unusual app registrations, and enforce multi-factor authentication with phishing-resistant methods like FI

___________________________________


# **[Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA](https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns)**

**PIR: 1.h**

Source: ketch Published: 2026-09-13

Attackers increasingly leverage compromised cloud-native services and serverless functions to host phishing infrastructure, evading traditional perimeter defenses. This report details how threat actors abuse legitimate cloud APIs to dynamically generate malicious landing pages, rotate domains, and maintain persistence. Infrastructure defenders must implement strict egress controls, monitor anomalous API calls, and deploy cloud workload protection platforms to detect and mitigate these stealthy c

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.i**

Source: ketch Published: 2026-09-13

Device code phishing has evolved into a primary vector for identity takeover, exploiting the convenience of cross-device authentication to bypass MFA. This analysis tracks how threat actors automate the generation of malicious consent pages and use social engineering to trick users into authorizing attacker-controlled applications. Infrastructure teams should implement strict OAuth consent policies, monitor for suspicious device code requests, and deploy identity threat detection solutions to fl

___________________________________


# **[Device Code Phishing: Turning a Convenience Feature Into an MFA Bypass | Trend Micro (US)](https://www.trendmicro.com/en_us/research/26/g/device-code-phishing.html)**

**PIR: 1.d**

Source: ketch Published: 2026-09-13

Trend Micro examines how device code phishing effectively bypasses multi-factor authentication by leveraging legitimate OAuth authorization flows. Attackers trick users into entering codes on compromised portals, granting direct access without triggering traditional MFA prompts. To mitigate this risk, organizations should restrict device code usage to approved applications, deploy identity protection tools that detect anomalous consent requests, and train users to recognize fake authorization pr

___________________________________


# **[Microsoft: Passkey Help Desk Calls Are Hijacking Cloud Accounts, Then Draining SharePoint](https://threat-intelligence.redeyesecurity.com/blog/passkey-phishing-microsoft-cloud-hijack-storm-3032-2026)**

**PIR: 1.e**

Source: ketch Published: 2026-09-13

Threat actors are exploiting help desk support channels to bypass passkey authentication, successfully hijacking Microsoft cloud accounts and exfiltrating sensitive SharePoint data. The campaign relies on social engineering to trick support staff into resetting credentials or approving device registrations. Defenders should enforce strict verification protocols for identity changes, monitor for unusual SharePoint access patterns, and implement conditional access policies that restrict help desk 

___________________________________


# **[PhantomEnigma: How a Malware Crew Turned Brazilian Government Sites Into Trusted Malware Hubs](https://securebulletin.com/phantomenigma-how-a-malware-crew-turned-brazilian-government-sites-into-trusted-malware-hubs)**

**PIR: 1.h**

Source: ketch Published: 2026-09-13

The PhantomEnigma malware crew has compromised Brazilian government websites to distribute malware, leveraging trusted domains to bypass security controls and increase victim trust. This infrastructure abuse highlights the risks of third-party web hosting and inadequate server hardening. Defenders must implement strict web application firewalls, monitor for unauthorized file uploads, enforce least-privilege access on public-facing servers, and collaborate with government CERTs to rapidly takedow

___________________________________


# **[The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations](https://itsecurityguru.org/2026/05/27/the-ai-phishing-revolution-from-spray-and-pray-to-autonomous-operations)**

**PIR: 1.f**

Source: ketch Published: 2026-09-13

The integration of generative AI has transformed phishing from broad, low-effort campaigns into highly targeted, autonomous operations. Attackers now use AI to craft context-aware emails, dynamically update landing pages, and automate follow-up sequences based on victim behavior. This shift demands advanced email security gateways with AI-driven content analysis, continuous user training focused on behavioral cues, and automated incident response playbooks to counter rapid, adaptive threats.

___________________________________


# **[CVE-2026-90474](https://nvd.nist.gov/vuln/detail/CVE-2026-90474)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-12

MCPHub before 1.0.32 contains an authentication bypass vulnerability in its embedded OAuth 2.0 authorization server where client authentication is disabled by default and PKCE enforcement is optional. Attackers who obtain an authorization code through interception can redeem it for access tokens without providing a client secret or PKCE verifier, gaining access to victim accounts and their privileges.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine