# **Infrastructure Daily Brief: 2026-08-23**

**Infrastructure Daily Report TLP:GREEN Alert Id: 9557a506 2026-08-24 02:02:18**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Threats    | Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale | Microsoft  | 1.a      |
| Threats    | Inside Kali365, a Device Code Phishing Ecosystem | Huntress                      | 1.b      |
| Threats    | New widespread EvilTokens kit: device code phishing as-a-service                 | 1.c      |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover                        | 1.d      |
| Threats    | The Illicit Consent Grant Part 2: Device-Code Phishing and the AI PhaaS Wave | S | 1.b      |
| Threats    | Law Enforcement Takes Down Kratos/Sneaky2FA Phishing Service, With an Assist Fro | 1.a      |
| Threats    | The Device Code Phishing Tsunami: What We’re Seeing in the Wild                  | 1.b      |
| Threats    | Device Code Phishing — The Attack That Makes MFA Irrelevant                      | 1.d      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale/)**

**PIR: 1.a**

Source: ketch Published: 2026-08-23

Microsoft Security researchers dissect the Tycoon2FA AiTM phishing kit, revealing how threat actors bypass multi-factor authentication at scale. The report details infrastructure patterns, proxy chaining techniques, and real-time session hijacking methods used to harvest valid tokens. IT defenders can leverage these indicators to harden identity perimeters, deploy adaptive MFA policies, and monitor for anomalous proxy traffic.

___________________________________


# **[Inside Kali365, a Device Code Phishing Ecosystem | Huntress](https://www.huntress.com/blog/kali365-device-code-phishing-kit)**

**PIR: 1.b**

Source: ketch Published: 2026-08-23

Huntress provides a comprehensive breakdown of the Kali365 device code phishing ecosystem. The analysis covers kit architecture, OAuth consent abuse, and automated token harvesting workflows. Defenders gain actionable insights into detecting illicit consent grants, blocking malicious redirect URIs, and implementing conditional access rules to mitigate device code abuse in enterprise environments.

___________________________________


# **[New widespread EvilTokens kit: device code phishing as-a-service](https://www.sekoia.com/blog/new-widespread-eviltokens-kit-device-code-phishing-as-a-service-part-1)**

**PIR: 1.c**

Source: ketch Published: 2026-08-23

Sekoia.io examines the EvilTokens phishing-as-a-service platform, highlighting its modular design and widespread adoption by cybercriminal groups. The report outlines how the kit automates device code phishing campaigns, manages victim sessions, and evades traditional email security controls. Infrastructure teams can use these findings to update WAF signatures, monitor for suspicious OAuth scopes, and strengthen identity governance.

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.d**

Source: ketch Published: 2026-08-23

Proofpoint explores how device code phishing has evolved into a primary vector for identity takeover. The article details attacker tactics for bypassing MFA, exploiting legacy authentication protocols, and maintaining persistent access. IT infrastructure defenders are advised to enforce modern authentication standards, deploy phishing-resistant MFA, and implement continuous identity monitoring to counter these advanced campaigns.

___________________________________


# **[The Illicit Consent Grant Part 2: Device-Code Phishing and the AI PhaaS Wave | SlashID Blog](https://slashid.com/blog/illicit-consent-grant-part-2)**

**PIR: 1.b**

Source: ketch Published: 2026-08-23

SlashID’s threat research team analyzes the intersection of device-code phishing and AI-driven PhaaS. The report explains how attackers abuse OAuth consent flows to obtain long-lived tokens without user interaction. Defenders can mitigate these threats by restricting third-party app permissions, auditing consent grants, and deploying identity threat detection platforms that flag anomalous authorization requests.

___________________________________


# **[Law Enforcement Takes Down Kratos/Sneaky2FA Phishing Service, With an Assist From TrendAI™ | Trend Micro](https://www.trendmicro.com/en/research/26/g/kratos-takedown.html)**

**PIR: 1.a**

Source: ketch Published: 2026-08-23

Trend Micro documents the coordinated takedown of the Kratos/Sneaky2FA phishing service, detailing its infrastructure, monetization model, and victim targeting strategies. The report provides valuable IOCs and architectural insights for SOC teams. IT defenders can use this intelligence to block known malicious domains, update threat feeds, and assess exposure to similar credential harvesting operations.

___________________________________


# **[The Device Code Phishing Tsunami: What We’re Seeing in the Wild](https://www.levelblue.com/blogs/spiderlabs-blog/the-device-code-phishing-tsunami-what-were-seeing-in-the-wild)**

**PIR: 1.b**

Source: ketch Published: 2026-08-23

Level Blue’s SpiderLabs team reports on the rapid proliferation of device code phishing campaigns observed in the wild. The analysis covers campaign volume, target sectors, and evasion techniques used to bypass email gateways. Infrastructure teams should prioritize monitoring for device code prompts, educate users on recognizing consent phishing, and implement zero-trust identity controls to reduce attack surface.

___________________________________


# **[Device Code Phishing — The Attack That Makes MFA Irrelevant](https://cybergrind.org/blog/2026-06-02-device-code-phishing)**

**PIR: 1.d**

Source: ketch Published: 2026-08-23

CyberGrind examines how device code phishing effectively neutralizes traditional MFA implementations. The article breaks down the technical workflow attackers use to capture valid authentication tokens and maintain session persistence. IT defenders are urged to transition to phishing-resistant MFA methods, enforce strict conditional access policies, and deploy identity-aware proxies to detect and block token theft attempts.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine