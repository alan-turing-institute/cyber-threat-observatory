# Daily phishing and identity campaigns

- **Report date:** 2026-08-26
- **Sources:** ketch OSINT (3 queries)

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.b

Microsoft researchers detail a sophisticated phishing campaign leveraging AI-generated prompts to trick users into entering device codes. This technique bypasses traditional password-based defenses and multi-factor authentication, granting attackers direct access to Microsoft 365 accounts. The report outlines detection strategies, telemetry indicators, and mitigation steps for infrastructure teams managing enterprise identity platforms.

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## When checking the URL isn’t enough: phishing via the Microsoft identity platform | Securelist

**PIR:** 1.b

Kaspersky Securelist reveals how threat actors exploit legitimate Microsoft identity endpoints to conduct phishing campaigns that evade traditional URL filtering. By leveraging authorized OAuth flows, attackers capture valid session tokens without stealing credentials. The analysis highlights infrastructure defense strategies, including token lifecycle monitoring and strict conditional access configurations.

Source: https://securelist.com/microsoft-device-code-phishing-attack/120350/

## Device Code Phishing is an Evolution in Identity Takeover

**PIR:** 1.b

Proofpoint analyzes how device code phishing has matured into a primary vector for enterprise identity takeover. Attackers now automate the generation of convincing login portals that harvest valid OAuth tokens, effectively neutralizing passwordless and MFA controls. The article provides actionable guidance for security operations centers to monitor token issuance anomalies and enforce conditional access policies.

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## Microsoft 365 device code phishing campaign bypasses password stealing | RL Blog

**PIR:** 1.b

ReversingLabs documents a widespread campaign targeting Microsoft 365 environments through device code phishing. Unlike traditional credential harvesting, this method captures valid authentication tokens directly, rendering password resets ineffective. The report details technical indicators, attack infrastructure, and recommended detection rules for identity protection platforms and SIEM systems.

Source: https://www.reversinglabs.com/blog/device-code-phishing-campaign

## EvilTokens abuses Microsoft device code flow for account takeovers | CSO Online

**PIR:** 1.b

CSO Online examines the EvilTokens malware family, which specifically targets the Microsoft device code authentication flow to facilitate account takeovers. The malware automates token theft and session hijacking, allowing persistent access to compromised environments. Infrastructure defenders are advised to implement token revocation workflows and monitor for anomalous device code requests.

Source: https://www.csoonline.com/article/4153742/eviltokens-abuses-microsoft-device-code-flow-for-account-takeovers.html

## Three Active Microsoft 365 Phishing Campaigns Targeting Schools and Government Agencies

**PIR:** 1.a

Forsyte IT identifies three concurrent phishing campaigns specifically targeting educational and government Microsoft 365 tenants. Attackers deploy credential harvesting pages mimicking Microsoft login flows to steal administrative and user accounts. The article provides infrastructure-focused mitigation steps, including domain allowlisting, user awareness training, and enhanced sign-in risk policies.

Source: https://forsyteit.com/three-active-microsoft-365-phishing-campaigns-targeting-schools-and-government-agencies

## Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA

**PIR:** 1.c

CISA warns of a zero-click phishing campaign by the Laundry Bear group exploiting vulnerabilities in Zimbra email servers. The attack requires no user interaction, automatically delivering malicious payloads or harvesting session data. Infrastructure teams are urged to patch Zimbra instances immediately, review server access logs, and isolate affected mail systems to prevent lateral movement.

Source: https://tempmail.ninja/blog/laundry-bear-zimbra-phishing

## Zero-click email attacks: What businesses need to know

**PIR:** 1.c

ITPro provides a comprehensive overview of zero-click email attacks, explaining how threat actors exploit rendering engines and email client vulnerabilities to execute code without user interaction. The article outlines architectural defenses, including sandboxed email processing, strict content filtering, and endpoint detection strategies tailored for modern infrastructure environments.

Source: https://itpro.com/security/phishing/zero-click-email-attacks-what-businesses-need-to-know

