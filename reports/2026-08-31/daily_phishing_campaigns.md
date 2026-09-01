# Daily phishing and identity campaigns

- **Report date:** 2026-08-31
- **Sources:** ketch OSINT (3 queries)

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.f

Threat actors are leveraging AI to automate device code phishing campaigns, generating live authentication codes on demand to bypass MFA. This evolution enables sustained post-compromise access and higher success rates. Defenders must monitor OAuth consent grants, implement conditional access policies, and deploy AI-driven detection to identify anomalous device code flows before account takeover occurs.

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## A New Era Of Social Engineering: The Device Code Phishing Boom

**PIR:** 1.f

The surge in device code phishing represents a paradigm shift in social engineering, moving from static credential harvesting to dynamic, automated authentication interception. Attackers exploit legitimate OAuth flows to trick users into entering codes, effectively neutralizing traditional MFA. Infrastructure teams should prioritize monitoring for suspicious device code requests, restrict app consent permissions, and educate users on recognizing dynamic code prompts.

Source: https://coalitioninc.com/blog/security-labs/a-new-era-of-social-engineering-the-device-code-phishing-boom

## The Device Code Phishing Tsunami: What We’re Seeing in the Wild

**PIR:** 1.f

Recent telemetry reveals a massive wave of device code phishing attacks targeting enterprise environments. Unlike traditional phishing, these campaigns abuse legitimate authentication endpoints to harvest active sessions. Security operations centers must enhance logging for OAuth device code endpoints, implement strict conditional access rules, and deploy behavioral analytics to detect rapid, automated code validation attempts.

Source: https://www.levelblue.com/blogs/spiderlabs-blog/the-device-code-phishing-tsunami-what-were-seeing-in-the-wild

## Device Code Phishing is an Evolution in Identity Takeover

**PIR:** 1.j

Device code phishing has evolved into a primary vector for identity takeover, allowing attackers to bypass password resets and MFA challenges. By hijacking legitimate authentication flows, threat actors gain persistent access to cloud environments. Defenders should enforce least-privilege access, monitor for unusual OAuth token issuance, and implement continuous authentication monitoring to mitigate identity compromise risks.

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## Device Code Phishing — The Attack That Makes MFA Irrelevant

**PIR:** 1.e

This analysis details how device code phishing renders traditional MFA ineffective by intercepting authentication at the consent stage. Attackers no longer need passwords or push approvals, instead leveraging automated scripts to validate device codes instantly. IT infrastructure teams must transition to phishing-resistant MFA methods, restrict legacy authentication protocols, and deploy real-time alerting for device code endpoint abuse.

Source: https://cybergrind.org/blog/2026-06-02-device-code-phishing

## EvilTokens Abuses Microsoft Device Codes to Hijack Accounts Without Stealing Passwords

**PIR:** 1.f

The EvilTokens campaign demonstrates how attackers abuse Microsoft device codes to hijack accounts without ever capturing passwords. By automating the device code flow, threat actors generate valid access tokens that bypass standard security controls. Defenders should audit OAuth application permissions, monitor for anomalous token generation patterns, and implement strict conditional access policies to prevent silent account takeover.

Source: https://gbhackers.com/microsoft-device-codes-abuse/amp

## Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA

**PIR:** 1.g

CISA has issued a warning regarding the Laundry Bear campaign, which exploits a zero-click vulnerability in Zimbra email servers to deliver phishing payloads. This attack requires no user interaction, making it highly dangerous for unpatched infrastructure. Administrators must immediately apply vendor patches, segment email servers, and deploy network-level detection rules to identify exploitation attempts before lateral movement occurs.

Source: https://tempmail.ninja/blog/laundry-bear-zimbra-phishing

## Three Active Microsoft 365 Phishing Campaigns Targeting Schools and Government Agencies

**PIR:** 1.a

Three active Microsoft 365 phishing campaigns are currently targeting educational and government sectors, leveraging tailored lures to harvest credentials and deploy malware. These campaigns exploit sector-specific workflows to increase click-through rates. Defenders should implement email authentication protocols, deploy URL sandboxing, and conduct targeted user awareness training to mitigate sector-focused phishing threats.

Source: https://forsyteit.com/three-active-microsoft-365-phishing-campaigns-targeting-schools-and-government-agencies

