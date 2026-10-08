# Daily phishing and identity campaigns

- **Report date:** 2026-10-07
- **Sources:** ketch OSINT (3 queries)

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.j

Microsoft details a sophisticated phishing campaign leveraging AI-driven infrastructure to automate the OAuth device code flow. Unlike previous manual scripts, this operation uses end-to-end automation to bypass multi-factor authentication by redirecting victims to legitimate Microsoft login pages. The campaign represents a significant escalation in threat actor sophistication, building on techniques first observed in the Storm-2372 campaign. Defenders are advised to monitor for anomalous device

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## OAuth Device Code Phishing: M365 Defense Guide

**PIR:** 1.j

Protego provides a comprehensive defense guide for mitigating OAuth device code phishing in Microsoft 365 tenants. The resource details step-by-step configurations for Azure AD Conditional Access, including blocking device code flows for guest users and enforcing risk-based authentication. It also covers PowerShell scripts for hunting historical device code grants and integrating detection rules with Microsoft Sentinel for automated incident response.

Source: https://protego.me/blog/oauth-device-code-phishing-mfa-bypass-microsoft-365

## AI-Enabled Device Code Phishing Campaign Abuses Device Code Sign-In Flow

**PIR:** 1.j

CapTech Group analyzes how threat actors exploit the OAuth device code sign-in flow to circumvent MFA protections. The report breaks down the technical mechanics of the attack, highlighting how attackers automate the pairing process to harvest valid access tokens. Infrastructure defenders can use these insights to configure Azure AD sign-in risk policies, detect suspicious device code requests, and deploy real-time alerting for unauthorized token issuance.

Source: https://captechgroup.com/threat-intelligence-center/ai-enabled-device-code-phishing-campaign-abuses-de-81a334

## Device Code Phishing: The MFA Bypass That Uses Microsoft's Own Login Page

**PIR:** 1.e

This guide explains how device code phishing effectively bypasses MFA by leveraging Microsoft’s official authentication portal. Attackers trick users into entering a verification code on a compromised device, granting the threat actor full account access without triggering traditional phishing alerts. The article outlines defensive measures, including user awareness training, conditional access restrictions for device code flows, and monitoring for impossible travel or concurrent session anomali

Source: https://phishingtackle.com/blog/device-code-phishing-mfa-bypass

## Midnight Blizzard-Linked Actor GTG-20006 Automated Device Code Phishing With AI

**PIR:** 1.i

AegisAI attributes an AI-automated device code phishing campaign to GTG-20006, a threat actor linked to Midnight Blizzard. The report highlights how machine learning models optimize phishing lures and automate victim interaction to accelerate token theft. Infrastructure teams are advised to deploy AI-driven threat detection, monitor for rapid sequential device code validations, and restrict OAuth app permissions to minimize blast radius during identity breaches.

Source: https://aegisai.ai/blog/anthropic-midnight-blizzard-ai-device-code-phishing

## The Device Code Phishing Tsunami: What We’re Seeing in the Wild

**PIR:** 1.j

LevelBlue’s SpiderLabs team documents a surge in device code phishing attacks targeting enterprise environments. The analysis covers observed TTPs, including the use of legitimate Microsoft authentication endpoints to validate stolen codes. The article provides actionable detection strategies for SIEM and EDR platforms, emphasizing log correlation for OAuth 2.0 device authorization grants and recommendations for hardening identity perimeters against automated token theft.

Source: https://www.levelblue.com/blogs/spiderlabs-blog/the-device-code-phishing-tsunami-what-were-seeing-in-the-wild

## GhostCode attackers abuse device codes to take over Microsoft 365 accounts

**PIR:** 1.a

Computerworld reports on the GhostCode threat group leveraging device code phishing to compromise Microsoft 365 environments. The campaign targets high-value accounts by combining social engineering with automated token harvesting. Defenders are urged to review audit logs for unusual device code sign-ins, enforce phishing-resistant MFA methods like FIDO2, and implement zero-trust network access controls to limit lateral movement post-compromise.

Source: https://computerworld.com/article/4223889/ghostcode-attackers-abuse-device-codes-to-take-over-microsoft-365-accounts.html

## PhantomEnigma: How a Malware Crew Turned Brazilian Government Sites Into Trusted Malware Hubs

**PIR:** 1.f

SecureBulletin investigates PhantomEnigma’s campaign compromising Brazilian government websites to host malware and phishing infrastructure. By leveraging trusted domains, attackers bypass reputation-based security controls and distribute malicious payloads to unsuspecting users. Defenders should implement strict DNS filtering, monitor for domain hijacking indicators, and validate certificate transparency logs to detect unauthorized subdomain usage in critical infrastructure environments.

Source: https://securebulletin.com/phantomenigma-how-a-malware-crew-turned-brazilian-government-sites-into-trusted-malware-hubs

