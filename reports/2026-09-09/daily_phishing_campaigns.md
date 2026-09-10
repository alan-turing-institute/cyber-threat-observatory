# Daily phishing and identity campaigns

- **Report date:** 2026-09-09
- **Sources:** ketch OSINT (3 queries)

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.c.2

Threat actors are leveraging AI to automate device code phishing at scale, generating live authentication codes on demand. This evolution bypasses traditional MFA controls and enables sustained post-compromise access. Infrastructure defenders must monitor for anomalous device code requests, implement conditional access policies, and deploy AI-driven detection to counter automated credential harvesting.

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## Device Code Phishing is an Evolution in Identity Takeover

**PIR:** 1.b.1

Device code phishing represents a significant shift in identity takeover tactics, exploiting legitimate authentication flows to circumvent multi-factor authentication. Attackers trick users into entering codes on malicious portals, granting threat actors direct token access. Defenders should enforce strict device compliance, monitor for unusual authentication patterns, and educate users on recognizing device code prompts.

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## When checking the URL isn’t enough: phishing via the Microsoft identity platform | Securelist

**PIR:** 1.e.3

Modern phishing campaigns increasingly abuse the Microsoft identity platform, rendering traditional URL inspection insufficient. Attackers leverage legitimate OAuth endpoints and token manipulation to steal credentials and session tokens. IT teams must implement advanced identity protection, enforce app consent policies, and deploy real-time telemetry to detect platform abuse.

Source: https://securelist.com/microsoft-device-code-phishing-attack/120350/

## Device Code Phishing: Turning a Convenience Feature Into an MFA Bypass | Trend Micro (US)

**PIR:** 1.b.4

The device code flow, designed for seamless authentication, is being weaponized to bypass MFA. Attackers host fake login pages that prompt users to enter device codes, effectively hijacking sessions without passwords. Infrastructure security requires tightening conditional access rules, disabling unnecessary device code flows, and monitoring for rapid token issuance.

Source: https://www.trendmicro.com/en_us/research/26/g/device-code-phishing.html

## EvilTokens abuses Microsoft device code flow for account takeovers | CSO Online

**PIR:** 1.e.1

The EvilTokens malware family exploits Microsoft’s device code authentication flow to silently harvest access tokens. By automating the device code exchange, attackers achieve persistent account access while evading traditional login alerts. Defenders should audit token issuance logs, restrict device code usage to managed devices, and deploy endpoint detection for token theft indicators.

Source: https://www.csoonline.com/article/4153742/eviltokens-abuses-microsoft-device-code-flow-for-account-takeovers.html

## Russian hacker group Laundry Bear exploits Zimbra zero-click flaw to target Western government, critical infrastructure

**PIR:** 1.d.1

Laundry Bear leverages a zero-click vulnerability in Zimbra mail servers to infiltrate government and critical infrastructure networks without user interaction. This exploit enables silent data exfiltration and lateral movement. Infrastructure teams must prioritize patching Zimbra deployments, deploy network segmentation, and monitor for anomalous outbound traffic indicative of zero-click compromises.

Source: https://industrialcyber.co/cisa/russian-hacker-group-laundry-bear-exploits-zimbra-zero-click-flaw-to-target-western-government-critical-infrastructure

## PhantomEnigma: How a Malware Crew Turned Brazilian Government Sites Into Trusted Malware Hubs

**PIR:** 1.f.2

The PhantomEnigma group hijacked compromised government websites to distribute malware, leveraging trusted domains to bypass security controls. This infrastructure abuse tactic complicates threat intelligence and endpoint detection. Defenders should implement strict web reputation filtering, monitor for domain hijacking indicators, and isolate critical assets from untrusted networks.

Source: https://securebulletin.com/phantomenigma-how-a-malware-crew-turned-brazilian-government-sites-into-trusted-malware-hubs

## Three Active Microsoft 365 Phishing Campaigns Targeting Schools and Government Agencies

**PIR:** 1.g.1

Coordinated phishing campaigns are actively targeting educational and government sectors using Microsoft 365 infrastructure. Attackers deploy credential harvesting pages and malicious attachments to compromise administrative accounts. IT defenders must prioritize MFA enforcement, segment privileged accounts, and leverage Microsoft Defender for Office 365 to block campaign infrastructure.

Source: https://forsyteit.com/three-active-microsoft-365-phishing-campaigns-targeting-schools-and-government-agencies

