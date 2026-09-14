# Daily phishing and identity campaigns

- **Report date:** 2026-09-13
- **Sources:** ketch OSINT (3 queries)

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.i

Microsoft researchers detail a sophisticated campaign leveraging AI to automate device code phishing attacks, bypassing traditional password theft and MFA prompts. Attackers generate fake Microsoft login portals that prompt users to enter device codes, granting threat actors direct OAuth tokens. Defenders must educate users on legitimate device code flows, monitor for anomalous OAuth consent grants, and enforce application consent policies to block unauthorized token issuance.

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## When checking the URL isn’t enough: phishing via the Microsoft identity platform | Securelist

**PIR:** 1.j.3

Kaspersky Securelist reveals how attackers exploit the Microsoft identity platform to host phishing campaigns that appear legitimate, bypassing URL-based filtering. By leveraging trusted Microsoft domains and OAuth flows, threat actors trick users into granting access to malicious applications. Defenders must move beyond URL inspection, implement strict conditional access rules, monitor for unusual app registrations, and enforce multi-factor authentication with phishing-resistant methods like FI

Source: https://securelist.com/microsoft-device-code-phishing-attack/120350/

## Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA

**PIR:** 1.h

Attackers increasingly leverage compromised cloud-native services and serverless functions to host phishing infrastructure, evading traditional perimeter defenses. This report details how threat actors abuse legitimate cloud APIs to dynamically generate malicious landing pages, rotate domains, and maintain persistence. Infrastructure defenders must implement strict egress controls, monitor anomalous API calls, and deploy cloud workload protection platforms to detect and mitigate these stealthy c

Source: https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns

## Device Code Phishing is an Evolution in Identity Takeover

**PIR:** 1.i

Device code phishing has evolved into a primary vector for identity takeover, exploiting the convenience of cross-device authentication to bypass MFA. This analysis tracks how threat actors automate the generation of malicious consent pages and use social engineering to trick users into authorizing attacker-controlled applications. Infrastructure teams should implement strict OAuth consent policies, monitor for suspicious device code requests, and deploy identity threat detection solutions to fl

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## Device Code Phishing: Turning a Convenience Feature Into an MFA Bypass | Trend Micro (US)

**PIR:** 1.d

Trend Micro examines how device code phishing effectively bypasses multi-factor authentication by leveraging legitimate OAuth authorization flows. Attackers trick users into entering codes on compromised portals, granting direct access without triggering traditional MFA prompts. To mitigate this risk, organizations should restrict device code usage to approved applications, deploy identity protection tools that detect anomalous consent requests, and train users to recognize fake authorization pr

Source: https://www.trendmicro.com/en_us/research/26/g/device-code-phishing.html

## Microsoft: Passkey Help Desk Calls Are Hijacking Cloud Accounts, Then Draining SharePoint

**PIR:** 1.e

Threat actors are exploiting help desk support channels to bypass passkey authentication, successfully hijacking Microsoft cloud accounts and exfiltrating sensitive SharePoint data. The campaign relies on social engineering to trick support staff into resetting credentials or approving device registrations. Defenders should enforce strict verification protocols for identity changes, monitor for unusual SharePoint access patterns, and implement conditional access policies that restrict help desk 

Source: https://threat-intelligence.redeyesecurity.com/blog/passkey-phishing-microsoft-cloud-hijack-storm-3032-2026

## PhantomEnigma: How a Malware Crew Turned Brazilian Government Sites Into Trusted Malware Hubs

**PIR:** 1.h

The PhantomEnigma malware crew has compromised Brazilian government websites to distribute malware, leveraging trusted domains to bypass security controls and increase victim trust. This infrastructure abuse highlights the risks of third-party web hosting and inadequate server hardening. Defenders must implement strict web application firewalls, monitor for unauthorized file uploads, enforce least-privilege access on public-facing servers, and collaborate with government CERTs to rapidly takedow

Source: https://securebulletin.com/phantomenigma-how-a-malware-crew-turned-brazilian-government-sites-into-trusted-malware-hubs

## The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations

**PIR:** 1.f

The integration of generative AI has transformed phishing from broad, low-effort campaigns into highly targeted, autonomous operations. Attackers now use AI to craft context-aware emails, dynamically update landing pages, and automate follow-up sequences based on victim behavior. This shift demands advanced email security gateways with AI-driven content analysis, continuous user training focused on behavioral cues, and automated incident response playbooks to counter rapid, adaptive threats.

Source: https://itsecurityguru.org/2026/05/27/the-ai-phishing-revolution-from-spray-and-pray-to-autonomous-operations

