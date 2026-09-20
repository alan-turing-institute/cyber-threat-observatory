# Daily phishing and identity campaigns

- **Report date:** 2026-09-19
- **Sources:** ketch OSINT (3 queries)

## GhostCode: Dissecting a Novel Device Code Phishing Kit | eSentire

**PIR:** 1.f

eSentire researchers dissect GhostCode, a novel device code phishing kit that automates Microsoft identity takeover. The kit leverages AI to generate convincing prompts, bypassing traditional URL validation. Infrastructure defenders should monitor for unauthorized OAuth consent grants and implement conditional access policies that restrict device code flows to managed devices.

Source: https://www.esentire.com/blog/ghostcode-dissecting-a-novel-device-code-phishing-kit

## Russian hacker group Laundry Bear exploits Zimbra zero-click flaw to target Western government, critical infrastructure

**PIR:** 1.j.3

Industrial Cyber details how the Russian group Laundry Bear exploits a zero-click Zimbra vulnerability to target Western government and critical infrastructure. The campaign requires no user interaction, automatically delivering payloads via compromised email servers. Infrastructure defenders should prioritize patching Zimbra instances, segment email systems, and monitor for lateral movement indicators.

Source: https://industrialcyber.co/cisa/russian-hacker-group-laundry-bear-exploits-zimbra-zero-click-flaw-to-target-western-government-critical-infrastructure

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.g

Microsoft details an AI-enabled device code phishing campaign that dynamically adapts lures based on victim interaction. Attackers exploit the convenience of device code authentication to harvest valid tokens without triggering MFA prompts. Defenders must enforce strict conditional access rules, monitor for anomalous token issuance, and educate users on verifying device code requests.

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## When checking the URL isn’t enough: phishing via the Microsoft identity platform | Securelist

**PIR:** 1.h

Kaspersky Securelist explains why URL validation fails against modern Microsoft identity platform phishing. Attackers use legitimate OAuth endpoints to harvest credentials and tokens, making traditional link inspection ineffective. Infrastructure defenders must shift focus to token telemetry, conditional access policies, and behavioral analytics to detect identity compromise.

Source: https://securelist.com/microsoft-device-code-phishing-attack/120350/

## Device Code Phishing is an Evolution in Identity Takeover

**PIR:** 1.f

Proofpoint analyzes how device code phishing has evolved into a primary identity takeover vector. By redirecting users to legitimate Microsoft login pages, attackers bypass traditional phishing filters and MFA. IT teams should deploy token-based conditional access, restrict device code usage to corporate networks, and implement continuous authentication monitoring.

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## Device Code Phishing: Turning a Convenience Feature Into an MFA Bypass | Trend Micro (US)

**PIR:** 1.f

Trend Micro examines how device code phishing turns a user convenience feature into a reliable MFA bypass. Attackers trick users into entering codes on malicious sites, granting full account access. Defenders should disable unnecessary device code flows, enforce risk-based conditional access, and monitor for impossible travel or rapid token usage patterns.

Source: https://www.trendmicro.com/en_us/research/26/g/device-code-phishing.html

## Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA

**PIR:** 1.h

CYFIRMA reports on phishing campaigns abusing cloud-native infrastructure to host dynamic landing pages and evade takedowns. Attackers leverage serverless functions and CDN networks to scale operations rapidly. Infrastructure teams must implement DNS sinkholing, monitor cloud resource creation anomalies, and enforce strict egress filtering to disrupt campaign infrastructure.

Source: https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns

## The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations

**PIR:** 1.g

IT Security Guru explores the shift from mass phishing to autonomous, AI-driven campaigns. Machine learning models now generate personalized lures, optimize send times, and adapt to security controls in real time. Defenders must prioritize behavioral analytics, zero-trust identity architectures, and automated threat response to counter adaptive phishing ecosystems.

Source: https://itsecurityguru.org/2026/05/27/the-ai-phishing-revolution-from-spray-and-pray-to-autonomous-operations

