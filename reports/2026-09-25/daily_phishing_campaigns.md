# Daily phishing and identity campaigns

- **Report date:** 2026-09-25
- **Sources:** ketch OSINT (3 queries)

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.j.3

This campaign represents a major escalation in threat actor sophistication, shifting from static scripts to fully AI-driven infrastructure. Attackers automate the entire device code phishing workflow, enabling rapid credential harvesting and token theft at scale. Defenders should monitor for anomalous device code sign-in flows and implement conditional access policies to block suspicious authentications.

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## Microsoft 365: Block Device Code Flow Against GhostCode

**PIR:** 1.j.3

Guidance on mitigating GhostCode’s abuse of the Microsoft 365 device code authentication flow. The article outlines registry and Intune configuration steps to restrict device code sign-ins, reducing exposure to automated credential theft campaigns. Essential reading for administrators managing hybrid or cloud-only environments.

Source: https://windowsforum.com/news/microsoft-365-block-device-code-flow-against-ghostcode.444973?amp=1

## EvilTokens made phishing-as-a-service look easy. Then it got taken down

**PIR:** 1.f

EvilTokens streamlined credential harvesting by offering an AI-powered phishing-as-a-service platform that auto-generated convincing login pages and managed token theft. Following its takedown, threat actors are migrating to decentralized alternatives. Defenders must update detection rules for emerging PaaS variants and enforce multi-factor authentication.

Source: https://securityaffairs.com/199593/cyber-crime/eviltokens-made-phishing-as-a-service-look-easy-then-it-got-taken-down.html

## Microsoft Warns of EvilTokens AI Phishing Service Hijacking Thousands of Accounts

**PIR:** 1.k

Microsoft’s advisory details how EvilTokens leveraged generative AI to bypass traditional phishing filters, resulting in widespread account compromises. The report highlights indicators of compromise, affected tenants, and recommended remediation steps including token revocation and conditional access hardening.

Source: https://gbhackers.com/eviltokens-ai-phishing/amp

## AI-Enabled Device Code Phishing Campaign Abuses Device Code Sign-In Flow

**PIR:** 1.j.3

An analysis of how attackers exploit the device code sign-in flow using AI to automate victim targeting and credential capture. The article provides technical breakdowns of the attack chain, detection queries for Sentinel, and mitigation strategies for enterprise identity administrators.

Source: https://captechgroup.com/threat-intelligence-center/ai-enabled-device-code-phishing-campaign-abuses-de-81a334

## Midnight Blizzard-Linked Actor GTG-20006 Automated Device Code Phishing With AI

**PIR:** 1.j.3

Threat intelligence linking the GTG-20006 actor to automated device code phishing campaigns powered by AI. The report maps infrastructure overlaps with Midnight Blizzard, details TTPs, and offers IOCs for SOC teams to hunt for similar activity in their environments.

Source: https://aegisai.ai/blog/anthropic-midnight-blizzard-ai-device-code-phishing

## PhantomEnigma: How a Malware Crew Turned Brazilian Government Sites Into Trusted Malware Hubs

**PIR:** 1.g

PhantomEnigma compromised official Brazilian government websites to host phishing pages and malware payloads, leveraging institutional trust to bypass user skepticism. The article details the supply chain compromise, persistence mechanisms, and defensive measures for web application firewalls and DNS filtering.

Source: https://securebulletin.com/phantomenigma-how-a-malware-crew-turned-brazilian-government-sites-into-trusted-malware-hubs

## Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA

**PIR:** 1.l

CISA alerts on Laundry Bear’s exploitation of a zero-click vulnerability in Zimbra collaboration servers to deliver phishing payloads. The campaign targets Western government and critical infrastructure sectors. Defenders are urged to patch Zimbra instances immediately and monitor for anomalous email routing or credential exfiltration.

Source: https://tempmail.ninja/blog/laundry-bear-zimbra-phishing

