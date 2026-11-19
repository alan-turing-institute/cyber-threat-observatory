# Daily phishing and identity campaigns

- **Report date:** 2026-11-17
- **Sources:** ketch OSINT (3 queries)

## Joint advisory: state-sponsored spear-phishing campaigns targeting critical infrastructure - SUVAT

**PIR:** 1.f.1

A Five Eyes joint advisory detailing coordinated state-sponsored spear-phishing operations aimed at energy, transportation, and utilities sectors. The campaigns utilize highly tailored lures and advanced evasion techniques to infiltrate operational technology networks. Infrastructure defenders should prioritize email filtering, network segmentation, and threat intelligence sharing to counter these high-impact threats.

Source: https://suvat.uk/blog/five-eyes-advisory.html

## Device Code Phishing is an Evolution in Identity Takeover

**PIR:** 1.c.1

Explores how threat actors are leveraging device code authentication flows to bypass traditional multi-factor authentication. This technique represents a significant evolution in identity takeover campaigns, allowing attackers to silently approve login requests on victim devices. IT defenders must monitor for anomalous device code approvals and implement conditional access policies to mitigate silent credential theft.

Source: https://proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## Access granted: phishing with device code authorization for account takeover

**PIR:** 1.c.2

Details a sophisticated phishing campaign that manipulates users into authorizing device code login requests. By mimicking legitimate service notifications, attackers trick victims into entering codes that grant immediate account access. This method bypasses password resets and traditional MFA prompts, requiring infrastructure teams to deploy real-time alerting for unusual device code validation patterns.

Source: https://proofpoint.com/us/blog/threat-insight/access-granted-phishing-device-code-authorization-account-takeover

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.d.1

Analyzes a coordinated campaign combining generative AI with device code phishing tactics. Attackers use AI to craft highly personalized prompts and automate victim targeting, significantly increasing conversion rates. The report highlights technical indicators and mitigation strategies for security operations centers to detect AI-driven social engineering targeting identity providers.

Source: https://microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026

## Unmasking EvilTokens: Getting to the root of device code phishing

**PIR:** 1.c.3

Investigates the EvilTokens infrastructure behind widespread device code phishing operations. The analysis reveals how attackers harvest and replay authentication tokens to maintain persistent access. IT defenders are advised to implement token binding, enforce short-lived session policies, and monitor for token reuse anomalies across identity management platforms.

Source: https://microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing

## The risks of device code authentication for AI coding agents

**PIR:** 1.d.2

Examines the emerging attack surface where AI coding agents interact with device code authentication prompts. Attackers are exploiting automated workflows to trick AI agents into approving malicious device codes, leading to compromised developer accounts and supply chain risks. Defenders should restrict AI agent permissions and enforce human-in-the-loop verification for sensitive authentication events.

Source: https://microsoft.com/en-us/security/blog/2026/11/17/the-risks-of-device-code-authentication-for-ai-coding-agents?WT.mc_id=AZ-MVP-5004796

## Foreign Threat Actor Conducting Large-Scale Spearphishing Campaign with RDP Attachments | CISA

**PIR:** 1.g.1

Alerts on a large-scale spearphishing campaign distributing malicious RDP files to bypass email security controls. Attackers leverage these attachments to establish remote access and deploy credential harvesters. Infrastructure teams must block executable RDP files at the gateway, enforce endpoint detection for unauthorized remote connections, and monitor for lateral movement indicators.

Source: https://www.cisa.gov/news-events/alerts/2024/10/31/foreign-threat-actor-conducting-large-scale-spearphishing-campaign-rdp-attachments

## Sophisticated Spearphishing Campaign Targets Government Organizations, IGOs, and NGOs | CISA

**PIR:** 1.e.2

Covers a targeted spearphishing campaign exploiting geopolitical events to compromise government and non-governmental organizations. The attack chain features custom malware and credential harvesting portals designed to mimic official portals. Defenders should enhance URL filtering, conduct security awareness training focused on current events, and monitor for anomalous authentication attempts from high-value targets.

Source: https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-148a

