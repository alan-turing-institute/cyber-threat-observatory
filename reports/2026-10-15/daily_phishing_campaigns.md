# Daily phishing and identity campaigns

- **Report date:** 2026-10-15
- **Sources:** ketch OSINT (3 queries)

## Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Security Blog

**PIR:** 1.b

Microsoft investigates the EvilTokens infrastructure driving widespread device code phishing campaigns. The blog reveals how threat actors automate token harvesting at scale, exploiting legitimate OAuth flows to maintain persistent access. Recommendations include implementing token-bound policies, monitoring for suspicious device code requests, and deploying identity protection alerts to revoke compromised sessions immediately.

Source: https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/

## Inside an AI‑enabled device code phishing campaign | Microsoft Security Blog

**PIR:** 1.j.3

Microsoft details a sophisticated campaign leveraging AI-generated lures to bypass traditional filters and trick users into authorizing device code flows. Attackers exploit OAuth consent mechanisms to silently harvest valid tokens, enabling persistent access without credential theft. Defenders should monitor for anomalous consent grants, enforce conditional access policies, and deploy AI-aware detection models to identify synthetic phishing infrastructure.

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US

**PIR:** 1.b

Proofpoint analyzes how device code phishing has matured into a primary vector for identity takeover. Unlike traditional credential harvesting, this method forces users to manually enter authorization codes, granting attackers direct token access. The report outlines TTPs, infrastructure patterns, and mitigation strategies including MFA fatigue defenses, token lifecycle management, and user awareness training focused on consent prompts.

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## Access granted: phishing with device code authorization for account takeover | Proofpoint US

**PIR:** 1.b

This analysis breaks down the mechanics of device code authorization phishing, where attackers host fake login portals prompting victims to input codes from secondary devices. Successful grants yield valid OAuth tokens that bypass MFA. The article provides detection rules for SIEM platforms, recommends restricting app consent permissions, and highlights the growing prevalence of this technique across enterprise environments.

Source: https://www.proofpoint.com/us/blog/threat-insight/access-granted-phishing-device-code-authorization-account-takeover

## Storm-2372 conducts device code phishing campaign | Microsoft Security Blog

**PIR:** 1.b

Microsoft attributes a targeted device code phishing campaign to the Storm-2372 threat group. The actors leverage customized landing pages and social engineering to trick users into authorizing malicious apps. The report details campaign infrastructure, targeted sectors, and defensive measures such as blocking unknown app registrations and enforcing strict conditional access rules for high-value accounts.

Source: https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/

## Foreign Threat Actor Conducting Large-Scale Spearphishing Campaign with RDP Attachments | CISA

**PIR:** 1.d

CISA warns of a foreign threat actor distributing spearphishing emails containing malicious RDP files designed to establish unauthorized remote access. The campaign targets government and enterprise networks, exploiting weak endpoint protections. Defenders are advised to block RDP file execution via email gateways, monitor for unexpected remote connections, and enforce network segmentation to limit lateral movement.

Source: https://www.cisa.gov/news-events/alerts/2024/10/31/foreign-threat-actor-conducting-large-scale-spearphishing-campaign-rdp-attachments

## Midnight Blizzard conducts large-scale spear-phishing campaign using RDP files | Microsoft Security Blog

**PIR:** 1.d

Microsoft tracks Midnight Blizzard’s large-scale spearphishing campaign utilizing malicious RDP files to compromise enterprise networks. The threat actor leverages stolen credentials and remote access tools to establish persistence. Defenders should prioritize blocking RDP file downloads, monitoring for anomalous remote desktop sessions, and enforcing multi-factor authentication across all administrative accounts.

Source: https://www.microsoft.com/en-us/security/blog/2024/10/29/midnight-blizzard-conducts-large-scale-spear-phishing-campaign-using-rdp-files/

## Sophisticated Spearphishing Campaign Targets Government Organizations, IGOs, and NGOs | CISA

**PIR:** 1.c

CISA details a sophisticated spearphishing operation targeting government bodies, international organizations, and NGOs. Attackers use highly tailored lures and credential harvesting portals to gain initial access. The advisory recommends implementing email authentication protocols, restricting external sharing, and deploying advanced threat protection to detect and block malicious attachments and links.

Source: https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-148a

