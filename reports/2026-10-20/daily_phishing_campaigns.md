# Daily phishing and identity campaigns

- **Report date:** 2026-10-20
- **Sources:** ketch OSINT (3 queries)

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.i

Threat actors are leveraging AI-driven infrastructure to automate device code phishing campaigns end-to-end, marking a significant escalation in sophistication. This evolution bypasses traditional static scripts, enabling rapid credential harvesting and identity takeover. Defenders must monitor OAuth consent grants and implement conditional access policies to mitigate these automated attacks.

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Security Blog

**PIR:** 1.i

This technical deep dive analyzes the EvilTokens infrastructure, revealing how threat actors automate device code phishing at scale. The campaign utilizes dynamic landing pages and AI-assisted social engineering to maximize success rates. Defenders are advised to review token issuance logs, restrict device code flow usage, and implement zero-trust identity controls.

Source: https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/

## Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US

**PIR:** 1.f

Device code phishing has emerged as a primary vector for identity takeover, exploiting legitimate OAuth flows to bypass multi-factor authentication. Attackers trick users into authorizing malicious apps, granting persistent access to cloud environments. Infrastructure teams should audit consent grants, enforce app registration policies, and deploy identity protection tools.

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## Access granted: phishing with device code authorization for account takeover | Proofpoint US

**PIR:** 1.f

Attackers are increasingly exploiting device code authorization flows to achieve account takeover without traditional credential theft. By prompting users to enter verification codes on attacker-controlled domains, threat actors gain legitimate-looking access tokens. IT infrastructure defenders must monitor for suspicious OAuth consent events and enforce strict app permissions.

Source: https://www.proofpoint.com/us/blog/threat-insight/access-granted-phishing-device-code-authorization-account-takeover

## Storm-2372 conducts device code phishing campaign | Microsoft Security Blog

**PIR:** 1.i

Storm-2372, a state-sponsored threat group, deployed a targeted device code phishing campaign against government and defense contractors. The operation utilized customized landing pages mimicking Microsoft login flows to harvest authorization codes. Defenders should correlate threat intelligence on Storm-2372 infrastructure and enforce conditional access rules.

Source: https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/

## Foreign Threat Actor Conducting Large-Scale Spearphishing Campaign with RDP Attachments | CISA

**PIR:** 1.j

A foreign threat actor is distributing spearphishing emails containing malicious RDP attachments designed to establish remote access to targeted networks. These files exploit user trust in remote desktop protocols to deploy backdoors and exfiltrate credentials. Infrastructure teams must block executable RDP files in email gateways and monitor for unauthorized connections.

Source: https://www.cisa.gov/news-events/alerts/2024/10/31/foreign-threat-actor-conducting-large-scale-spearphishing-campaign-rdp-attachments

## Joint advisory: state-sponsored spear-phishing campaigns targeting critical infrastructure - SUVAT

**PIR:** 1.c

Five Eyes intelligence agencies issued a joint advisory warning of coordinated spear-phishing campaigns targeting energy, transportation, and government sectors. Threat actors use highly tailored lures and credential harvesting sites to infiltrate critical infrastructure networks. Defenders should prioritize email filtering, implement strict identity governance, and participate in threat intelligence sharing.

Source: https://suvat.uk/blog/five-eyes-advisory.html

## Midnight Blizzard conducts large-scale spear-phishing campaign using RDP files | Microsoft Security Blog

**PIR:** 1.j

Midnight Blizzard, linked to Russian state-sponsored activity, launched a widespread spear-phishing campaign leveraging malicious RDP files to compromise organizational networks. The campaign targets IT administrators and helpdesk staff to facilitate lateral movement. Infrastructure defenders must disable RDP file execution via email and enforce multi-factor authentication for remote access.

Source: https://www.microsoft.com/en-us/security/blog/2024/10/29/midnight-blizzard-conducts-large-scale-spear-phishing-campaign-using-rdp-files/

