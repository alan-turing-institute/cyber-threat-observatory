# Daily phishing and identity campaigns

- **Report date:** 2026-11-05
- **Sources:** ketch OSINT (3 queries)

## Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale

**PIR:** 1.a

Tycoon2FA has emerged as a dominant phishing-as-a-service platform, facilitating adaptive identity threat management campaigns targeting over 500,000 organizations monthly. Microsoft’s Digital Crimes Unit collaborated with Europol to dismantle its infrastructure. This report details the kit’s architecture, proxy mechanisms, and operational scale, offering critical insights for defenders monitoring credential theft and session hijacking threats.

Source: https://www.microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale/

## Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Security Blog

**PIR:** 1.b

EvilTokens represents a sophisticated evolution in device code phishing, exploiting OAuth 2.0 device authorization flows to bypass traditional MFA. This analysis dissects the kit’s infrastructure, token harvesting techniques, and deployment patterns. Infrastructure defenders can leverage these findings to implement stricter conditional access policies, monitor anomalous device code requests, and mitigate identity takeover risks across cloud environments.

Source: https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/

## Inside an AI‑enabled device code phishing campaign | Microsoft Security Blog

**PIR:** 1.j.3

This campaign demonstrates how threat actors integrate generative AI to automate and personalize device code phishing attacks. By dynamically generating convincing prompts and managing OAuth flows at scale, attackers significantly increase success rates. The report outlines detection signatures, AI-driven behavioral patterns, and defensive strategies for identity protection teams to counter automated, intelligent phishing infrastructure.

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## Joint advisory: state-sponsored spear-phishing campaigns targeting critical infrastructure - SUVAT

**PIR:** 1.c

This Five Eyes joint advisory outlines coordinated state-sponsored spear-phishing campaigns specifically targeting critical infrastructure sectors. It details infrastructure indicators, malicious attachment types, and defensive recommendations. IT infrastructure defenders should prioritize email gateway hardening, attachment sandboxing, and identity monitoring to mitigate high-impact, nation-state-driven phishing operations.

Source: https://suvat.uk/blog/five-eyes-advisory.html

## Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US

**PIR:** 1.b

Proofpoint examines how device code phishing has matured into a primary vector for identity takeover, circumventing passwordless and MFA controls. The article details attack lifecycles, infrastructure indicators, and mitigation frameworks. IT defenders gain actionable guidance on configuring identity providers, implementing token binding, and deploying behavioral analytics to detect and block OAuth abuse campaigns targeting enterprise environments.

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## Storm-2372 conducts device code phishing campaign | Microsoft Security Blog

**PIR:** 1.c

Storm-2372, a state-sponsored threat actor, leveraged device code phishing to compromise targeted organizations. This Microsoft Security Blog post details the campaign’s infrastructure, luring techniques, and post-compromise objectives. Defenders can use the provided IOCs and TTPs to enhance email filtering, monitor for suspicious OAuth consent requests, and strengthen identity governance against advanced persistent threats.

Source: https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/

## Foreign Threat Actor Conducting Large-Scale Spearphishing Campaign with RDP Attachments | CISA

**PIR:** 1.c

CISA warns of a large-scale spearphishing campaign utilizing malicious RDP attachments to establish remote access. The alert provides technical indicators, attack methodology, and mitigation steps. Infrastructure teams should block RDP file execution via email, enforce application control policies, and monitor for unauthorized remote desktop connections to prevent initial access and lateral movement.

Source: https://www.cisa.gov/news-events/alerts/2024/10/31/foreign-threat-actor-conducting-large-scale-spearphishing-campaign-rdp-attachments

## New APT group breached gov and critical infrastructure orgs in 37 countries | CSO Online

**PIR:** 1.c

A newly identified APT group has successfully breached government and critical infrastructure organizations across 37 nations. The article summarizes the group’s phishing techniques, infrastructure footprint, and operational scope. Infrastructure defenders should review cross-border threat intelligence, harden identity perimeters, and implement zero-trust architectures to defend against widespread, multi-vector APT campaigns.

Source: https://www.csoonline.com/article/4128378/new-apt-group-breached-gov-and-critical-infrastructure-orgs-in-37-countries.html

