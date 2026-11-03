# Daily phishing and identity campaigns

- **Report date:** 2026-11-02
- **Sources:** ketch OSINT (3 queries)

## The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime | Microsoft Security Blog

**PIR:** 1.d

Microsoft Security researchers dissect the sprawling infrastructure ecosystem that underpins modern phishing campaigns. The report details how threat actors leverage compromised legitimate domains, cloud hosting services, and dynamic DNS providers to rapidly deploy and rotate phishing pages. Defenders gain actionable insights into tracking infrastructure footprints, identifying shared hosting patterns, and implementing proactive takedown strategies to disrupt the supply chain before credentials 

Source: https://www.microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime/

## Joint advisory: state-sponsored spear-phishing campaigns targeting ...

**PIR:** 1.e

A Five Eyes joint advisory warns of ongoing state-sponsored spear-phishing campaigns specifically targeting energy, transport, and water sectors. The report outlines attacker TTPs, including highly tailored lures, malicious document attachments, and credential harvesting portals. Critical infrastructure operators are advised to review email filtering rules, enforce strict conditional access policies, and monitor for anomalous authentication attempts to mitigate identity compromise risks.

Source: https://suvat.uk/blog/five-eyes-advisory.html

## Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale | Microsoft Security Blog

**PIR:** 1.b

This analysis exposes the Tycoon2FA kit, a sophisticated Adversary-in-the-Middle tool that bypasses multi-factor authentication by proxying real-time sessions between victims and legitimate services. The article breaks down the kit architecture, automation capabilities, and deployment tactics. Infrastructure defenders learn how to detect proxy traffic patterns, identify malicious reverse-proxy configurations, and enforce session-binding controls to neutralize AiTM attacks.

Source: https://www.microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale/

## Inside Wazza: A Newly Observed Device Code Phishing Kit Targeting Microsoft 365 Accounts

**PIR:** 1.c

Level Blue researchers analyze the Wazza kit, a novel device code phishing tool designed to bypass MFA by tricking users into authorizing attacker-controlled sessions. The article details the kit user interface, backend token exchange mechanisms, and distribution methods. Defenders receive guidance on monitoring for suspicious device code authorization requests, blocking malicious redirect URIs, and educating users on recognizing device code prompts.

Source: https://www.levelblue.com/blogs/spiderlabs-blog/inside-wazza-a-newly-observed-device-code-phishing-kit-targeting-microsoft-365-accounts

## Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Security Blog

**PIR:** 1.c

Microsoft Security investigates EvilTokens, a prevalent device code phishing framework that exploits OAuth 2.0 device authorization flows. The report explains how attackers harvest valid tokens without requiring passwords or MFA codes. Infrastructure teams are provided with detection queries for Azure AD logs, recommendations for restricting device code grant types, and strategies to implement token binding to prevent session hijacking.

Source: https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.f

This Microsoft Security blog post examines a campaign leveraging generative AI to automate device code phishing at scale. Attackers use AI to craft highly convincing prompts, dynamically generate landing pages, and adapt messaging in real-time. The article highlights infrastructure indicators, AI-generated content detection techniques, and defensive measures such as enhanced URL filtering and user awareness training focused on AI-assisted social engineering.

Source: https://microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026

## Operation HookedWing: Four-Year Phishing Campaign Hits 500 ...

**PIR:** 1.e

SecurityWeek reports on Operation HookedWing, a persistent credential-harvesting campaign active since 2022 targeting aviation, government, and critical infrastructure sectors. The analysis covers the campaign infrastructure evolution, domain registration patterns, and phishing page templates. Defenders are advised to monitor for known malicious domains, implement strict email authentication, and review historical login anomalies for compromised accounts.

Source: https://cybersecurityjournal.ca/techtalk/84066-operation-hookedwing-phishing-aviation-critical-infrastructure-2026-05-11/

## Talos: Attackers Refine Phishing Playbook To Target Critical ...

**PIR:** 1.e

Cisco Talos details how threat actors are refining phishing techniques to specifically target healthcare, local government, and critical infrastructure organizations. The report highlights the abuse of trusted collaboration platforms, cloud storage services, and legitimate SaaS integrations to evade detection. Infrastructure defenders gain insights into identifying malicious OAuth applications, monitoring for unusual API activity, and hardening identity perimeters against evolving phishing tacti

Source: https://securityledger.com/2026/07/talos-attackers-refine-phishing-playbook-to-target-critical-infrastructure/

