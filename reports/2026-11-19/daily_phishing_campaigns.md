# Daily phishing and identity campaigns

- **Report date:** 2026-11-19
- **Sources:** ketch OSINT (3 queries)

## Crafty Microsoft Teams Booking Flow Disguises Device Code Phishing | Huntress

**PIR:** 1.b

Huntress researchers uncover a novel tactic where attackers abuse Microsoft Teams meeting booking flows to deliver device code phishing prompts. By embedding malicious verification requests within legitimate calendar invites, threat actors achieve higher user compliance. The article provides detection queries for Teams audit logs, guidance on restricting external booking permissions, and user awareness strategies to identify spoofed scheduling workflows.

Source: https://www.huntress.com/blog/crafty-microsoft-teams-booking-flow-disguises-device-code-phishing

## Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Security Blog

**PIR:** 1.h

This analysis exposes EvilTokens, a sophisticated framework enabling device code phishing that bypasses traditional MFA by hijacking OAuth consent flows. Defenders learn how attackers trick users into entering verification codes on malicious portals, granting them persistent access tokens. The article provides detection rules for Azure AD sign-in logs, conditional access policy hardening, and user education tactics to mitigate this evolving identity threat.

Source: https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/

## Inside an AI‑enabled device code phishing campaign | Microsoft Security Blog

**PIR:** 1.e

Microsoft details a campaign leveraging generative AI to craft highly personalized device code phishing emails that dynamically adapt to target industries and internal communication styles. The report highlights how AI reduces attacker setup time and increases click-through rates. Defenders are advised to deploy AI-driven email classification, monitor for unnatural linguistic patterns, and enforce strict OAuth consent policies to block automated token theft.

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime | Microsoft Security Blog

**PIR:** 1.d

Microsoft researchers dissect the underground infrastructure supporting modern phishing campaigns, revealing how threat actors leverage bulletproof hosting, fast-flux DNS, and compromised legitimate domains to evade takedowns. The report details defensive strategies for infrastructure teams, including passive DNS monitoring, certificate transparency log analysis, and automated sinkholing techniques to disrupt attacker supply chains before credentials are compromised.

Source: https://www.microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime/

## Tracking BigBear 2.0 Evilginx2 Phishing Campaign | CloudSEK

**PIR:** 1.f

CloudSEK tracks the BigBear 2.0 campaign utilizing Evilginx2 to perform advanced proxy-based phishing attacks that capture session cookies and bypass multi-factor authentication. The report outlines network-level indicators, proxy configuration patterns, and behavioral anomalies defenders can monitor. It emphasizes the importance of certificate pinning, session timeout policies, and endpoint detection to neutralize cookie-stealing infrastructure.

Source: https://www.cloudsek.com/blog/tracking-bigbear-2-0-evilginx2-phishing-campaign

## Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US

**PIR:** 1.b

Proofpoint examines how device code phishing has matured from opportunistic scams into a structured identity takeover methodology. Attackers now automate consent requests and deploy realistic landing pages mimicking enterprise SSO portals. The article guides security teams on implementing token revocation workflows, monitoring for anomalous OAuth app registrations, and deploying email filtering rules to block device code prompts.

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## Microsoft 365 device code phishing campaign bypasses password stealing | RL Blog

**PIR:** 1.b

ReversingLabs analyzes a targeted campaign exploiting Microsoft 365 device code flows to bypass traditional credential harvesting. By redirecting users to legitimate Microsoft login pages that prompt for verification codes, attackers obtain valid access tokens without ever capturing passwords. The post provides forensic indicators, proxy detection techniques, and recommendations for restricting device code usage in high-security environments.

Source: https://www.reversinglabs.com/blog/device-code-phishing-campaign

## Joint advisory: state-sponsored spear-phishing campaigns targeting critical infrastructure - SUVAT

**PIR:** 1.c

A Five Eyes joint advisory details coordinated spear-phishing operations targeting critical infrastructure sectors with highly tailored lures and malicious RDP attachments. The report emphasizes threat intelligence sharing, email gateway hardening, and endpoint isolation protocols. Defenders are urged to monitor for anomalous lateral movement post-delivery and implement strict macro execution policies to mitigate initial access risks.

Source: https://suvat.uk/blog/five-eyes-advisory.html

