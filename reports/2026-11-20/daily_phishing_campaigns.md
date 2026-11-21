# Daily phishing and identity campaigns

- **Report date:** 2026-11-20
- **Sources:** ketch OSINT (3 queries)

## The hidden network: Inside the phishing infrastructure ecosystem ...

**PIR:** 1.c

Microsoft uncovered a Chinese-language cybercriminal ecosystem featuring interconnected phishing kit operators (Storm-2990) and an illicit marketplace (Storm-3119) selling tools for large-scale phishing. Collaborating with global law enforcement, Microsoft’s Digital Crimes Unit facilitated a major disruption of this infrastructure, offering critical insights for defenders monitoring underground tool distribution and phishing-as-a-service networks.

Source: https://www.microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime/

## High volume phishing campaign uses Microsoft 365 outage lures to target ...

**PIR:** 1.f

Threat actors launched a coordinated, high-volume phishing campaign exploiting Microsoft 365 service-health notifications. By disguising malicious emails as legitimate outage alerts, attackers targeted organizations across multiple sectors. Infrastructure defenders should monitor for spoofed service-status domains and reinforce email authentication controls to mitigate this widespread credential-harvesting tactic.

Source: https://www.microsoft.com/en-us/security/blog/2026/11/16/high-volume-phishing-campaign-uses-microsoft-365-outage-lures-target-multiple-industry-sectors-2/

## Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Security Blog

**PIR:** 1.b

Microsoft researchers dissect the EvilTokens campaign, revealing the underlying mechanics of device code phishing that bypasses traditional credential theft. The analysis provides technical indicators, attacker infrastructure details, and defensive recommendations. Infrastructure teams should implement strict OAuth consent policies, monitor for suspicious device code approvals, and deploy token lifecycle management controls.

Source: https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/

## Inside an AI‑enabled device code phishing campaign | Microsoft Security Blog

**PIR:** 1.e

This analysis details a sophisticated phishing campaign leveraging artificial intelligence to automate and personalize device code requests. By bypassing traditional password theft, attackers directly target OAuth authorization flows. Defenders must review conditional access policies, monitor for anomalous device code approvals, and deploy AI-aware detection rules to counter this evolving identity threat.

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## Crafty Microsoft Teams Booking Flow Disguises Device Code Phishing | Huntress

**PIR:** 1.b

Huntress researchers uncover a novel phishing technique that disguises device code requests within legitimate-looking Microsoft Teams booking flows. This tactic exploits user trust in familiar collaboration tools to bypass security awareness. Infrastructure defenders should monitor Teams API abuse, validate booking flow integrations, and educate users on recognizing disguised authorization prompts.

Source: https://www.huntress.com/blog/crafty-microsoft-teams-booking-flow-disguises-device-code-phishing

## Microsoft 365 device code phishing campaign bypasses password stealing | RL Blog

**PIR:** 1.b

ReversingLabs details a widespread Microsoft 365 phishing campaign that sidesteps password harvesting by exploiting device code authorization flows. The article provides actionable detection rules, infrastructure indicators, and configuration hardening steps. Defenders should audit M365 consent policies, restrict device code usage to approved applications, and enhance monitoring for anomalous authentication patterns.

Source: https://www.reversinglabs.com/blog/device-code-phishing-campaign

## Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US

**PIR:** 1.b

Proofpoint examines how device code phishing has evolved into a primary method for identity takeover, circumventing multi-factor authentication and password-based defenses. The report outlines attacker tactics, infrastructure patterns, and mitigation strategies. IT defenders should prioritize monitoring OAuth consent grants and implementing device code approval workflows to secure enterprise identity perimeters.

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

