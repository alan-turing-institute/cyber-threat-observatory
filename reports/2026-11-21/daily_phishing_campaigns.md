# Daily phishing and identity campaigns

- **Report date:** 2026-11-21
- **Sources:** ketch OSINT (3 queries)

## Inside an AI‑enabled device code phishing campaign | Microsoft Security Blog

**PIR:** 1.e

Microsoft researchers detail an AI-enabled device code phishing campaign that dynamically generates convincing consent requests. Machine learning models tailor lures to specific organizational contexts, increasing success rates. Infrastructure teams must integrate AI-driven threat detection, monitor for anomalous OAuth activity, and restrict third-party app registrations to neutralize adaptive phishing tactics.

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## Device Code Phishing Hits 340+ Microsoft 365 Orgs Across Five Countries ...

**PIR:** 1.d

A widespread device code phishing campaign has compromised over 340 Microsoft 365 organizations across five countries since February 2026. By abusing OAuth consent flows, threat actors bypass traditional password protections to hijack persistent access tokens. Defenders must audit delegated permissions, restrict device code authorization endpoints, and implement token lifecycle monitoring to prevent account takeover.

Source: https://thehackernews.com/2026/03/device-code-phishing-hits-340-microsoft.html

## Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Security Blog

**PIR:** 1.d

This deep dive into EvilTokens reveals the underlying mechanics of device code phishing campaigns. Threat actors exploit legitimate Microsoft authentication flows to harvest long-lived tokens, effectively bypassing MFA. Defenders should implement token revocation strategies, monitor for suspicious device code usage patterns, and enforce zero-trust identity controls to limit lateral movement.

Source: https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/

## High volume phishing campaign uses Microsoft 365 outage lures to target ...

**PIR:** 1.g

Microsoft Threat Intelligence identified a coordinated, high-volume phishing campaign leveraging fake Microsoft 365 service-health notifications. Attackers exploit outage rumors to trick users into surrendering credentials. Infrastructure defenders should monitor for anomalous login spikes, validate service status via official channels, and enforce conditional access policies to mitigate credential theft.

Source: https://www.microsoft.com/en-us/security/blog/2026/11/16/high-volume-phishing-campaign-uses-microsoft-365-outage-lures-target-multiple-industry-sectors-2/

## Microsoft 365 device code phishing campaign bypasses password stealing | RL Blog

**PIR:** 1.d

ReversingLabs examines a Microsoft 365 campaign that circumvents traditional password-stealing techniques via device code authorization. By leveraging OAuth consent, attackers gain direct account access without credential harvesting. IT infrastructure teams must prioritize identity-centric defenses, audit consent grants, and deploy real-time alerting for unusual authentication method shifts.

Source: https://www.reversinglabs.com/blog/device-code-phishing-campaign

## Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US

**PIR:** 1.d

Proofpoint analyzes how device code phishing has evolved into a sophisticated identity takeover vector. Attackers now combine social engineering with automated consent manipulation to maintain long-term access. Security teams should deploy advanced email filtering, educate users on OAuth prompts, and enforce strict application consent policies to block unauthorized token issuance.

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## Access granted: phishing with device code authorization for account takeover | Proofpoint US

**PIR:** 1.d

Proofpoint explores how device code authorization phishing enables seamless account takeover. Attackers manipulate users into approving malicious OAuth requests, granting persistent access. Security operations should enforce application consent workflows, restrict device code endpoints, and implement behavioral analytics to detect and block unauthorized identity delegation attempts.

Source: https://www.proofpoint.com/us/blog/threat-insight/access-granted-phishing-device-code-authorization-account-takeover

## DHS: Spear Phishing Campaign Targeted 11 Energy Sector Firms

**PIR:** 1.h

DHS reports a targeted spear phishing campaign aimed at 11 energy sector firms, highlighting persistent threats to critical infrastructure. Attackers use tailored lures to compromise operational technology networks. Defenders must segment OT/IT environments, enforce strict email security gateways, and maintain incident response playbooks specific to sector-specific identity threats.

Source: https://securityweek.com/dhs-spear-phishing-campaign-targeted-11-energy-sector-firms

