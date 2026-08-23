# Daily phishing and identity campaigns

- **Report date:** 2026-08-18
- **Sources:** ketch OSINT (3 queries)

## Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale | Microsoft Security Blog

**PIR:** 1.d

Microsoft Security researchers dissect the Tycoon2FA Adversary-in-the-Middle (AiTM) phishing kit, detailing its architecture, proxy mechanisms, and automation capabilities. The report provides infrastructure defenders with actionable indicators of compromise, network traffic patterns, and mitigation strategies to block real-time session hijacking and MFA bypass attempts targeting enterprise environments.

Source: https://www.microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale/

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.e

Microsoft details a novel campaign leveraging AI to automate device code phishing and generate live authentication tokens on demand. The analysis emphasizes how machine learning accelerates account compromise, providing defenders with behavioral detection signatures, identity governance controls, and network segmentation strategies to mitigate AI-driven identity attacks.

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## Inside Kali365, a Device Code Phishing Ecosystem | Huntress

**PIR:** 1.j.3

Huntress analyzes the Kali365 ecosystem, a sophisticated device code phishing framework designed to harvest OAuth tokens and bypass traditional MFA controls. The breakdown covers infrastructure hosting patterns, redirect URI abuse, and detection rules for SIEM and identity protection platforms, helping defenders identify and block token theft campaigns before lateral movement occurs.

Source: https://www.huntress.com/blog/kali365-device-code-phishing-kit

## New widespread EvilTokens kit: device code phishing as-a-service

**PIR:** 1.j.3

Sekoia.io reveals EvilTokens, a phishing-as-a-service platform specializing in device code abuse. The analysis highlights how threat actors monetize OAuth flow exploitation, providing defenders with infrastructure IOCs, domain registration patterns, and conditional access policy recommendations to prevent unauthorized token issuance and persistent identity compromise.

Source: https://www.sekoia.com/blog/new-widespread-eviltokens-kit-device-code-phishing-as-a-service-part-1

## Device Code Phishing Hits 340+ Microsoft 365 Orgs Across Five Countries ...

**PIR:** 1.j.3

This report documents a widespread OAuth abuse campaign compromising over 340 Microsoft 365 tenants. It outlines the technical mechanics of device code phishing, token persistence techniques, and cross-tenant lateral movement risks. IT infrastructure teams receive actionable guidance on auditing consent grants, implementing token lifetime restrictions, and deploying identity threat detection rules.

Source: https://thehackernews.com/2026/03/device-code-phishing-hits-340-microsoft.html

## Device Code Phishing Drives Identity Takeover Risks

**PIR:** 1.j

Gurucul examines how device code phishing has evolved into a primary vector for enterprise identity takeover. The analysis breaks down MFA bypass workflows, corporate validation manipulation, and post-compromise persistence. Defenders are provided with architectural recommendations for zero-trust identity validation, conditional access hardening, and real-time token monitoring to neutralize advanced phishing threats.

Source: https://gurucul.com/latest-threats/device-code-phishing-is-an-evolution-in-identity-takeover/

## Law Enforcement Takes Down Kratos/Sneaky2FA Phishing Service, With an Assist From TrendAI™ | Trend Micro

**PIR:** 1.d

Trend Micro documents the coordinated takedown of the Kratos/Sneaky2FA phishing infrastructure, detailing the service’s role in distributing credential-harvesting kits. The report outlines forensic artifacts, hosting provider patterns, and defensive playbooks for monitoring residual infrastructure, offering IT teams critical insights into emerging phishing-as-a-service supply chains.

Source: https://www.trendmicro.com/en/research/26/g/kratos-takedown.html

## IronToll: Global Government-Impersonation PhaaS | PhishEye

**PIR:** 1.a

PhishEye tracks the IronToll campaign, a global phishing-as-a-service operation impersonating government entities to harvest credentials and deploy malicious payloads. Infrastructure defenders gain visibility into the campaign’s domain generation algorithms, email header spoofing techniques, and recommended DNS sinkhole configurations to disrupt attacker infrastructure at scale.

Source: https://phisheye.com/blog/irontoll-iron-man-phaas-campaign

