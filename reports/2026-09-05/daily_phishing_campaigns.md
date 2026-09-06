# Daily phishing and identity campaigns

- **Report date:** 2026-09-05
- **Sources:** ketch OSINT (3 queries)

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.b.2

Microsoft details a sophisticated phishing campaign leveraging AI-driven infrastructure to automate device code requests. Unlike traditional static scripts, this threat actor utilizes end-to-end automation to bypass multi-factor authentication, marking a significant escalation in operational sophistication. Infrastructure defenders should monitor OAuth consent logs and implement conditional access policies to mitigate automated credential harvesting.

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## The Illicit Consent Grant Part 2: Device-Code Phishing and the AI PhaaS Wave

**PIR:** 1.e.2

SlashID explores the convergence of illicit OAuth consent grants and AI-powered phishing-as-a-service. The analysis highlights how threat actors abuse device code flows to silently harvest identity tokens without user interaction. Defenders must audit third-party application permissions, enforce strict consent policies, and deploy identity threat detection to block automated token theft.

Source: https://slashid.com/blog/illicit-consent-grant-part-2

## A New Era Of Social Engineering: The Device Code Phishing Boom

**PIR:** 1.b.1

Coalition Inc. examines the rapid proliferation of device code phishing as a primary vector for identity compromise. The report outlines how attackers combine social engineering with automated infrastructure to target enterprise users. IT teams are advised to disable unnecessary device code flows, educate users on QR code verification prompts, and integrate identity analytics for real-time anomaly detection.

Source: https://coalitioninc.com/blog/security-labs/a-new-era-of-social-engineering-the-device-code-phishing-boom

## Device Code Phishing — The Attack That Makes MFA Irrelevant

**PIR:** 1.b.2

CyberGrind breaks down how device code phishing effectively neutralizes traditional MFA controls by leveraging legitimate authentication endpoints. The article provides technical indicators of compromise and mitigation strategies for infrastructure teams. Recommendations include implementing phishing-resistant MFA, monitoring for rapid sequential device code approvals, and restricting OAuth scopes to limit lateral movement.

Source: https://cybergrind.org/blog/2026-06-02-device-code-phishing

## The Device Code Phishing Tsunami: What We’re Seeing in the Wild

**PIR:** 1.b.1

LevelBlue shares real-world telemetry from active device code phishing campaigns targeting cloud infrastructure. The analysis reveals patterns in domain registration, hosting infrastructure, and user targeting tactics. Defenders can leverage these insights to update firewall rules, block malicious OAuth redirect URIs, and enhance SIEM correlation rules for suspicious consent grant activities.

Source: https://www.levelblue.com/blogs/spiderlabs-blog/the-device-code-phishing-tsunami-what-were-seeing-in-the-wild

## Device Code Phishing is an Evolution in Identity Takeover

**PIR:** 1.e.1

Proofpoint traces the evolution of identity takeover attacks, highlighting device code phishing as a critical inflection point. The report details how attackers pivot from credential stuffing to consent-based authentication abuse. Infrastructure defenders should prioritize zero-trust identity architectures, enforce just-in-time access, and deploy behavioral analytics to detect anomalous login patterns across hybrid environments.

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## Operation HookedWing: 4-Year Campaign Compromises 500 Orgs - Phishing

**PIR:** 1.g.1

Daily Security Review investigates a persistent, multi-year phishing campaign that successfully infiltrated over 500 organizations. The operation utilized customized lures and infrastructure hopping to evade detection. IT defenders should review historical email logs, assess third-party vendor access, and implement advanced email security gateways with AI-driven threat classification to prevent similar long-term compromises.

Source: https://dailysecurityreview.com/phishing/operation-hookedwing-4-year-campaign-compromises-500-orgs/

## Massive “TrustTrap” Phishing Campaign Exploits Human Perception, Targets Government Services Across US, India, and Beyond

**PIR:** 1.f.1

CyberP1 analyzes the TrustTrap campaign, which weaponizes cognitive biases and realistic UI cloning to target government and critical infrastructure sectors. The attack chain relies on psychological manipulation rather than technical exploits. Defenders should enhance user awareness training, deploy browser isolation for high-risk links, and monitor for anomalous access patterns from geographically inconsistent locations.

Source: https://cyberp1.com/massive-trusttrap-phishing-campaign-exploits-human-perception-targets-government-services-across-us-india-and-beyond/

