# Daily phishing and identity campaigns

- **Report date:** 2026-09-06
- **Sources:** ketch OSINT (3 queries)

## OAuth Device Code Phishing: 37x Surge in Enterprise ATO

**PIR:** 1.g

Enterprise account takeover attacks have surged 37x due to OAuth device code phishing, exploiting the Device Authorization Grant flow to bypass traditional MFA. Threat actors leverage automated toolkits to generate live authentication codes, enabling persistent token hijacking. Infrastructure defenders must monitor OAuth consent logs, restrict device code grant scopes, and implement conditional access policies that validate device posture and user context to mitigate this rapidly scaling identit

Source: https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/04/CSA_research_note_oauth-device-code-phishing-surge_20260405-csa-styled.pdf

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.h

Microsoft researchers detail a sophisticated campaign combining AI-generated lures with automated device code phishing to scale account compromises. Attackers dynamically generate authentication codes on demand, bypassing password theft and sustaining post-compromise access. Defenders should prioritize real-time OAuth token monitoring, deploy AI-driven anomaly detection for consent requests, and enforce strict conditional access rules to neutralize these autonomous identity takeover attempts.

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## Device Code Phishing is an Evolution in Identity Takeover

**PIR:** 1.d

Device code phishing represents a critical evolution in identity compromise, manipulating corporate validation workflows to bypass multi-factor authentication. Publicly released toolkits and PhaaS offerings have democratized access to these techniques, enabling rapid scaling across enterprises. Security leaders must audit OAuth application permissions, deploy user-aware conditional access policies, and educate staff on recognizing device code prompts to prevent widespread account takeovers.

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA

**PIR:** 1.g

Modern phishing operations increasingly exploit cloud-native services like serverless functions, object storage, and container registries to host malicious payloads and evade traditional perimeter defenses. By leveraging ephemeral infrastructure, threat actors reduce detection windows and complicate takedown efforts. IT defenders must implement cloud workload protection platforms, enforce strict IAM policies, and monitor for anomalous API calls to secure cloud environments against infrastructure

Source: https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns

## Tycoon2FA Returns: PhaaS Platform Survives Law Enforcement Disruption

**PIR:** 1.i

Despite law enforcement takedowns, the Tycoon2FA Phishing-as-a-Service platform has resurfaced, demonstrating the resilience of criminal MaaS ecosystems. The service provides attackers with ready-made 2FA bypass tools, credential harvesting dashboards, and automated campaign management. Defenders should monitor for known PhaaS infrastructure indicators, enforce hardware-backed MFA, and implement continuous authentication monitoring to disrupt these persistent identity theft networks.

Source: https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/03/CSA_research_note_Tycoon2FA-PhaaS-resurrection-MaaS-resilience-20260326-csa-styled.pdf

## Microsoft 365 Device Code Phishing Campaign Bypasses Password Theft ...

**PIR:** 1.d

ReversingLabs analysts document an active campaign leveraging Microsoft’s Device Authorization Grant flow to execute near-invisible account takeovers. Attackers combine realistic business-themed lures with polished phishing kits, eliminating the need for password theft. Infrastructure defenders should prioritize OAuth consent logging, restrict third-party app integrations, and implement zero-trust identity validation to block these sophisticated MFA-bypass techniques.

Source: https://cybersecuritynews.com/microsoft-365-device-code-phishing-campaign/

## The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations

**PIR:** 1.h

Phishing campaigns have evolved from broad, low-success-rate blasts to highly targeted, AI-driven autonomous operations. Machine learning models now craft personalized lures, optimize send times, and dynamically adapt to security controls. Infrastructure teams must shift from signature-based filtering to behavioral analytics, deploy AI-resistant email authentication protocols, and train users to recognize context-aware social engineering to counter these next-generation threats.

Source: https://itsecurityguru.org/2026/05/27/the-ai-phishing-revolution-from-spray-and-pray-to-autonomous-operations

## Nation-State Hackers Deploy AI-Assisted Spear Phishing Against Critical Infrastructure — CyberJeneration

**PIR:** 1.a

Nation-state actors are weaponizing AI to craft highly targeted spear-phishing campaigns against critical infrastructure sectors. These operations leverage automated reconnaissance, language modeling, and dynamic content generation to bypass traditional email security. Defenders must implement advanced threat intelligence feeds, deploy AI-driven email filtering, enforce strict network segmentation, and conduct regular red-team exercises to harden critical systems against state-sponsored identity

Source: https://cyberjeneration.com/news/my-first-article/

