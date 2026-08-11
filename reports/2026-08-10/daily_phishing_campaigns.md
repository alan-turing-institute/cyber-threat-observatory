# Daily phishing and identity campaigns

- **Report date:** 2026-08-10
- **Sources:** ketch OSINT (3 queries)

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.i

This campaign combines AI-generated lures with OAuth device code flows to bypass traditional email filters and MFA. Attackers trick users into entering device codes on malicious portals, granting them direct access to corporate accounts. Defenders should monitor for unusual device code authorization requests, restrict OAuth app permissions, and deploy identity threat detection solutions that flag rapid, automated consent grants across cloud directories.

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## Device Code Phishing is an Evolution in Identity Takeover

**PIR:** 1.i

Device code phishing exploits legitimate OAuth flows to harvest valid access tokens, effectively neutralizing password-based MFA. This report outlines the technical mechanics of token theft and lateral movement within cloud environments. IT infrastructure defenders must implement strict OAuth consent policies, monitor for high-privilege token issuance, and deploy identity-aware proxies to validate authentication contexts before granting resource access.

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA

**PIR:** 1.i

Attackers increasingly leverage cloud-native services like serverless functions and object storage to host phishing infrastructure, evading traditional perimeter defenses. This report details how threat actors abuse legitimate cloud APIs to dynamically generate malicious landing pages, rotate domains, and bypass DNS blacklists. Infrastructure defenders must implement cloud workload protection platforms, monitor anomalous API calls, and enforce strict egress filtering to detect and disrupt these 

Source: https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns

## New widespread EvilTokens kit: device code phishing as-a-service

**PIR:** 1.k

The EvilTokens kit has evolved into a full-featured device code phishing-as-a-service platform, enabling low-skill actors to conduct sophisticated identity theft. The infrastructure supports multi-tenant phishing portals and automated token harvesting. Defenders should block known EvilTokens infrastructure, implement zero-trust identity architectures, and enforce just-in-time access controls to limit the blast radius of compromised credentials and stolen OAuth tokens.

Source: https://www.sekoia.com/blog/new-widespread-eviltokens-kit-device-code-phishing-as-a-service-part-1

## Tycoon2FA Returns: PhaaS Platform Survives Law Enforcement Disruption

**PIR:** 1.k

Despite law enforcement takedowns, the Tycoon2FA Phishing-as-a-Service platform has rapidly re-emerged, demonstrating the resilience of modern MaaS ecosystems. The kit facilitates real-time session hijacking and MFA bypass by proxying authentication requests. Infrastructure teams must enforce phishing-resistant MFA standards like FIDO2, monitor for anomalous authentication proxy traffic, and implement conditional access policies that restrict login locations and device compliance to mitigate ses

Source: https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/03/CSA_research_note_Tycoon2FA-PhaaS-resurrection-MaaS-resilience-20260326-csa-styled.pdf

## Inside Kali365, a Device Code Phishing Ecosystem | Huntress

**PIR:** 1.k

Kali365 operates as a comprehensive device code phishing ecosystem, offering attackers ready-made infrastructure, victim tracking, and automated credential harvesting. This analysis reveals how the platform scales identity attacks across multiple cloud providers. Infrastructure teams must integrate threat intelligence feeds tracking Kali365 indicators, monitor cloud audit logs for suspicious consent grants, and enforce strict application allow-listing to prevent unauthorized OAuth integrations.

Source: https://www.huntress.com/blog/kali365-device-code-phishing-kit

## The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations

**PIR:** 1.j

Generative AI has transformed phishing from broad, low-success campaigns into highly targeted, autonomous operations. This analysis explores how LLMs craft context-aware lures, automate multi-stage social engineering, and dynamically adapt to victim responses. Defenders should prioritize AI-driven email security gateways, implement continuous user training focused on AI-generated content detection, and deploy behavioral analytics to identify subtle deviations in communication patterns that signa

Source: https://itsecurityguru.org/2026/05/27/the-ai-phishing-revolution-from-spray-and-pray-to-autonomous-operations

## Storm-2372 conducts device code phishing campaign | Microsoft Security Blog

**PIR:** 1.a

The APT group Storm-2372 has adopted device code phishing to target government and defense contractors, leveraging legitimate Microsoft 365 flows to bypass security controls. This campaign highlights the convergence of state-sponsored threat actors and commercial phishing kits. Defenders should monitor for anomalous device code usage patterns, implement advanced identity protection rules, and conduct regular access reviews to detect and revoke compromised service principals and user tokens.

Source: https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/

