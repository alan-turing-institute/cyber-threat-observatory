# Daily phishing and identity campaigns

- **Report date:** 2026-11-25
- **Sources:** ketch OSINT (3 queries)

## The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime

**PIR:** 1.a

Examines the underground infrastructure supporting global phishing operations, detailing domain generation algorithms, bulletproof hosting networks, and proxy chains used to evade takedowns. Infrastructure defenders can leverage these insights to enhance DNS sinkholing, implement advanced threat intelligence feeds, and harden perimeter defenses against rapidly rotating malicious endpoints.

Source: https://www.microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime/

## Joint advisory: state-sponsored spear-phishing campaigns targeting critical infrastructure

**PIR:** 1.d

Details coordinated Five Eyes intelligence on advanced spear-phishing tactics targeting critical infrastructure sectors. The advisory outlines malicious document payloads, credential harvesting techniques, and lateral movement strategies employed by state actors. Defenders should prioritize email gateway filtering, endpoint detection tuning, and strict access controls for OT/IT convergence points.

Source: https://suvat.uk/blog/five-eyes-advisory.html

## Unmasking EvilTokens: Getting to the root of device code phishing

**PIR:** 1.b

Analyzes the EvilTokens framework, which abuses OAuth device code flows to bypass multi-factor authentication. The report breaks down token interception mechanisms, session hijacking vectors, and mitigation strategies for identity providers. Infrastructure teams must enforce conditional access policies, monitor for anomalous device code requests, and restrict public-facing authentication endpoints.

Source: https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/

## The risks of device code authentication for AI coding agents

**PIR:** 1.c

Explores how AI-driven development tools leverage device code flows, creating new attack surfaces for credential theft and unauthorized access. The article highlights risks of automated agent authentication, token persistence, and supply chain compromise. Defenders should implement strict agent identity management, rotate credentials frequently, and audit AI tool authentication scopes.

Source: https://microsoft.com/en-us/security/blog/2026/11/17/the-risks-of-device-code-authentication-for-ai-coding-agents

## Tracking BigBear 2.0 Evilginx2 Phishing Campaign

**PIR:** 1.b

Chronicles a large-scale phishing campaign utilizing Evilginx2 reverse proxy technology to harvest credentials and session cookies. The analysis covers infrastructure patterns, domain registration tactics, and evasion techniques. Network defenders can improve detection by monitoring for proxy-based traffic anomalies, implementing certificate pinning, and deploying advanced URL filtering.

Source: https://www.cloudsek.com/blog/tracking-bigbear-2-0-evilginx2-phishing-campaign

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.c

Investigates a novel campaign combining generative AI with device code phishing to automate credential harvesting at scale. The report details AI-generated landing pages, dynamic QR code generation, and real-time token forwarding. Identity teams should deploy behavioral analytics, restrict device code usage to trusted networks, and educate users on QR code authentication risks.

Source: https://microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026

## Device Code Phishing: An Evolving Technique Impacting SLTTs

**PIR:** 1.b

Examines how state, local, tribal, and territorial governments face targeted device code phishing attacks exploiting legacy identity systems. The guide provides architectural recommendations for modernizing authentication flows, implementing zero-trust principles, and monitoring for unauthorized device registrations. Infrastructure planners should prioritize identity governance and secure remote access frameworks.

Source: https://cisecurity.org/insights/blog/device-code-phishing-evolving-technique-impacting-sltts

## Storm-2372 conducts device code phishing campaign

**PIR:** 1.f

Documents a persistent threat actor leveraging device code phishing to infiltrate government and defense networks. The analysis covers campaign timelines, infrastructure reuse, and post-compromise tactics. Defenders should correlate authentication logs with threat intelligence, enforce strict MFA policies, and isolate compromised identity accounts immediately.

Source: https://microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign

