# Daily phishing and identity campaigns

- **Report date:** 2026-08-25
- **Sources:** ketch OSINT (3 queries)

## OAuth Device Code Phishing: 37x Surge in Enterprise ATO

**PIR:** 1.c.2

Enterprise account takeover campaigns leveraging OAuth device code flows have surged 37x, exploiting legitimate authentication mechanisms to bypass traditional MFA controls. Attackers deploy convincing login portals that prompt users to enter device codes, granting threat actors direct session tokens without credential theft. Infrastructure defenders must monitor for anomalous OAuth consent grants, enforce conditional access policies, and deploy real-time alerting for device code authentication 

Source: https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/04/CSA_research_note_oauth-device-code-phishing-surge_20260405-csa-styled.pdf

## Device Code Phishing — The Attack That Makes MFA Irrelevant

**PIR:** 1.c.1

Device code phishing represents a critical evolution in identity compromise, effectively neutralizing multi-factor authentication by hijacking the OAuth 2.0 device authorization grant. Threat actors host spoofed portals requesting users to input codes from corporate devices, instantly capturing valid access tokens. Defenders should implement strict OAuth scope restrictions, monitor for high-velocity device code validations, and educate users on recognizing legitimate device authorization prompts

Source: https://cybergrind.org/blog/2026-06-02-device-code-phishing

## Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA

**PIR:** 1.d.1

Modern phishing operations increasingly leverage cloud-native services like serverless functions, object storage, and managed DNS to host malicious infrastructure at scale. This approach reduces detection latency, complicates takedown efforts, and mimics legitimate traffic patterns. Infrastructure teams must implement cloud workload protection platforms, enforce strict egress filtering, and deploy behavioral analytics to identify anomalous cloud resource provisioning tied to phishing domains.

Source: https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns

## The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations

**PIR:** 1.e.1

Generative AI has transformed phishing from broad, low-yield campaigns into highly targeted, autonomous operations capable of real-time content adaptation and multi-language deployment. Threat actors utilize AI to craft context-aware lures, automate infrastructure provisioning, and dynamically adjust payloads based on victim responses. Defenders must shift from signature-based detection to behavioral analytics, implement AI-driven email security gateways, and enforce zero-trust email handling pr

Source: https://itsecurityguru.org/2026/05/27/the-ai-phishing-revolution-from-spray-and-pray-to-autonomous-operations

## Tycoon2FA Returns: PhaaS Platform Survives Law Enforcement Disruption

**PIR:** 1.f.1

The Tycoon2FA phishing-as-a-service platform has re-emerged following a major law enforcement takedown, demonstrating the resilience and decentralized architecture of modern PhaaS ecosystems. Operators now utilize distributed cloud hosting, encrypted communication channels, and automated infrastructure rotation to maintain service continuity. Infrastructure defenders should monitor known PhaaS infrastructure patterns, block associated C2 domains, and enforce strict MFA phishing-resistant standar

Source: https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/03/CSA_research_note_Tycoon2FA-PhaaS-resurrection-MaaS-resilience-20260326-csa-styled.pdf

## The Procurement Trap: Inside an AiTM Campaign Targeting Global Institutions

**PIR:** 1.g.1

Attackers are weaponizing procurement workflows to deploy advanced-in-the-middle (AiTM) phishing kits that intercept and relay authentication sessions in real-time. By mimicking vendor portals and purchase order systems, threat actors bypass MFA and extract session cookies from high-value targets. Defenders must implement procurement-specific email filtering, enforce hardware-backed authentication, and deploy session token monitoring to detect active AiTM relay attacks.

Source: https://www.hendryadrian.com/the-procurement-trap-inside-an-aitm-campaign-targeting-global-institutions/

## Spearphishing Campaign Abuses npm Registry to Target Critical Infrastructure Sales Teams | Mallory

**PIR:** 1.g.2

A sophisticated spearphishing campaign is exploiting the npm registry to distribute malicious packages disguised as legitimate development tools, specifically targeting sales and engineering teams within critical infrastructure sectors. The malware establishes persistent backdoors and exfiltrates internal network maps. Infrastructure teams should enforce strict package integrity verification, implement software bill of materials tracking, and isolate development environments from production netw

Source: https://mallory.ai/stories/019b5374-9b37-7ddb-9b5b-5a7226c9e64f

## CISA and partners publish joint advisory on Russia- ...

**PIR:** 1.h.1

A joint CISA advisory details a state-sponsored phishing campaign utilizing highly customized lures and advanced evasion techniques to target government and defense contractors. The operation employs living-off-the-land binaries and encrypted C2 channels to maintain persistence. Defenders should review CISA mitigation guidance, patch exposed services, enhance endpoint detection rules for LOLBin abuse, and monitor for anomalous outbound traffic to known threat actor infrastructure.

Source: https://insidecybersecurity.com/daily-news/cisa-and-partners-publish-joint-advisory-russia-sponsored-sophisticated-phishing-campaign

