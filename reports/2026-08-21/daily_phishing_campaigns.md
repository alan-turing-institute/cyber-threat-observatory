# Daily phishing and identity campaigns

- **Report date:** 2026-08-21
- **Sources:** ketch OSINT (3 queries)

## OAuth Device Code Phishing: 37x Surge in Enterprise ATO

**PIR:** 1.f

Enterprise account takeover incidents have surged 37x due to OAuth device code phishing. Attackers exploit the Device Authorization Grant flow to bypass traditional password theft and MFA. This report details infrastructure indicators, token persistence mechanisms, and mitigation strategies for identity administrators managing cloud environments.

Source: https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/04/CSA_research_note_oauth-device-code-phishing-surge_20260405-csa-styled.pdf

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.g

A new wave of device code phishing shows how threat actors are scaling account compromise using AI and end‑to‑end automation. This campaign goes beyond traditional phishing by generating live authentication codes on demand, enabling higher success rates and sustained post‑compromise access. Defenders should monitor for anomalous OAuth consent grants.

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## Microsoft 365 Device Code Phishing Campaign Bypasses Password Theft ...

**PIR:** 1.f

Analysts at ReversingLabs identified and documented this active campaign, noting that it combines realistic business-themed lure emails, a polished phishing kit, and Microsoft's own Device Authorization Grant flow to carry out a near-invisible account takeover. Infrastructure teams must implement conditional access policies that restrict device code flows.

Source: https://cybersecuritynews.com/microsoft-365-device-code-phishing-campaign/

## Tycoon2FA Returns: PhaaS Platform Survives Law Enforcement Disruption

**PIR:** 1.j.2

The Tycoon2FA Phishing-as-a-Service platform has resurfaced following law enforcement takedowns, demonstrating remarkable infrastructure resilience. The updated MaaS architecture leverages decentralized hosting and automated 2FA interception proxies. Security operations centers should update threat intelligence feeds to block newly registered C2 domains.

Source: https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/03/CSA_research_note_Tycoon2FA-PhaaS-resurrection-MaaS-resilience-20260326-csa-styled.pdf

## Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA

**PIR:** 1.f

Modern phishing operations increasingly leverage cloud-native services like serverless functions, object storage, and managed DNS to host malicious payloads and evade traditional perimeter defenses. This analysis maps the infrastructure supply chain abused by threat actors and provides detection rules for cloud workload protection platforms.

Source: https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns

## Device Code Phishing Hits 340+ Microsoft 365 Orgs Across Five Countries ...

**PIR:** 1.d

Device code phishing targets 340+ Microsoft 365 orgs since Feb 2026 via OAuth abuse, enabling persistent token hijacking and account takeover. The campaign demonstrates how attackers leverage legitimate authentication flows to maintain long-term access. Defenders should audit OAuth app permissions and deploy identity threat detection solutions.

Source: https://thehackernews.com/2026/03/device-code-phishing-hits-340-microsoft.html

## Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA

**PIR:** 1.i

CISA has issued an alert regarding a zero-click phishing campaign targeting Zimbra email servers. The Laundry Bear group exploits unpatched authentication flaws to inject malicious payloads directly into user inboxes, bypassing traditional email gateways. Infrastructure administrators must prioritize patching and monitor for anomalous server-side script execution.

Source: https://tempmail.ninja/blog/laundry-bear-zimbra-phishing

## The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations

**PIR:** 1.g

Generative AI has transformed phishing from broad campaigns into highly targeted, autonomous operations. Attackers now use LLMs to craft context-aware lures, automate infrastructure provisioning, and dynamically adapt to security controls. IT defenders must shift from signature-based filtering to behavioral analytics and user interaction telemetry.

Source: https://itsecurityguru.org/2026/05/27/the-ai-phishing-revolution-from-spray-and-pray-to-autonomous-operations

