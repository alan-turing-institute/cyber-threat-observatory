# Daily phishing and identity campaigns

- **Report date:** 2026-10-19
- **Sources:** ketch OSINT (3 queries)

## Microsoft Disrupts YAM Store Network Behind 1 Billion Phishing Scams and M365 Device-Code Attacks

**PIR:** 1.f

Microsoft’s security operations dismantled the YAM Store network, a massive infrastructure supporting over one billion phishing attempts and widespread Microsoft 365 device-code attacks. The campaign leveraged compromised OAuth flows to bypass traditional email filters, directly targeting identity providers. Defenders should monitor for anomalous device-code authorization requests, enforce conditional access policies, and block known malicious redirect URIs. This disruption highlights the scale 

Source: https://windowsforum.com/news/microsoft-disrupts-yam-store-network-behind-1-billion-phishing-scams-and-m365-device-code-attacks.448313/post-1012947

## Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA

**PIR:** 1.g

Modern phishing operations increasingly leverage cloud-native services like serverless functions, object storage, and CDN networks to host malicious payloads and evade detection. This infrastructure abuse allows attackers to scale campaigns rapidly while maintaining low costs and high resilience. IT defenders must shift focus from static URL blocking to behavioral analysis of cloud service usage. Implementing egress filtering, monitoring for anomalous API calls, and enforcing strict IAM policies

Source: https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns

## GhostCode attackers abuse device codes to take over Microsoft 365 accounts

**PIR:** 1.f

The GhostCode threat actor group is actively exploiting Microsoft 365 device-code authentication flows to hijack enterprise accounts. By tricking users into entering authorization codes on malicious portals, attackers bypass multi-factor authentication and gain persistent access to email, Teams, and cloud storage. Infrastructure defenders must implement strict conditional access rules, monitor for unusual device-code sign-ins, and educate users on recognizing fake verification prompts. Blocking 

Source: https://computerworld.com/article/4223889/ghostcode-attackers-abuse-device-codes-to-take-over-microsoft-365-accounts.html

## SideWinder APT Credential Harvesting Campaign — PaaS Platform Abuse at Scale

**PIR:** 1.j.3

The SideWinder APT group is conducting large-scale credential harvesting by abusing Platform-as-a-Service (PaaS) environments to host sophisticated phishing infrastructure. By leveraging legitimate cloud platforms, attackers bypass traditional security controls and target high-value identity accounts. The campaign utilizes automated deployment scripts and dynamic domain generation to maintain persistence. Defenders should monitor for unauthorized PaaS resource provisioning, enforce least-privile

Source: https://intel.breakglass.tech/post/sidewinder-mhil-zeabur

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.h

Threat actors are deploying AI-generated landing pages and dynamic content to enhance device-code phishing campaigns targeting Microsoft 365 tenants. These AI-driven sites mimic legitimate Microsoft login flows with high fidelity, increasing user compliance rates. The campaign automates token harvesting and rapidly rotates infrastructure to evade takedowns. Defenders should deploy AI-aware web filtering, monitor for rapid OAuth consent spikes, and enforce application allow-listing. Identity gove

Source: https://microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026

## Device Code Phishing: How EvilTokens Hit 12,000+ Inboxes

**PIR:** 1.f

The EvilTokens campaign demonstrates how attackers weaponize device-code phishing to compromise thousands of inboxes simultaneously. By distributing malicious links via compromised accounts and spam, threat actors harvest OAuth tokens that grant broad M365 permissions. This technique circumvents traditional email security and MFA controls. Infrastructure teams should audit delegated permissions, restrict third-party app registrations, and implement real-time identity threat detection. Monitoring

Source: https://ctiacademy.io/blog/device-code-phishing

## Device Code Phishing Hits 340+ Microsoft 365 Orgs Across Five Countries via OAuth Abuse

**PIR:** 1.f

A coordinated OAuth abuse campaign has impacted over 340 Microsoft 365 organizations across five countries, leveraging device-code phishing to steal identity tokens. Attackers exploit legitimate authentication mechanisms to bypass perimeter defenses and establish persistent access. The campaign highlights vulnerabilities in default cloud identity configurations. Defenders must enforce strict consent policies, disable unnecessary device-code flows where possible, and deploy identity protection so

Source: https://news.u-labs.de/link?id=30726

## Microsoft Teams Phishing via Fake IT Helpdesk Impersonation (External Chat, Vishing, Screen Sharing, RMM

**PIR:** 1.e

Attackers are executing sophisticated phishing campaigns within Microsoft Teams by impersonating IT helpdesk personnel to initiate external chats, vishing calls, and unauthorized screen-sharing sessions. The tactic leverages trust in internal support channels to deploy Remote Monitoring and Management (RMM) tools on victim endpoints. Infrastructure defenders must restrict external Teams messaging, enforce strict RMM deployment policies, and monitor for anomalous helpdesk account activity. User t

Source: https://intel.threadlinqs.com/threat/TL-2026-3778

