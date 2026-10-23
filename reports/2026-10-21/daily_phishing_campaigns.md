# Daily phishing and identity campaigns

- **Report date:** 2026-10-21
- **Sources:** ketch OSINT (3 queries)

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.c

Microsoft’s threat intelligence team details a sophisticated campaign leveraging generative AI to dynamically generate convincing device code phishing pages. Attackers use AI to adapt language, branding, and layout in real-time, evading static URL and content filters. The campaign targets enterprise users by exploiting the device code flow’s inherent trust model. Defenders must implement behavioral analytics for authentication endpoints, restrict device code usage to approved networks, and educa

Source: https://microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026

## GhostCode attackers abuse device codes to take over Microsoft 365 accounts

**PIR:** 1.b

Threat actors behind the GhostCode campaign are exploiting Microsoft 365 device code authentication flows to bypass traditional email filters and multi-factor authentication. By directing users to malicious login portals that mimic Microsoft’s OAuth consent screens, attackers harvest valid access tokens for persistent account takeover. Infrastructure defenders should monitor for anomalous device code authorization requests, enforce conditional access policies that restrict token issuance, and de

Source: https://computerworld.com/article/4223889/ghostcode-attackers-abuse-device-codes-to-take-over-microsoft-365-accounts.html

## Device Code Phishing: How EvilTokens Hit 12,000+ Inboxes

**PIR:** 1.b

The EvilTokens threat group has successfully compromised over 12,000 inboxes by weaponizing device code phishing techniques. By distributing malicious links via compromised accounts and spam campaigns, attackers trick users into entering device codes on fake Microsoft login pages. This grants threat actors long-lived access tokens, enabling lateral movement and data exfiltration. IT infrastructure teams should audit OAuth app permissions, implement token lifetime restrictions, and deploy identit

Source: https://ctiacademy.io/blog/device-code-phishing

## SideWinder APT Credential Harvesting Campaign — PaaS Platform Abuse at Scale

**PIR:** 1.f

The SideWinder APT group is leveraging Platform-as-a-Service environments to host credential harvesting infrastructure at scale, dynamically provisioning phishing sites and data exfiltration endpoints. By abusing legitimate PaaS APIs, attackers evade traditional perimeter defenses and maintain persistent access even after initial domains are blocked. Infrastructure teams should monitor for anomalous PaaS API usage, enforce strict egress filtering, and deploy identity-aware proxies to validate au

Source: https://intel.breakglass.tech/post/sidewinder-mhil-zeabur

## Microsoft Teams Phishing via Fake IT Helpdesk Impersonation (External Chat, Vishing, Screen Sharing, RMM

**PIR:** 1.e

Attackers are increasingly using Microsoft Teams to impersonate IT helpdesk personnel, combining external chat, vishing, and screen-sharing requests to harvest credentials and deploy remote monitoring tools. By exploiting trust in internal support channels, threat actors bypass email security controls entirely. Infrastructure defenders should enforce strict external messaging policies, disable unnecessary screen-sharing capabilities for guest users, and implement call recording or verification p

Source: https://intel.threadlinqs.com/threat/TL-2026-3778

## Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA

**PIR:** 1.a

Modern phishing operations are rapidly migrating to cloud-native platforms like serverless functions, object storage, and containerized environments to host malicious payloads and landing pages. This infrastructure abuse provides attackers with high availability, geographic distribution, and resilience against takedown efforts. Defenders must shift from static blocklists to behavioral monitoring of cloud resource deployments, implement DNS sinkholing for newly registered cloud domains, and integ

Source: https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns

## As phishing-as-a-service goes industrial, Microsoft takes down a marketplace behind 1 billion messages

**PIR:** 1.d

The industrialization of phishing-as-a-service has enabled threat actors to distribute over one billion malicious messages through automated marketplaces offering customizable templates, infrastructure hosting, and credential harvesting dashboards. Microsoft’s recent takedown operation disrupted a major hub, but the underlying ecosystem remains resilient. Infrastructure defenders must prioritize threat intelligence sharing, implement automated domain reputation scoring, and deploy machine learni

Source: https://computerworld.com/article/4235537/as-phishing-as-a-service-goes-industrial-microsoft-takes-down-a-marketplace-behind-1-billion-messages-2.html

## Capacity Enhancement Guide: Counter-Phishing Recommendations for Federal Agencies

**PIR:** 1.g

This CISA-published guide provides actionable counter-phishing strategies tailored for federal IT infrastructure, emphasizing zero-trust identity validation, automated takedown workflows, and continuous user awareness training. It outlines technical controls for email authentication enforcement, OAuth token lifecycle management, and incident response playbooks for credential compromise. Defenders should align their security architectures with these recommendations to harden identity perimeters a

Source: https://cisa.gov/sites/default/files/publications/Capacity_Enhancement_Guide-Counter-Phishing_Recommendations_for_Federal_Agencies.pdf

