# Daily phishing and identity campaigns

- **Report date:** 2026-09-23
- **Sources:** ketch OSINT (3 queries)

## Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Security Blog

**PIR:** 1.i

Microsoft researchers dissect the EvilTokens Phishing-as-a-Service operation, detailing how attackers exploit the OAuth device code flow to bypass multi-factor authentication. The report provides infrastructure defenders with actionable telemetry, detection rules, and mitigation strategies to block malicious device code requests and protect Microsoft 365 environments from credential theft.

Source: https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/

## Cloudflare participates in global operation to disrupt EvilTokens Phishing-as-a-Service | Cloudflare

**PIR:** 1.d

Cloudflare details its role in a coordinated global takedown of the EvilTokens infrastructure. The analysis covers the network architecture, domain generation algorithms, and proxy techniques used by the service. Defenders gain insights into identifying and blocking associated C2 domains, understanding the economic model of modern phishing-as-a-service, and implementing DNS-layer defenses.

Source: https://www.cloudflare.com/threat-intelligence/research/report/cloudflare-participates-in-global-operation-to-disrupt-eviltokens-phishing-as-a-service/

## The Alert Gap: Hunting an Undetected Device Code Phishing Compromise

**PIR:** 1.i

This technical deep-dive explores the detection blind spots surrounding device code phishing campaigns. The author demonstrates how standard SIEM rules often miss these attacks due to legitimate-looking authentication patterns. The article provides advanced hunting queries for Microsoft Sentinel and Splunk, focusing on token issuance anomalies, cross-tenant sign-in behaviors, and lateral movement indicators post-compromise.

Source: https://packetstorm.news/news/view/43540

## Microsoft 365: Block Device Code Flow Against GhostCode

**PIR:** 1.i

A practical guide for IT administrators on disabling or restricting the OAuth device code flow in Microsoft 365 to counter GhostCode attacks. The article provides step-by-step configuration instructions for Conditional Access policies and Azure AD app registration settings. It emphasizes the trade-offs between usability and security, helping defenders implement least-privilege access while neutralizing automated device code phishing vectors.

Source: https://windowsforum.com/news/microsoft-365-block-device-code-flow-against-ghostcode.444973

## Midnight Blizzard-Linked Actor GTG-20006 Automated Device Code Phishing With AI

**PIR:** 1.g

Researchers link the GTG-20006 actor to Midnight Blizzard, detailing their use of AI to automate device code phishing at scale. The report analyzes how machine learning models generate highly convincing prompts and manage victim interactions without human intervention. Defenders gain insights into identifying AI-driven campaign patterns, monitoring for rapid token validation attempts, and updating behavioral analytics to catch automated identity theft.

Source: https://aegisai.ai/blog/anthropic-midnight-blizzard-ai-device-code-phishing

## Tracking BigBear 2.0 Evilginx2 Phishing Campaign | CloudSEK

**PIR:** 1.a

CloudSEK tracks the BigBear 2.0 campaign leveraging Evilginx2 to conduct sophisticated reverse-proxy phishing attacks. The report outlines how the tool bypasses MFA by intercepting session cookies during legitimate login flows. Infrastructure teams receive guidance on detecting proxy-based authentication anomalies, monitoring for suspicious TLS certificates, and hardening identity providers against session hijacking.

Source: https://www.cloudsek.com/blog/tracking-bigbear-2-0-evilginx2-phishing-campaign

## GhostCode attackers abuse device codes to take over Microsoft 365 accounts

**PIR:** 1.j

Computerworld examines the GhostCode threat group's methodology for exploiting device code authentication to compromise enterprise Microsoft 365 accounts. The report highlights how attackers automate the phishing process to harvest valid tokens, bypassing traditional MFA. Infrastructure defenders are advised to monitor for unusual device code sign-ins, enforce strict Conditional Access rules, and deploy identity protection alerts.

Source: https://computerworld.com/article/4223889/ghostcode-attackers-abuse-device-codes-to-take-over-microsoft-365-accounts.html

## Bypassing the Gatekeepers: How a Global Phishing Campaign Turns Google's Infrastructure into a Trust Proxy

**PIR:** 1.f

This analysis reveals how threat actors abuse legitimate Google services to host phishing pages, effectively using major cloud infrastructure as a trust proxy. The campaign evades traditional URL filtering by leveraging high-reputation domains. Defenders learn to implement advanced reputation scoring, monitor for anomalous subdomain usage, and adjust email security gateways to catch infrastructure-abuse phishing attempts.

Source: https://blog.knowbe4.com/bypassing-the-gatekeepers-how-a-global-phishing-campaign-turns-googles-infrastructure-into-a-trust-proxy

