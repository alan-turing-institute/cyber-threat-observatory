# Daily phishing and identity campaigns

- **Report date:** 2026-09-17
- **Sources:** ketch OSINT (3 queries)

## GhostCode Phishing Kit Bypasses Microsoft 365 MFA to Hijack Accounts in 78 Seconds

**PIR:** 1.b

GhostCode operators deploy a refined phishing kit that intercepts Microsoft 365 authentication flows, bypassing multi-factor authentication in under two minutes. The campaign leverages real-time session token theft and automated device registration to maintain persistent access. Infrastructure defenders should monitor for anomalous device code grants, enforce conditional access policies restricting legacy authentication, and deploy token revocation scripts immediately upon detection.

Source: https://cybersecuritynews.com/ghostcode-phishing-kit/amp

## Microsoft 365: Block Device Code Flow Against GhostCode

**PIR:** 1.c

Microsoft recommends immediate mitigation steps to disable the device code authorization flow, a primary vector exploited by GhostCode for M365 account takeover. The advisory outlines PowerShell commands and Entra ID configuration changes to restrict device enrollment and token issuance. IT infrastructure teams must audit active device codes, implement just-in-time access controls, and validate conditional access rules to prevent unauthorized cloud resource provisioning.

Source: https://windowsforum.com/news/microsoft-365-block-device-code-flow-against-ghostcode.444973

## Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA

**PIR:** 1.e

CISA alerts infrastructure teams to a zero-click phishing campaign targeting Zimbra email servers, exploited by the Russian-linked Laundry Bear group. The attack leverages an unpatched server-side vulnerability to inject malicious payloads directly into user inboxes without interaction. Defenders must immediately apply vendor patches, segment email infrastructure, monitor for unauthorized outbound connections, and validate server integrity using known-good baselines.

Source: https://tempmail.ninja/blog/laundry-bear-zimbra-phishing

## Microsoft: Passkey Help Desk Calls Are Hijacking Cloud Accounts, Then Draining SharePoint

**PIR:** 1.a

Threat actors are exploiting social engineering via fake Microsoft support calls to trick users into initiating passkey registration on attacker-controlled devices. Once registered, these passkeys grant full administrative access to cloud environments, enabling rapid SharePoint data exfiltration. Defenders should implement passkey registration alerts, enforce hardware-bound credential policies, and train help desk staff to verify identity requests through out-of-band channels.

Source: https://threat-intelligence.redeyesecurity.com/blog/passkey-phishing-microsoft-cloud-hijack-storm-3032-2026

## Midnight Blizzard-Linked Actor GTG-20006 Automated Device Code Phishing With AI

**PIR:** 1.d

A threat actor linked to Midnight Blizzard is automating Microsoft device code phishing campaigns using AI-driven orchestration. The group dynamically generates phishing pages, manages concurrent authentication sessions, and auto-registers rogue devices upon token capture. Defenders should monitor Entra ID sign-in logs for rapid device code approvals, enforce risk-based conditional access, and deploy automated response playbooks to revoke compromised tokens and isolate affected endpoints.

Source: https://aegisai.ai/blog/anthropic-midnight-blizzard-ai-device-code-phishing

## Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA

**PIR:** 1.f

Modern phishing operations increasingly leverage cloud-native services like serverless functions, CDN edge nodes, and ephemeral containers to host malicious payloads and evade traditional perimeter defenses. Attackers dynamically rotate infrastructure to bypass DNS blacklists and IP reputation filters. Infrastructure defenders must implement cloud workload protection platforms, monitor for anomalous API calls, and enforce strict egress filtering to detect and block cloud-hosted phishing endpoint

Source: https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns

## The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations

**PIR:** 1.d

Generative AI is transforming phishing from broad, low-success campaigns into highly targeted, autonomous operations capable of adapting to security controls in real time. AI-driven tools automate victim profiling, craft context-aware lures, and dynamically modify landing pages to bypass content filters. Defenders should prioritize behavioral analytics, deploy AI-resistant email authentication standards, and implement continuous user training focused on contextual threat recognition.

Source: https://itsecurityguru.org/2026/05/27/the-ai-phishing-revolution-from-spray-and-pray-to-autonomous-operations

## Fast Flux Phishing Turns the Internet Into a Moving Target as Silent Push Uncovers a Massive Canada-First Banking Operation + Video - UNDERCODE NEWS

**PIR:** 1.f

Attackers are deploying fast-flux DNS networks to rapidly rotate phishing infrastructure across thousands of compromised hosts, making takedown efforts nearly impossible. Combined with silent push notifications, this technique enables large-scale banking credential theft. Infrastructure defenders should implement DNS sinkholing, monitor for high-entropy domain registrations, and deploy network-level threat intelligence feeds to dynamically block fast-flux endpoints before user interaction.

Source: https://undercodenews.com/fast-flux-phishing-turns-the-internet-into-a-moving-target-as-silent-push-uncovers-a-massive-canada-first-banking-operation-video

