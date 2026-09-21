# Daily phishing and identity campaigns

- **Report date:** 2026-09-18
- **Sources:** ketch OSINT (3 queries)

## GhostCode Abuses Microsoft Device Codes to Steal M365 Tokens and Register Rogue Devices

**PIR:** 1.d

Analyzes how threat actors exploit the device code flow to steal Microsoft 365 tokens and register rogue devices, effectively bypassing traditional MFA. Infrastructure defenders must monitor Entra ID device enrollment logs, restrict device code flows, and enforce conditional access policies to prevent persistent unauthorized access.

Source: https://cyberpress.org/ghostcode-m365-device-code

## GhostCode Phishing Kit Bypasses Microsoft 365 MFA to Hijack Accounts in 78 Seconds

**PIR:** 1.d

Details a sophisticated phishing kit that intercepts device codes to hijack accounts in under two minutes. Highlights the critical need for infrastructure teams to implement real-time authentication monitoring, deploy phishing-resistant MFA, and configure automated alerts for anomalous device registration events.

Source: https://cybersecuritynews.com/ghostcode-phishing-kit/amp

## Microsoft 365: Block Device Code Flow Against GhostCode

**PIR:** 1.g

Provides actionable administrative guidance for disabling or restricting the device code flow within Microsoft 365 and Entra ID. Essential reading for infrastructure defenders seeking to harden authentication boundaries, mitigate token theft, and enforce stricter identity governance across enterprise environments.

Source: https://windowsforum.com/news/microsoft-365-block-device-code-flow-against-ghostcode.444973

## GhostCode attackers abuse device codes to take over Microsoft 365 accounts

**PIR:** 1.d

Examines operational tactics used to compromise M365 accounts via device code abuse. Recommends infrastructure defenders implement token lifetime restrictions, monitor for unauthorized device registrations, and accelerate migration to passwordless authentication to reduce attack surface.

Source: https://computerworld.com/article/4223889/ghostcode-attackers-abuse-device-codes-to-take-over-microsoft-365-accounts.html

## Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA

**PIR:** 1.a

Analyzes how attackers leverage serverless functions, container registries, and cloud storage to host resilient phishing infrastructure. Defenders should audit cloud resource permissions, implement strict egress filtering, and monitor for anomalous cloud-native service usage to disrupt campaign hosting.

Source: https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns

## The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations

**PIR:** 1.c

Covers the shift from manual campaigns to AI-driven, autonomous phishing operations that adapt in real-time. Infrastructure defenders should prioritize email gateway AI detection, user behavior analytics, and automated incident response playbooks to counter increased scale and sophistication.

Source: https://itsecurityguru.org/2026/05/27/the-ai-phishing-revolution-from-spray-and-pray-to-autonomous-operations

## Fast Flux Phishing Turns the Internet Into a Moving Target as Silent Push Uncovers a Massive Canada-First Banking Operation + Video - UNDERCODE NEWS

**PIR:** 1.b

Explores how fast-flux DNS techniques make phishing domains highly resilient to takedowns. Network and infrastructure teams must deploy DNS threat intelligence, implement sinkholing strategies, and monitor for rapid IP rotation patterns to effectively block malicious traffic at the perimeter.

Source: https://undercodenews.com/fast-flux-phishing-turns-the-internet-into-a-moving-target-as-silent-push-uncovers-a-massive-canada-first-banking-operation-video

## Operation HookedWing: 4 Years, 500 Organizations, 2,000 Credentials

**PIR:** 1.e

Documents a persistent four-year campaign harvesting credentials across hundreds of organizations. Highlights the importance of continuous credential monitoring, passwordless migration, and infrastructure segmentation to limit lateral movement and contain breaches post-initial compromise.

Source: https://www.gblock.app/articles/operation-hookedwing-four-year-phishing-500-orgs-may-2026

