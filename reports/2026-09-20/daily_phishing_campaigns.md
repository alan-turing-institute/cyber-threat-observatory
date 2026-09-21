# Daily phishing and identity campaigns

- **Report date:** 2026-09-20
- **Sources:** ketch OSINT (3 queries)

## Microsoft 365: Block Device Code Flow Against GhostCode

**PIR:** 1.e

GhostCode operators exploit the OAuth 2.0 Device Code Flow to authenticate on behalf of users without requiring interactive MFA prompts. This guide provides step-by-step PowerShell and Entra ID Conditional Access policies to restrict device code grants, enforce risk-based authentication, and audit legacy application permissions. Critical for M365 administrators seeking to close authentication bypass vectors.

Source: https://windowsforum.com/news/microsoft-365-block-device-code-flow-against-ghostcode.444973

## GhostCode Abuses Microsoft Entra Device Enrollment to Maintain Access After Token Revocation

**PIR:** 1.f

Researchers detail how GhostCode registers rogue devices via Entra ID enrollment endpoints, creating persistent backdoors that survive password resets and token revocations. The technique abuses legitimate device management APIs to bypass conditional access restrictions. IT infrastructure defenders must audit device compliance policies, restrict enrollment permissions to approved administrators, and monitor for unauthorized device registration events.

Source: https://gbhackers.com/ghostcode-abuses-microsoft-entra

## Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA

**PIR:** 1.f

Threat actors increasingly leverage cloud-native services like serverless functions, object storage, and CDN networks to host phishing infrastructure. This report details how defenders can detect anomalous cloud resource provisioning, monitor for misconfigured IAM roles, and implement egress filtering to disrupt these ephemeral attack surfaces. Essential reading for cloud security architects managing hybrid environments.

Source: https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns

## GhostCode Phishing Kit Bypasses Microsoft 365 MFA to Hijack Accounts in 78 Seconds

**PIR:** 1.d

Analysis reveals how the GhostCode phishing kit intercepts valid MFA tokens during the authentication handshake, granting attackers immediate account access. The kit utilizes real-time proxying to mirror legitimate Microsoft login pages while silently capturing session cookies. Defenders should prioritize phishing-resistant MFA methods like FIDO2 security keys and deploy token-binding policies to neutralize this rapid takeover technique.

Source: https://cybersecuritynews.com/ghostcode-phishing-kit/amp

## Fast Flux Phishing Turns the Internet Into a Moving Target as Silent Push Uncovers a Massive Canada-First Banking Operation + Video - UNDERCODE NEWS

**PIR:** 1.g

Silent Push researchers expose a sophisticated fast-flux network used to host credential-harvesting pages targeting Canadian banking customers. By rapidly rotating IP addresses and DNS records, attackers evade traditional blocklists and takedown requests. Infrastructure defenders are advised to deploy DNS sinkholing, monitor for high-entropy domain registrations, and integrate threat intelligence feeds that track flux network patterns.

Source: https://undercodenews.com/fast-flux-phishing-turns-the-internet-into-a-moving-target-as-silent-push-uncovers-a-massive-canada-first-banking-operation-video

## The Shadow Campaigns: Uncovering Global Espionage

**PIR:** 1.j.3

Palo Alto Networks Unit 42 tracks a coordinated espionage operation utilizing multi-stage phishing campaigns to infiltrate critical infrastructure sectors. Attackers combine initial access brokers, custom malware loaders, and living-off-the-land techniques to establish long-term persistence. Network defenders should focus on endpoint detection tuning, lateral movement monitoring, and threat hunting for known APT infrastructure indicators.

Source: https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/

## Operation HookedWing: 4-Year Phishing Campaign Hits 500+

**PIR:** 1.a

A four-year spear-phishing operation compromised over 500 organizations by exploiting trusted vendor relationships and compromised email accounts. Attackers used highly customized lures and legitimate-looking document attachments to deploy credential stealers. Infrastructure teams must review email gateway rules, enforce strict DMARC/DKIM/SPF alignment, and monitor for anomalous outbound authentication attempts from compromised mailboxes.

Source: https://cipherssecurity.com/operation-hookedwing-phishing-500/

## Government Leaders Face Evolving Phishing Attacks

**PIR:** 1.b

State and local government executives are increasingly targeted by whaling campaigns that exploit public schedules and official correspondence. Attackers craft highly personalized messages mimicking inter-agency communications to extract sensitive policy documents and credentials. Defenders should implement executive protection programs, deploy AI-driven email classification, and enforce strict data loss prevention controls on high-privilege accounts.

Source: https://statetechmagazine.com/article/2025/09/when-trust-becomes-weapon-government-leaders-face-evolving-phishing-attacks

