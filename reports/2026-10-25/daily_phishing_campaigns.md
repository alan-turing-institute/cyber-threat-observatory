# Daily phishing and identity campaigns

- **Report date:** 2026-10-25
- **Sources:** ketch OSINT (3 queries)

## Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Security Blog

**PIR:** 1.j.3

EvilTokens represents a sophisticated evolution in device code phishing, where threat actors harvest long-lived authentication tokens rather than just session cookies. By targeting the underlying OAuth 2.0 device authorization flow, attackers achieve persistent access that survives password resets and MFA re-registration. This analysis details the technical mechanics of EvilTokens and provides actionable mitigation strategies for identity architects, emphasizing the need for token lifecycle mana

Source: https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.j.3

This campaign marks a significant escalation in threat actor sophistication, moving away from static, manual scripts toward an AI-driven infrastructure with end-to-end automation. It builds upon the Storm-2372 device code phishing campaign observed in February 2025, demonstrating how adversaries are leveraging generative AI to streamline credential harvesting and bypass traditional MFA controls. Infrastructure defenders should monitor for automated OAuth consent requests and implement strict con

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US

**PIR:** 1.j.3

Device code phishing continues to evolve as a primary vector for identity takeover, exploiting the convenience of multi-device authentication flows. Attackers now deploy sophisticated landing pages that mimic legitimate OAuth consent prompts, tricking users into authorizing malicious applications. This technique effectively circumvents traditional password-based MFA, making it a critical threat for organizations relying on cloud identity platforms. Defenders must prioritize user education and im

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## Russian hacker group Laundry Bear exploits Zimbra zero-click flaw to target Western government, critical infrastructure

**PIR:** 1.a

Laundry Bear, a Russian threat actor, is exploiting a zero-click vulnerability in Zimbra collaboration software to compromise Western government and critical infrastructure networks. The attack requires no user interaction, bypassing traditional email security controls and directly harvesting credentials or deploying backdoors. Infrastructure defenders must prioritize patching Zimbra instances, implementing network segmentation, and deploying endpoint detection and response solutions to mitigate

Source: https://industrialcyber.co/cisa/russian-hacker-group-laundry-bear-exploits-zimbra-zero-click-flaw-to-target-western-government-critical-infrastructure

## Access granted: phishing with device code authorization for account takeover | Proofpoint US

**PIR:** 1.j.3

This report details how threat actors leverage device code authorization flows to execute account takeover attacks at scale. By directing users to counterfeit Microsoft 365 login portals, attackers capture the six-character device codes and exchange them for valid access tokens. The campaign highlights vulnerabilities in default cloud configurations and underscores the necessity of enforcing app consent policies, monitoring for anomalous OAuth grants, and deploying identity protection solutions.

Source: https://www.proofpoint.com/us/blog/threat-insight/access-granted-phishing-device-code-authorization-account-takeover

## SideWinder APT Credential Harvesting Campaign — PaaS Platform Abuse at Scale

**PIR:** 1.d

The SideWinder APT group is conducting a large-scale credential harvesting campaign by abusing Platform-as-a-Service infrastructure to host phishing domains and proxy traffic. This approach allows attackers to rapidly deploy and rotate malicious infrastructure while evading traditional blocklists. The campaign targets enterprise users to steal cloud credentials, highlighting the need for DNS filtering, threat intelligence integration, and continuous monitoring of cloud-hosted phishing infrastruc

Source: https://intel.breakglass.tech/post/sidewinder-mhil-zeabur

## Storm-2372 conducts device code phishing campaign | Microsoft Security Blog

**PIR:** 1.j.3

Storm-2372, a Chinese state-sponsored threat group, deployed a targeted device code phishing campaign against government and enterprise targets. The operation utilized customized landing pages and social engineering to harvest OAuth device codes, enabling persistent access to compromised accounts. This campaign illustrates the growing reliance of advanced persistent threats on identity-centric attack vectors, prompting defenders to strengthen conditional access rules and monitor for unauthorized

Source: https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/

## Three Active Microsoft 365 Phishing Campaigns Targeting Schools and Government Agencies

**PIR:** 1.a

Three concurrent phishing campaigns are actively targeting educational institutions and government agencies using Microsoft 365 infrastructure. Attackers deploy credential harvesting pages mimicking Office 365 login portals, often distributed via malicious email attachments or links. The campaigns exploit weak email filtering configurations and lack of multi-factor authentication. Defenders should review mail flow rules, enforce MFA, and monitor for suspicious sign-in locations and impossible tr

Source: https://forsyteit.com/three-active-microsoft-365-phishing-campaigns-targeting-schools-and-government-agencies

