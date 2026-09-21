# Daily phishing and identity campaigns

- **Report date:** 2026-09-15
- **Sources:** ketch OSINT (3 queries)

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.f

A new wave of device code phishing shows how threat actors are scaling account compromise using AI and end‑to‑end automation. This campaign goes beyond traditional phishing by generating live authentication codes on demand, enabling higher success rates and sustained post‑compromise access.

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## Microsoft 365: Block Device Code Flow Against GhostCode

**PIR:** 1.f

Guidance on disabling the device code authentication flow in Microsoft 365 to mitigate GhostCode’s account takeover tactics. Infrastructure defenders can implement conditional access policies and block specific OAuth grants to neutralize this vector.

Source: https://windowsforum.com/news/microsoft-365-block-device-code-flow-against-ghostcode.444973

## GhostCode Abuses Microsoft Entra Device Enrollment to Maintain Access After Token Revocation

**PIR:** 1.j.3

Investigation into GhostCode’s abuse of Microsoft Entra device enrollment to maintain persistent access after token revocation. Defenders must monitor enrollment logs, enforce strict device compliance, and implement automated revocation workflows to counter this identity persistence tactic.

Source: https://gbhackers.com/ghostcode-abuses-microsoft-entra

## Midnight Blizzard-Linked Actor GTG-20006 Automated Device Code Phishing With AI

**PIR:** 1.i

Attribution of AI-automated device code phishing to a Midnight Blizzard-linked actor (GTG-20006). The campaign uses machine learning to scale authentication bypass attempts, highlighting the convergence of state-sponsored tactics and automated identity theft.

Source: https://aegisai.ai/blog/anthropic-midnight-blizzard-ai-device-code-phishing

## GhostCode attackers abuse device codes to take over Microsoft 365 accounts

**PIR:** 1.f

Threat actors leverage Microsoft’s device code authentication flow to bypass multi-factor authentication and hijack M365 accounts. The technique exploits legitimate OAuth endpoints, allowing attackers to silently acquire valid tokens without user interaction.

Source: https://computerworld.com/article/4223889/ghostcode-attackers-abuse-device-codes-to-take-over-microsoft-365-accounts.html

## GhostCode Abuses Microsoft Device Codes to Steal M365 Tokens and Register Rogue Devices

**PIR:** 1.f

Analysis of how GhostCode steals M365 access tokens and registers rogue devices via abused device code flows. The campaign highlights persistence mechanisms that survive standard token revocation, requiring infrastructure teams to audit device compliance and enrollment policies.

Source: https://cyberpress.org/ghostcode-m365-device-code

## GhostCode Phishing Kit Bypasses Microsoft 365 MFA to Hijack Accounts in 78 Seconds

**PIR:** 1.e

Breakdown of a phishing kit that bypasses Microsoft 365 MFA to hijack accounts in under two minutes. The tool automates credential harvesting and session token theft, demonstrating the urgent need for phishing-resistant MFA and real-time identity monitoring.

Source: https://cybersecuritynews.com/ghostcode-phishing-kit/amp

## Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA

**PIR:** 1.g

CISA alert detailing a zero-click phishing campaign by Laundry Bear targeting Zimbra email servers. The exploit leverages a critical vulnerability to compromise Western government and critical infrastructure accounts without user interaction, emphasizing the need for immediate patching.

Source: https://tempmail.ninja/blog/laundry-bear-zimbra-phishing

