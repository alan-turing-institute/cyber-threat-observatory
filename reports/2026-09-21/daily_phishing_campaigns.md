# Daily phishing and identity campaigns

- **Report date:** 2026-09-21
- **Sources:** ketch OSINT (3 queries)

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.e

Threat actors leverage AI to automate device code phishing at scale, generating live authentication prompts on demand. This campaign bypasses traditional email filters by targeting users directly with dynamic codes, enabling rapid account takeover and persistent access. Defenders should monitor for anomalous device code requests and restrict OAuth consent flows.

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## GhostCode Phishing Kit Bypasses Microsoft 365 MFA to Hijack Accounts in 78 Seconds

**PIR:** 1.b

A newly discovered GhostCode phishing kit bypasses Microsoft 365 MFA in under two minutes. The kit automates device code interception and token theft, enabling rapid account hijacking. Security operations should deploy MFA fatigue defenses, restrict interactive login flows, and implement behavioral analytics to detect automated credential harvesting campaigns.

Source: https://cybersecuritynews.com/ghostcode-phishing-kit/amp

## GhostCode Abuses Microsoft Device Codes to Steal M365 Tokens and Register Rogue Devices

**PIR:** 1.b

The GhostCode toolkit abuses Microsoft device codes to extract valid M365 access tokens and register unauthorized devices. This technique allows attackers to maintain persistence even after password resets. Defenders should monitor Entra ID sign-in logs for token theft indicators, restrict app registrations, and implement token lifetime policies.

Source: https://cyberpress.org/ghostcode-m365-device-code

## GhostCode Abuses Microsoft Entra Device Enrollment to Maintain Access After Token Revocation

**PIR:** 1.f

Attackers leverage Microsoft Entra device enrollment to retain access after token revocation. By registering rogue devices during the initial compromise, GhostCode operators create persistent backdoors. IT teams must enforce device compliance policies, audit enrollment approvals, and monitor for unauthorized device additions in Entra ID.

Source: https://gbhackers.com/ghostcode-abuses-microsoft-entra

## Microsoft 365: Block Device Code Flow Against GhostCode

**PIR:** 1.e

Administrators can mitigate GhostCode attacks by disabling the device code flow in Microsoft 365. This configuration change prevents threat actors from exploiting the interactive authentication mechanism to steal tokens. Implementing conditional access policies and restricting device enrollment scopes further reduces exposure to automated credential harvesting.

Source: https://windowsforum.com/news/microsoft-365-block-device-code-flow-against-ghostcode.444973

## GhostCode attackers abuse device codes to take over Microsoft 365 accounts

**PIR:** 1.e

GhostCode operators exploit Microsoft’s device code authentication to hijack M365 accounts. By tricking users into entering codes on malicious portals, attackers bypass standard MFA controls. Infrastructure teams must audit active device code sessions, enforce strict conditional access rules, and deploy real-time alerting for suspicious authentication patterns.

Source: https://computerworld.com/article/4223889/ghostcode-attackers-abuse-device-codes-to-take-over-microsoft-365-accounts.html

## Operation HookedWing: 4-Year Phishing Campaign Hits 500+

**PIR:** 1.c

Operation HookedWing represents a sustained, four-year spear phishing campaign targeting over 500 organizations. Attackers use highly tailored lures to harvest credentials and deploy persistent access tools. Defenders should review historical email logs, enforce least-privilege access, and implement advanced phishing simulation and detection controls.

Source: https://cipherssecurity.com/operation-hookedwing-phishing-500/

