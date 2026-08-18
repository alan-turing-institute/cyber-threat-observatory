# Daily phishing and identity campaigns

- **Report date:** 2026-08-17
- **Sources:** ketch OSINT (3 queries)

## OAuth Device Code Phishing: 37x Surge in Enterprise ATO

**PIR:** 1.j.3

Enterprise account takeover attacks leveraging OAuth device code flows have surged by 37x. Attackers exploit legitimate authentication mechanisms to bypass MFA and harvest long-lived access tokens. Defenders should monitor for unusual device code grant requests, restrict OAuth app permissions, and implement conditional access policies that validate device compliance and user context during authentication flows.

Source: https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/04/CSA_research_note_oauth-device-code-phishing-surge_20260405-csa-styled.pdf

## Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA

**PIR:** 1.h

Threat actors increasingly leverage cloud-native services like serverless functions, object storage, and CDNs to host phishing infrastructure. This approach bypasses traditional domain-based blocklists and complicates takedown efforts. IT defenders must implement cloud security posture management, monitor for anomalous API usage, and enforce strict egress controls to mitigate these evolving infrastructure-level phishing tactics.

Source: https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.i

This campaign demonstrates how threat actors combine AI-generated lures with automated device code phishing to scale account compromises. By dynamically generating authentication prompts and mimicking legitimate app interfaces, attackers achieve higher success rates. Infrastructure teams should deploy AI-aware email filtering, monitor for rapid sequential authentication attempts, and enforce step-up authentication for sensitive OAuth grants.

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## Device Code Phishing Hits 340+ Microsoft 365 Orgs Across Five Countries ...

**PIR:** 1.j.3

Over 340 Microsoft 365 organizations have been targeted by device code phishing campaigns exploiting OAuth abuse. The attacks enable persistent token hijacking and account takeover without traditional credential theft. Defenders must audit registered OAuth applications, disable unnecessary device code grants, and leverage Microsoft Graph alerts to detect anomalous authentication patterns across tenant environments.

Source: https://thehackernews.com/2026/03/device-code-phishing-hits-340-microsoft.html

## Microsoft 365 Device Code Phishing Campaign Bypasses Password Theft ...

**PIR:** 1.d

ReversingLabs documented a sophisticated campaign using business-themed lures and polished phishing kits to exploit Microsoft's Device Authorization Grant flow. The attack bypasses traditional password theft by leveraging legitimate OAuth mechanisms for near-invisible account takeover. Defenders should enforce strict OAuth consent policies, monitor for high-frequency device code requests, and deploy conditional access rules that require compliant devices.

Source: https://cybersecuritynews.com/microsoft-365-device-code-phishing-campaign/

## Storm-2372 conducts device code phishing campaign

**PIR:** 1.a

Storm-2372 has been conducting a sustained device code phishing campaign since August 2024, using lures that mimic popular messaging platforms. The group targets enterprise users to bypass MFA and establish persistent access. IT defenders should analyze email headers for spoofed messaging domains, monitor for unfamiliar OAuth consent prompts, and implement user training focused on recognizing app-mimicking authentication requests.

Source: https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/

## Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA

**PIR:** 1.e

CISA warns of a zero-click phishing campaign targeting Zimbra email servers, exploiting vulnerabilities to deliver payloads without user interaction. This threat bypasses traditional email security gateways and user training. Defenders must prioritize patching Zimbra instances, implement network segmentation for mail servers, and deploy endpoint detection to catch post-exploitation activity.

Source: https://tempmail.ninja/blog/laundry-bear-zimbra-phishing

## Three Active Microsoft 365 Phishing Campaigns Targeting Schools and Government Agencies

**PIR:** 1.a

Active phishing campaigns are specifically targeting educational and government Microsoft 365 tenants. Attackers use tailored lures to harvest credentials and deploy malicious payloads. Infrastructure defenders in these sectors should prioritize zero-trust network access, enforce multi-factor authentication with phishing-resistant methods, and regularly audit third-party application integrations to prevent unauthorized data exfiltration.

Source: https://forsyteit.com/three-active-microsoft-365-phishing-campaigns-targeting-schools-and-government-agencies

