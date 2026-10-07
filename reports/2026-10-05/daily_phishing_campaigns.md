# Daily phishing and identity campaigns

- **Report date:** 2026-10-05
- **Sources:** ketch OSINT (3 queries)

## The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations

**PIR:** 1.e

Generative AI is transforming phishing from broad, low-success campaigns into highly targeted, autonomous operations. Attackers now use LLMs to craft context-aware lures, automate victim interaction, and dynamically adapt payloads. Defenders must shift from signature-based detection to behavioral analytics and AI-driven threat hunting to protect identity perimeters.

Source: https://itsecurityguru.org/2026/05/27/the-ai-phishing-revolution-from-spray-and-pray-to-autonomous-operations

## Device Code Phishing is an Evolution in Identity Takeover

**PIR:** 1.f

Device code phishing is rapidly expanding as threat actors exploit OAuth 2.0 device authorization flows to bypass MFA. Publicly available toolkits and phishing-as-a-service platforms have lowered the barrier to entry. Defenders must implement strict OAuth consent policies, monitor device code grants, and educate users on authorization prompts.

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.f

This campaign demonstrates how AI automates device code phishing at scale, generating live authentication codes on demand. By combining AI-driven lure generation with end-to-end automation, attackers achieve higher success rates and maintain persistent access. Security teams should deploy real-time session monitoring and restrict device code grant scopes.

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA

**PIR:** 1.g

Threat actors increasingly leverage cloud-native services like serverless functions, object storage, and container registries to host phishing infrastructure. This approach bypasses traditional IP-based blocklists and complicates takedown efforts for defenders. Understanding these tactics is critical for securing modern cloud environments and implementing effective egress filtering.

Source: https://www.cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns/

## Microsoft 365 Device Code Phishing Campaign Bypasses Password Theft ...

**PIR:** 1.f

Analysts documented a campaign leveraging Microsoft’s Device Authorization Grant flow to execute near-invisible account takeovers. The attack uses realistic business-themed emails and polished phishing kits to trick users into authorizing malicious apps. Defenders must audit M365 app permissions and enforce strict consent workflows.

Source: https://cybersecuritynews.com/microsoft-365-device-code-phishing-campaign/

## AI-Generated Lures Behind Microsoft Cloud Account Takeovers

**PIR:** 1.d

Recent Microsoft cloud account compromises exploit AI-generated passkey and authentication lures that mimic legitimate Microsoft branding. These sophisticated attacks bypass traditional MFA by tricking users into authorizing malicious sessions. Infrastructure teams should enforce conditional access policies and monitor for anomalous authentication patterns.

Source: https://labs.cloudsecurityalliance.org/research/csa-research-note-genai-passkey-phishing-msft-20260914-csa-s

## Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA

**PIR:** 1.i

CISA warned of a zero-click phishing campaign targeting Zimbra email servers, exploiting vulnerabilities to deliver malicious payloads without user interaction. This technique bypasses traditional email security gateways and user training programs. Infrastructure teams must prioritize patch management, network segmentation, and advanced threat detection for email platforms.

Source: https://tempmail.ninja/blog/laundry-bear-zimbra-phishing

## Storm-2372 conducts device code phishing campaign

**PIR:** 1.b

Microsoft Threat Intelligence tracked Storm-2372’s campaign, which mimics messaging apps like WhatsApp, Signal, and Teams to deliver device code phishing lures. Active since August 2024, the campaign targets specific organizations with highly contextualized messages. Defenders should monitor for unauthorized messaging app integrations and enforce strict OAuth consent policies.

Source: https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/

