# Daily phishing and identity campaigns

- **Report date:** 2026-09-30
- **Sources:** ketch OSINT (3 queries)

## Unmasking EvilTokens: Getting to the root of device code phishing

**PIR:** 1.g

Microsoft researchers dissect the EvilTokens infrastructure, revealing how threat actors automate device code phishing at scale. By exploiting OAuth 2.0 device authorization flows, attackers harvest long-lived tokens that bypass MFA and persist across sessions. The report details detection signatures, token revocation procedures, and architectural mitigations for identity platforms. Critical for SecOps teams managing Azure AD and hybrid cloud environments.

Source: https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/

## Passkey-themed social engineering leads to identity and cloud compromise

**PIR:** 1.g

Attackers are increasingly leveraging passkey authentication prompts to bypass traditional MFA defenses. This campaign uses highly targeted social engineering to trick users into approving legitimate-looking passkey requests, granting threat actors direct access to cloud environments and identity providers. Defenders must monitor for anomalous passkey approval patterns, enforce conditional access policies, and educate users on recognizing spoofed authentication prompts.

Source: https://www.microsoft.com/en-us/security/blog/2026/09/09/passkey-themed-social-engineering-leads-identity-cloud-compromise/

## Midnight Blizzard-Linked Actor GTG-20006 Automated Device Code Phishing With AI

**PIR:** 1.j.3

Threat intelligence reveals that a Midnight Blizzard-associated group has integrated AI automation into device code phishing operations. The actor uses machine learning to optimize landing page deployment, credential harvesting timing, and victim targeting. Infrastructure defenders should prioritize monitoring for automated OAuth consent requests, implement token lifetime restrictions, and correlate identity logs with known APT TTPs.

Source: https://aegisai.ai/blog/anthropic-midnight-blizzard-ai-device-code-phishing

## AI-Generated Lures Behind Microsoft Cloud Account Takeovers

**PIR:** 1.f

The Cloud Security Alliance analyzes a surge in account takeovers driven by generative AI-crafted phishing lures. These campaigns dynamically adapt language, branding, and urgency cues to evade email security filters and maximize click-through rates. The research highlights the limitations of traditional URL reputation checks and recommends AI-aware content inspection, behavioral analytics, and zero-trust identity validation for cloud workloads.

Source: https://labs.cloudsecurityalliance.org/research/csa-research-note-genai-passkey-phishing-msft-20260914-csa-s

## Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA

**PIR:** 1.h

CISA alerts on a zero-click phishing campaign targeting Zimbra email servers, exploited by the Russian-linked Laundry Bear group. The attack leverages a server-side vulnerability to deliver malicious payloads without user interaction, bypassing traditional email security gateways. Infrastructure teams must prioritize immediate patching, implement network segmentation for mail servers, and monitor for lateral movement indicators post-exploitation.

Source: https://tempmail.ninja/blog/laundry-bear-zimbra-phishing

## Device Code Phishing is an Evolution in Identity Takeover

**PIR:** 1.d

Proofpoint outlines how device code phishing has matured from opportunistic attacks into a systematic identity takeover methodology. By redirecting users to malicious OAuth consent pages, attackers capture authorization codes that exchange for persistent access tokens. The article provides network-level indicators, proxy blocking strategies, and user training frameworks to mitigate this growing vector in enterprise environments.

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations

**PIR:** 1.f

This analysis tracks the shift from bulk phishing campaigns to fully autonomous, AI-driven operations. Modern threat actors deploy LLMs to generate context-aware lures, manage infrastructure provisioning, and adapt to security controls in real time. Defenders must transition from signature-based detection to behavioral anomaly monitoring, implement strict email authentication, and prepare incident response playbooks for AI-accelerated breaches.

Source: https://itsecurityguru.org/2026/05/27/the-ai-phishing-revolution-from-spray-and-pray-to-autonomous-operations

## Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA

**PIR:** 1.i

CYFIRMA documents how adversaries leverage compromised cloud instances, serverless functions, and CDN networks to host phishing infrastructure. By blending malicious traffic with legitimate cloud services, attackers evade traditional perimeter defenses and IP blocklists. The report recommends cloud workload protection, DNS monitoring, and egress filtering to disrupt infrastructure abuse and protect identity endpoints.

Source: https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns

