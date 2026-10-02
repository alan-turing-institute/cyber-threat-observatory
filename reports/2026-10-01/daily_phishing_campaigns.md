# Daily phishing and identity campaigns

- **Report date:** 2026-10-01
- **Sources:** ketch OSINT (3 queries)

## Inside an AI‑enabled device code phishing campaign | Microsoft Security Blog

**PIR:** 1.j

This campaign combines AI-driven reconnaissance with device code phishing to bypass multi-factor authentication. Attackers generate context-aware prompts that direct users to enter authorization codes on attacker-controlled endpoints. Once validated, threat actors gain persistent access to cloud identities. Defenders should monitor OAuth consent logs, restrict device code flows to approved applications, and implement real-time alerting for suspicious authorization requests.

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Security Blog

**PIR:** 1.j

EvilTokens represents a sophisticated evolution of device code phishing, enabling attackers to silently harvest valid OAuth tokens without user interaction. By exploiting legitimate authentication flows, these tokens grant persistent access to Microsoft 365 and Azure resources. Infrastructure defenders must audit token issuance patterns, enforce short-lived token policies, and deploy identity threat detection tools to identify anomalous consent grants and token reuse.

Source: https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/

## AI-Generated Lures Behind Microsoft Cloud Account Takeovers

**PIR:** 1.h

Generative AI is being weaponized to create highly personalized phishing lures targeting Microsoft 365 administrators and high-privilege users. These AI-crafted messages bypass traditional spam filters by mimicking internal communication styles and referencing real project contexts. Infrastructure teams must prioritize behavioral analytics, deploy AI-aware email security gateways, and enforce strict least-privilege access to mitigate account takeover risks.

Source: https://labs.cloudsecurityalliance.org/research/csa-research-note-genai-passkey-phishing-msft-20260914-csa-s

## Midnight Blizzard-Linked Actor GTG-20006 Automated Device Code Phishing With AI

**PIR:** 1.j

A state-linked threat group has automated device code phishing operations using AI to scale targeting and adapt lures in real time. The campaign focuses on government and critical infrastructure accounts, leveraging stolen credentials and AI-generated prompts to bypass MFA. Defenders should implement automated threat hunting for OAuth anomalies, restrict device code authentication to managed devices, and integrate AI detection models into identity protection workflows.

Source: https://aegisai.ai/blog/anthropic-midnight-blizzard-ai-device-code-phishing

## Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA

**PIR:** 1.g

Threat actors increasingly leverage cloud-native services like serverless functions, object storage, and CDN networks to host phishing infrastructure. This approach bypasses traditional IP-based blocklists and complicates takedown efforts. Infrastructure defenders must monitor cloud provider abuse reports, implement DNS sinkholing for dynamic domains, and deploy cloud workload protection platforms to detect anomalous resource provisioning tied to credential harvesting campaigns.

Source: https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns

## Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA

**PIR:** 1.i

CISA has issued an alert regarding a zero-click phishing campaign exploiting a critical vulnerability in Zimbra collaboration suites. The attack requires no user interaction, automatically delivering malicious payloads that establish persistent backdoors. Infrastructure teams must immediately patch Zimbra instances, deploy network segmentation for email servers, and monitor for unauthorized outbound connections indicative of command-and-control activity.

Source: https://tempmail.ninja/blog/laundry-bear-zimbra-phishing

## Access granted: phishing with device code authorization for account takeover | Proofpoint US

**PIR:** 1.j

This analysis details how threat actors abuse device code authorization flows to harvest valid access tokens and bypass traditional MFA controls. By directing users to enter codes on compromised endpoints, attackers gain seamless access to cloud environments. Defenders should enforce strict OAuth consent policies, monitor for high-frequency device code requests, and implement user verification steps for sensitive authorization flows.

Source: https://www.proofpoint.com/us/blog/threat-insight/access-granted-phishing-device-code-authorization-account-takeover

## Passkey-themed social engineering leads to identity and cloud compromise

**PIR:** 1.e

Attackers are deploying sophisticated social engineering tactics that mimic passkey authentication prompts to trick users into granting unauthorized access. These campaigns exploit trust in modern passwordless protocols, leading to rapid identity compromise and lateral movement across cloud environments. Defenders should enforce conditional access policies, monitor for anomalous authentication requests, and educate users on verifying legitimate passkey challenges versus spoofed interfaces.

Source: https://www.microsoft.com/en-us/security/blog/2026/09/09/passkey-themed-social-engineering-leads-identity-cloud-compromise/

