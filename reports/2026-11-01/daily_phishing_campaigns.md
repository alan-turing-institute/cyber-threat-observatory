# Daily phishing and identity campaigns

- **Report date:** 2026-11-01
- **Sources:** ketch OSINT (3 queries)

## Unmasking EvilTokens: Getting to the root of device code phishing

**PIR:** 1.d

This analysis dissects the EvilTokens infrastructure, revealing how threat actors automate device code phishing to bypass multi-factor authentication. Defenders will find detailed indicators of compromise, network traffic patterns, and mitigation strategies for OAuth 2.0 device authorization flows. The report emphasizes the need for conditional access policies and real-time token monitoring to prevent silent identity takeover in enterprise environments.

Source: https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/

## Breaking the code: Multi-stage ‘code of conduct’ phishing campaign leads to AiTM token compromise

**PIR:** 1.b

Examines a sophisticated multi-stage campaign leveraging social engineering around corporate compliance to deploy Adversary-in-the-Middle proxies. The article details how attackers capture session tokens in real-time, rendering traditional MFA ineffective. Infrastructure teams are advised to implement token binding, deploy browser isolation, and monitor for anomalous OAuth consent grants to neutralize this evolving identity threat.

Source: https://microsoft.com/en-us/security/blog/2026/05/04/breaking-the-code-multi-stage-code-of-conduct-phishing-campaign-leads-to-aitm

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.c

Explores the integration of generative AI into device code phishing operations, enabling dynamic landing pages and personalized lures at scale. The breakdown highlights automated infrastructure provisioning and evasion techniques used to bypass email security gateways. Defenders should prioritize AI-driven threat detection, enforce strict OAuth scope limitations, and educate users on recognizing AI-crafted authorization prompts.

Source: https://microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign

## Device Code Phishing is an Evolution in Identity Takeover

**PIR:** 1.d

Provides a comprehensive overview of how device code phishing has matured into a primary vector for enterprise identity compromise. The report maps the attack lifecycle from initial lure to token exfiltration, emphasizing the limitations of current email filtering. IT infrastructure defenders are guided through architectural adjustments, including conditional access rules, token revocation workflows, and enhanced logging for OAuth endpoints.

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## Joint advisory: state-sponsored spear-phishing campaigns targeting critical infrastructure

**PIR:** 1.e

A Five Eyes intelligence advisory detailing coordinated spear-phishing operations by state-sponsored actors against critical infrastructure sectors. The document outlines TTPs, including supply chain manipulation and credential harvesting via malicious attachments. Infrastructure defenders are urged to segment OT/IT networks, enforce strict email attachment sandboxing, and monitor for lateral movement indicators following initial compromise.

Source: https://suvat.uk/blog/five-eyes-advisory.html

## The ‘code of conduct’ phishing campaign: What MSPs need to know right now

**PIR:** 1.a

Focuses on the operational impact of the ‘code of conduct’ phishing wave on managed service providers and their client infrastructure. The article provides actionable response playbooks, including tenant isolation, credential reset protocols, and detection rules for security information and event management platforms. Essential reading for MSPs managing multi-tenant identity environments under active threat.

Source: https://blog.barracuda.com/2026/05/07/code-of-conduct-phishing-campaign-msp-response

## Storm-2372 conducts device code phishing campaign

**PIR:** 1.e

Documents a targeted campaign by the Storm-2372 threat group utilizing device code authorization flows to infiltrate government and defense contractor networks. The analysis covers infrastructure hosting, domain generation algorithms, and persistence mechanisms. Defenders should review OAuth application permissions, implement just-in-time access controls, and correlate login telemetry with known adversary infrastructure.

Source: https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/

## Access granted: phishing with device code authorization for account takeover

**PIR:** 1.d

Details the technical mechanics behind device code authorization phishing, demonstrating how attackers exploit legitimate OAuth endpoints to bypass perimeter defenses. The report includes packet captures, consent screen manipulation techniques, and recommended detection signatures. Infrastructure teams are advised to audit third-party application integrations and deploy user behavior analytics to flag anomalous authorization requests.

Source: https://www.proofpoint.com/us/blog/threat-insight/access-granted-phishing-device-code-authorization-account-takeover

