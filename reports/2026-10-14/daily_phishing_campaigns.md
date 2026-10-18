# Daily phishing and identity campaigns

- **Report date:** 2026-10-14
- **Sources:** ketch OSINT (3 queries)

## Unmasking EvilTokens: Getting to the root of device code phishing

**PIR:** 1.b.4

This technical deep dive examines EvilTokens, a sophisticated framework enabling persistent device-code phishing attacks that bypass MFA and conditional access controls. Attackers harvest long-lived tokens by tricking users into authorizing malicious apps, granting them seamless access to M365 and Azure resources. Infrastructure teams must audit OAuth app permissions, revoke suspicious device codes, and implement token lifetime restrictions to neutralize this identity takeover vector.

Source: https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/

## Microsoft Disrupts YAM Store Network Behind 1 Billion Phishing Scams and M365 Device-Code Attacks

**PIR:** 1.b.2

Microsoft’s coordinated takedown of the YAM Store network dismantled a massive infrastructure responsible for over one billion phishing attempts and widespread M365 device-code attacks. The campaign exploited compromised legitimate services to host credential-harvesting pages and bypass email security filters. Defenders should review M365 audit logs for suspicious device-code authorizations, enforce conditional access policies, and monitor for traffic to known YAM Store domains to prevent identi

Source: https://windowsforum.com/news/microsoft-disrupts-yam-store-network-behind-1-billion-phishing-scams-and-m365-device-code-attacks.448313/post-1012947

## Inside an AI‑enabled device code phishing campaign | Microsoft Security Blog

**PIR:** 1.d.2

Threat actors are integrating generative AI to automate device-code phishing campaigns, dynamically generating realistic login pages and contextual lures that adapt to victim behavior. The AI-driven infrastructure scales attacks rapidly while evading signature-based detection. Defenders should deploy AI-aware web filtering, monitor for anomalous OAuth consent requests, and enforce strict conditional access rules to block automated identity harvesting attempts.

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA

**PIR:** 1.c.1

Threat actors increasingly leverage ephemeral cloud resources, serverless functions, and containerized environments to host phishing infrastructure, evading traditional IP-based blocklists. This report details how attackers abuse cloud-native APIs to dynamically provision phishing domains and redirect traffic, complicating takedown efforts. Infrastructure defenders must implement cloud workload protection platforms, enforce strict IAM policies, and monitor for anomalous resource provisioning pat

Source: https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns

## Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US

**PIR:** 1.b.1

Device code phishing has emerged as a primary vector for identity takeover, allowing attackers to bypass traditional password and MFA defenses by exploiting OAuth 2.0 authorization flows. This analysis outlines the attack lifecycle, detection signatures, and mitigation strategies for enterprise environments. IT infrastructure teams must prioritize monitoring of device code endpoints, implement just-in-time access controls, and educate users on recognizing authorization prompts.

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## Microsoft Teams Phishing via Fake IT Helpdesk Impersonation (External Chat, Vishing, Screen Sharing, RMM

**PIR:** 1.e.3

Attackers are exploiting Microsoft Teams’ external chat and screen-sharing features to impersonate IT helpdesk personnel, tricking users into granting remote access via RMM tools. This vishing and social engineering campaign bypasses traditional email filters by operating entirely within collaboration platforms. Defenders should disable external Teams messaging where possible, enforce multi-factor authentication for RMM access, and train staff to verify helpdesk requests through out-of-band chan

Source: https://intel.threadlinqs.com/threat/TL-2026-3778

## Access granted: phishing with device code authorization for account takeover | Proofpoint US

**PIR:** 1.b.3

This foundational report details how attackers leverage device code authorization flows to harvest valid access tokens, effectively bypassing multi-factor authentication. By directing users to malicious consent pages, threat actors gain persistent access to cloud identities. Defenders should audit Azure AD sign-in logs for device code flows, restrict third-party app registrations, and deploy identity protection solutions to detect and block anomalous authorization requests.

Source: https://www.proofpoint.com/us/blog/threat-insight/access-granted-phishing-device-code-authorization-account-takeover

## n8n Weaponized for Phishing and Device Fingerprinting

**PIR:** 1.d.1

Cybercriminals are repurposing the open-source workflow automation tool n8n to orchestrate phishing campaigns and collect detailed device fingerprints. By chaining n8n workflows with browser fingerprinting scripts, attackers tailor phishing payloads to specific victim environments, increasing success rates. IT teams must monitor for unauthorized n8n deployments, restrict outbound API calls from automation servers, and deploy browser fingerprinting detection in web proxies to disrupt these adapti

Source: https://labs.cloudsecurityalliance.org/research/csa-research-note-n8n-ai-workflow-phishing-20260416-csa-styl

