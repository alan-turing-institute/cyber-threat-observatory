# Daily phishing and identity campaigns

- **Report date:** 2026-10-09
- **Sources:** ketch OSINT (3 queries)

## GhostCode attackers abuse device codes to take over Microsoft 365 accounts

**PIR:** 1.h

The GhostCode threat group exploits Microsoft 365 device code authentication flows to hijack user accounts, bypassing traditional email-based phishing filters. By directing victims to legitimate Microsoft login portals with pre-generated device codes, attackers capture session tokens upon approval. Infrastructure defenders should monitor for anomalous device code grant events, restrict interactive login capabilities for high-privilege accounts, and deploy identity protection tools that flag susp

Source: https://computerworld.com/article/4223889/ghostcode-attackers-abuse-device-codes-to-take-over-microsoft-365-accounts.html

## Fake IT Help Desk Phishing Campaign Hits Blackstone, Bridgewater, KKR: Detecting and Defeating MFA Credential Theft

**PIR:** 1.e

A sophisticated phishing campaign impersonating IT help desks has targeted major financial firms, successfully bypassing MFA through real-time credential relay and social engineering. Attackers leverage urgency and authority to trick users into surrendering session tokens or approving push notifications. Infrastructure teams must enforce phishing-resistant MFA, implement conditional access policies that block help-desk credential resets, and deploy user awareness training focused on verifying su

Source: https://securityarsenal.com/blog/fake-it-help-desk-phishing-campaign-hits-blackstone-bridgewater-kkr-detecting-and-defeating-mfa-credential-theft

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.h

Microsoft researchers detail a campaign combining AI-generated lures with device code authentication abuse to compromise enterprise accounts. Attackers use LLMs to craft highly personalized prompts that trick users into entering device codes on malicious sites, which are then relayed to Microsoft’s legitimate auth endpoints. Defenders must implement risk-based conditional access, monitor for rapid device code approvals, and educate users on the dangers of sharing authentication codes.

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## Device Code Phishing is an Evolution in Identity Takeover

**PIR:** 1.h

Device code phishing represents a significant shift in identity compromise tactics, leveraging Microsoft’s OAuth 2.0 device authorization grant to bypass email security controls. Since the phishing payload redirects to legitimate Microsoft domains, traditional URL filtering fails. Infrastructure teams should prioritize monitoring Azure AD sign-in logs for device code flows, enforce non-interactive app restrictions, and deploy identity threat detection solutions that correlate authentication anom

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA

**PIR:** 1.g

Attackers increasingly leverage cloud-native services like serverless functions, object storage, and CDN providers to host phishing infrastructure, bypassing traditional domain reputation filters. This report details how threat actors abuse legitimate cloud APIs to dynamically generate and rotate phishing domains, complicating takedown efforts. Infrastructure defenders must implement strict egress controls, monitor for anomalous cloud resource provisioning, and integrate cloud-native telemetry i

Source: https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns

## The Alert Gap: Hunting an Undetected Device Code Phishing Compromise

**PIR:** 1.j

This analysis reveals how device code phishing campaigns often evade standard security alerts due to legitimate-looking authentication endpoints and delayed token usage. Threat hunters demonstrate techniques for identifying compromised accounts by analyzing sign-in velocity, geographic anomalies, and post-authentication lateral movement. Defenders should implement proactive hunting playbooks, tune identity alert thresholds, and integrate behavioral analytics to close detection gaps in modern ide

Source: https://www.cyberproof.com/blog/the-alert-gap-how-threat-hunting-surfaced-an-undetected-device-code-phishing-compromise/

## n8n Weaponized for Phishing and Device Fingerprinting

**PIR:** 1.f

Open-source workflow automation tools like n8n are being repurposed by threat actors to orchestrate large-scale phishing operations and collect device fingerprints. By chaining HTTP requests, data parsing, and conditional logic, attackers automate victim profiling and credential harvesting without relying on traditional botnets. Defenders should monitor for unauthorized n8n instances, restrict outbound API calls from automation platforms, and analyze network traffic for characteristic workflow-g

Source: https://labs.cloudsecurityalliance.org/research/csa-research-note-n8n-ai-workflow-phishing-20260416-csa-styl

## The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations

**PIR:** 1.f

Generative AI is transforming phishing from broad, low-success campaigns into highly targeted, autonomous operations. LLMs now craft context-aware lures, dynamically adapt to victim responses, and automate multi-stage social engineering at scale. Defenders must shift from signature-based detection to behavioral analytics, monitor for AI-generated linguistic patterns, and enforce strict email authentication alongside advanced URL sandboxing to counter these adaptive threats.

Source: https://itsecurityguru.org/2026/05/27/the-ai-phishing-revolution-from-spray-and-pray-to-autonomous-operations

