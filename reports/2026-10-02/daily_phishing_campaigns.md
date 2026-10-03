# Daily phishing and identity campaigns

- **Report date:** 2026-10-02
- **Sources:** ketch OSINT (3 queries)

## Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA

**PIR:** 1.e

Threat actors increasingly leverage ephemeral cloud resources, serverless functions, and containerized environments to host phishing infrastructure. This report details how attackers bypass traditional IP-based blocklists by dynamically provisioning domains and hosting assets across major cloud providers, forcing defenders to adopt cloud-native telemetry and behavioral analysis for detection.

Source: https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns

## AI-Generated Lures Behind Microsoft Cloud Account Takeovers

**PIR:** 1.b

Generative AI models are now crafting highly personalized, context-aware phishing lures that successfully trick users into surrendering Microsoft cloud credentials. The analysis reveals how AI-driven content generation reduces campaign development time while increasing success rates, necessitating advanced email security gateways and user training focused on AI-generated deception patterns.

Source: https://labs.cloudsecurityalliance.org/research/csa-research-note-genai-passkey-phishing-msft-20260914-csa-s

## Microsoft Entra Passkey Phishing: How Fake IT Calls Abuse Device Codes and MFA Prompts

**PIR:** 1.c

Attackers are combining vishing with Microsoft Entra device code flows to bypass passkey and MFA protections. By impersonating IT support, adversaries guide users to enter legitimate device codes on attacker-controlled endpoints, effectively hijacking authentication sessions. Infrastructure defenders must monitor for anomalous device code usage and implement conditional access policies to mitigate this hybrid attack vector.

Source: https://windowsforum.com/news/microsoft-entra-passkey-phishing-how-fake-it-calls-abuse-device-codes-and-mfa-prompts.446452

## AI-Enabled Device Code Phishing Campaign Abuses Device Code Sign-In Flow

**PIR:** 1.g

This campaign exploits the OAuth 2.0 device authorization grant by using AI to dynamically generate convincing login prompts. Attackers target enterprise users, capturing valid tokens that bypass traditional MFA. The report provides technical indicators, flow analysis, and mitigation strategies for securing device code endpoints and detecting token theft in cloud identity environments.

Source: https://captechgroup.com/threat-intelligence-center/ai-enabled-device-code-phishing-campaign-abuses-de-81a334

## OAuth Device Code Phishing: M365 Defense Guide

**PIR:** 1.g

A comprehensive defense guide addressing the rising threat of OAuth device code phishing against Microsoft 365 tenants. The article outlines architectural weaknesses in the device authorization flow, demonstrates real-world bypass techniques, and provides actionable configuration steps for Conditional Access, token lifetime restrictions, and monitoring to protect infrastructure credentials.

Source: https://protego.me/blog/oauth-device-code-phishing-mfa-bypass-microsoft-365

## Tycoon2FA Returns: PhaaS Platform Survives Law Enforcement Disruption

**PIR:** 1.f

Despite coordinated takedowns, the Tycoon2FA Phishing-as-a-Service platform has rapidly reconstituted using decentralized hosting and automated infrastructure provisioning. This research examines the platform's resilience mechanisms, subscription model, and how it enables low-skill actors to launch sophisticated MFA-bypass campaigns, highlighting the need for proactive threat intelligence sharing.

Source: https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/03/CSA_research_note_Tycoon2FA-PhaaS-resurrection-MaaS-resilience-20260326-csa-styled.pdf

## The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations

**PIR:** 1.d

The evolution of phishing campaigns now features fully autonomous AI agents that handle reconnaissance, payload generation, and adaptive delivery. This shift eliminates human bottlenecks, enabling continuous, multi-vector attacks against enterprise infrastructure. Defenders must transition from static rule-based defenses to AI-driven detection and automated response frameworks.

Source: https://itsecurityguru.org/2026/05/27/the-ai-phishing-revolution-from-spray-and-pray-to-autonomous-operations

## GhostCode attackers abuse device codes to take over Microsoft 365 accounts

**PIR:** 1.g

The GhostCode threat group has weaponized Microsoft 365 device code authentication to execute large-scale account takeovers. By distributing malicious scripts that prompt users to authorize device codes, attackers harvest valid access tokens. The article details the group's infrastructure, token harvesting techniques, and recommended identity protection controls for enterprise environments.

Source: https://computerworld.com/article/4223889/ghostcode-attackers-abuse-device-codes-to-take-over-microsoft-365-accounts.html

