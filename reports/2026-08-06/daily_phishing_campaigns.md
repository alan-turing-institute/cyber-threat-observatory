# Daily phishing and identity campaigns

- **Report date:** 2026-08-06
- **Sources:** ketch OSINT (3 queries)

## The Device Code Phishing Tsunami: What We’re Seeing in the Wild

**PIR:** 1.b

Device code phishing has surged as attackers exploit OAuth 2.0 device authorization flows to bypass multi-factor authentication. Victims are tricked into entering short alphanumeric codes on malicious sites, granting attackers direct access to corporate accounts without passwords or MFA prompts. Defenders must monitor for anomalous device code grant requests, restrict OAuth app registrations, and educate users on recognizing device flow prompts. Network visibility into authentication traffic is 

Source: https://www.levelblue.com/blogs/spiderlabs-blog/the-device-code-phishing-tsunami-what-were-seeing-in-the-wild

## The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations

**PIR:** 1.d

Generative AI has transformed phishing from broad, low-success campaigns into highly targeted, autonomous operations. Attackers now use LLMs to craft context-aware emails, dynamically generate landing pages, and automate follow-up sequences based on victim behavior. For infrastructure defenders, this means traditional signature-based email filtering is insufficient. Defenses must shift toward behavioral analytics, AI-driven email authentication validation, and continuous user training to detect 

Source: https://itsecurityguru.org/2026/05/27/the-ai-phishing-revolution-from-spray-and-pray-to-autonomous-operations

## Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US

**PIR:** 1.b

This analysis details how device code phishing has evolved from niche exploits to a primary identity takeover vector. Attackers now automate the generation of fake device code portals that mirror legitimate SSO providers, capturing tokens in real-time. IT infrastructure teams should implement OAuth monitoring, enforce app consent policies, and deploy identity threat detection solutions that flag unusual device flow activity. Proactive configuration of identity providers remains the most effectiv

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## Device Code Phishing — The Attack That Makes MFA Irrelevant

**PIR:** 1.b

By leveraging the device authorization grant, threat actors completely circumvent traditional MFA mechanisms, rendering passwordless and hardware key protections ineffective if users are socially engineered. This article outlines detection strategies for infrastructure defenders, including logging OAuth token issuance, analyzing user-agent strings for automation, and implementing step-up authentication for sensitive actions. Securing the identity perimeter now requires shifting focus from authen

Source: https://cybergrind.org/blog/2026-06-02-device-code-phishing

## Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA

**PIR:** 1.c

Attackers increasingly leverage cloud-native services like serverless functions, object storage, and managed DNS to host phishing pages and credential harvesters. This infrastructure abuse bypasses traditional IP-based blocklists and complicates takedown efforts. IT defenders must monitor cloud provider APIs, implement strict egress controls, and deploy cloud workload protection platforms to detect anomalous resource provisioning. Understanding these tactics is critical for securing hybrid envir

Source: https://www.cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns/

## The Illicit Consent Grant Part 2: Device-Code Phishing and the AI PhaaS Wave | SlashID Blog

**PIR:** 1.f

Combining illicit consent grants with device-code phishing and AI-driven PhaaS platforms, attackers are orchestrating highly scalable identity compromises. This report examines how malicious apps request excessive permissions while using AI to personalize phishing prompts. Defenders must audit registered enterprise applications, enforce least-privilege consent policies, and deploy machine learning models to detect anomalous OAuth flows. Integrating identity telemetry with cloud security posture 

Source: https://slashid.com/blog/illicit-consent-grant-part-2

## Tycoon2FA Returns: PhaaS Platform Survives Law Enforcement Disruption

**PIR:** 1.e

Despite coordinated law enforcement takedowns, the Tycoon2FA Phishing-as-a-Service platform has rapidly re-emerged using decentralized hosting and modular codebases. This resilience highlights the operational maturity of cybercriminal ecosystems. Infrastructure teams should prioritize threat intelligence sharing, monitor for known PhaaS branding and infrastructure patterns, and enforce strict conditional access policies. Detecting PhaaS indicators early can prevent large-scale credential harvest

Source: https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/03/CSA_research_note_Tycoon2FA-PhaaS-resurrection-MaaS-resilience-20260326-csa-styled.pdf

## Three Active Microsoft 365 Phishing Campaigns Targeting Schools and Government Agencies

**PIR:** 1.a

Recent campaigns exploit Microsoft 365 login pages and calendar invitation templates to harvest credentials from educational and public sector networks. Attackers leverage trusted Microsoft domains and spoofed internal senders to increase click-through rates. Infrastructure defenders should validate SPF/DKIM/DMARC records, monitor for suspicious OAuth token requests, and enforce multi-factor authentication with phishing-resistant methods. Regular log analysis of Azure AD sign-ins can reveal earl

Source: https://forsyteit.com/three-active-microsoft-365-phishing-campaigns-targeting-schools-and-government-agencies

