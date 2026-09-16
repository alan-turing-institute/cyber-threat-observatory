# Daily phishing and identity campaigns

- **Report date:** 2026-09-14
- **Sources:** ketch OSINT (3 queries)

## Microsoft: Passkey Help Desk Calls Are Hijacking Cloud Accounts, Then Draining SharePoint

**PIR:** 1.f.2

Attackers are exploiting social engineering via fake help desk calls to trick IT staff into initiating passkey registration flows. Once registered, threat actors hijack cloud accounts and systematically drain SharePoint repositories. This campaign highlights a critical gap in identity verification processes and underscores the need for strict change-management protocols for authentication methods. Infrastructure defenders must implement multi-person approval for passkey additions and monitor for

Source: https://threat-intelligence.redeyesecurity.com/blog/passkey-phishing-microsoft-cloud-hijack-storm-3032-2026

## Storm-3121 Fakes Passkey Portals to Steal M365 Data

**PIR:** 1.f.1

The Storm-3121 threat group has deployed sophisticated phishing portals that mimic Microsoft’s native passkey registration interface. By intercepting authentication-in-motion tokens, attackers bypass traditional MFA and gain persistent access to M365 environments. Defenders should deploy conditional access policies that restrict passkey registration to known corporate networks and monitor for rapid credential validation followed by bulk data exfiltration.

Source: https://0daynews.com/articles/2026-09-12-shinyhunters-passkey-phishing-m365-aitm

## Device Code Phishing Surge — Threat Analysis

**PIR:** 1.b.3

A significant increase in device code phishing campaigns is targeting organizations relying on Microsoft’s device code authentication flow. Attackers host malicious pages that prompt users to visit a legitimate Microsoft login URL, tricking them into authorizing attacker-controlled sessions. This technique effectively bypasses MFA without requiring credential theft. Infrastructure teams should disable device code flows where possible and implement user education focused on recognizing unauthoriz

Source: https://intel.threadlinqs.com/threat/TL-2026-2468

## AI-Enabled Device Code Phishing Campaign Abuses Device Code Sign-In Flow

**PIR:** 1.c.2

Threat actors are leveraging AI to dynamically generate highly convincing device code phishing pages that adapt to target domains and branding. The campaign automates the delivery of tailored prompts, significantly increasing success rates. By abusing the legitimate device code sign-in flow, attackers harvest valid access tokens. Defenders must prioritize token lifecycle management, enforce strict conditional access rules, and deploy AI-driven detection to identify anomalous authorization patter

Source: https://captechgroup.com/threat-intelligence-center/ai-enabled-device-code-phishing-campaign-abuses-de-81a334

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.c.1

Microsoft’s security research details an advanced campaign combining AI-generated lures with device code authentication abuse. The threat actors use machine learning to optimize phishing page layouts and timing, maximizing victim interaction. By capturing valid OAuth tokens, they bypass password and MFA protections entirely. The report provides actionable mitigation strategies, including restricting device code flows, implementing token-bound policies, and leveraging Microsoft Defender for Cloud

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## Dual-RMM Phishing And PowerShell RAT Campaign Hits SLTTs

**PIR:** 1.e.4

A targeted campaign against state, local, tribal, and territorial governments combines phishing lures with dual RMM software deployment and a PowerShell-based RAT. Attackers use initial access to install legitimate remote management tools, establishing persistent backdoors that evade traditional endpoint detection. Infrastructure defenders should enforce strict RMM whitelisting, monitor for unauthorized PowerShell execution chains, and implement network segmentation to limit lateral movement pos

Source: https://www.hendryadrian.com/dual-rmm-phishing-and-powershell-rat-campaign-hits-sltts/

## The Device Code Phishing Tsunami: What We’re Seeing in the Wild

**PIR:** 1.b.1

Operational analysis reveals a massive wave of device code phishing attacks exploiting the OAuth 2.0 device authorization grant. Attackers are distributing malicious QR codes and short URLs via email and messaging platforms. Once scanned, victims are directed to legitimate Microsoft login pages, unknowingly granting attackers session tokens. Infrastructure defenders should monitor for high volumes of device code requests, restrict grant types to essential services, and implement real-time alerti

Source: https://www.levelblue.com/blogs/spiderlabs-blog/the-device-code-phishing-tsunami-what-were-seeing-in-the-wild

## Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns

**PIR:** 1.d.2

Modern phishing operations are increasingly leveraging cloud-native services like serverless functions, CDN networks, and managed DNS to host malicious infrastructure. This approach provides attackers with high availability, geographic distribution, and resilience against takedown efforts. Defenders must shift from static URL blocking to behavioral analysis, monitoring for newly provisioned cloud resources, anomalous DNS resolutions, and infrastructure patterns associated with phishing-as-a-serv

Source: https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns

