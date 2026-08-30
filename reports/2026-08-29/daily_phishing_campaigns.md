# Daily phishing and identity campaigns

- **Report date:** 2026-08-29
- **Sources:** ketch OSINT (3 queries)

## OAuth Device Code Phishing: 37x Surge in Enterprise ATO

**PIR:** 1.j.3

This Cloud Security Alliance report details a 37-fold increase in enterprise account takeovers driven by OAuth device code phishing. Attackers exploit the device authorization flow to bypass traditional MFA, tricking users into entering codes on malicious domains. Infrastructure defenders must monitor for anomalous OAuth consent requests, implement conditional access policies that restrict device flow usage, and deploy identity threat detection rules targeting illicit consent grants.

Source: https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/04/CSA_research_note_oauth-device-code-phishing-surge_20260405-csa-styled.pdf

## Device Code Phishing — The Attack That Makes MFA Irrelevant

**PIR:** 1.j.3

CyberGrind analyzes how device code phishing neutralizes multi-factor authentication by leveraging legitimate OAuth endpoints. The article provides technical breakdowns of the attack chain, highlighting how defenders can detect malicious redirect URIs and abnormal token issuance patterns. Recommendations include enforcing strict OAuth scope limitations, deploying identity-aware proxies, and training users to recognize device flow prompts.

Source: https://cybergrind.org/blog/2026-06-02-device-code-phishing

## The Illicit Consent Grant Part 2: Device-Code Phishing and the AI PhaaS Wave

**PIR:** 1.f

SlashID explores the convergence of illicit consent grants, device-code phishing, and AI-driven phishing-as-a-service platforms. The report outlines how automated infrastructure scales credential harvesting at unprecedented rates. Defenders are advised to audit third-party OAuth applications, implement continuous consent monitoring, and integrate AI-detection heuristics into email and web gateways to mitigate automated takeover campaigns.

Source: https://slashid.com/blog/illicit-consent-grant-part-2

## Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns

**PIR:** 1.h

CYFIRMA examines threat actors leveraging cloud-native services like serverless functions, object storage, and CDN networks to host phishing infrastructure. By blending malicious payloads with legitimate cloud traffic, attackers evade traditional perimeter defenses. The report provides detection strategies for cloud workload protection platforms, including anomaly detection in API calls, DNS sinkholing for dynamic domains, and cloud security posture management integrations.

Source: https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns

## Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA

**PIR:** 1.g

This analysis covers a CISA-warned zero-click phishing campaign targeting Zimbra email servers. Attackers exploit server-side vulnerabilities to inject malicious payloads without user interaction, bypassing email security gateways. Infrastructure teams should prioritize patching Zimbra instances, implementing strict network segmentation for mail servers, and deploying endpoint detection rules for zero-click exploitation indicators.

Source: https://tempmail.ninja/blog/laundry-bear-zimbra-phishing

## Three Active Microsoft 365 Phishing Campaigns Targeting Schools and Government Agencies

**PIR:** 1.a

Forsyte IT details three concurrent phishing campaigns exploiting Microsoft 365 authentication flows to compromise educational and government networks. The attacks leverage credential harvesting portals mimicking M365 login pages and abuse legacy authentication protocols. Defenders are urged to disable basic auth, enforce phishing-resistant MFA, and configure Microsoft Defender for Office 365 to block suspicious URL redirects.

Source: https://forsyteit.com/three-active-microsoft-365-phishing-campaigns-targeting-schools-and-government-agencies

## Tycoon2FA Returns: PhaaS Platform Survives Law Enforcement Disruption

**PIR:** 1.b

The CSA tracks the rapid resurrection of the Tycoon2FA phishing-as-a-service platform following law enforcement takedowns. The report highlights how threat actors utilize decentralized hosting, domain generation algorithms, and rapid infrastructure pivoting to maintain operations. Infrastructure defenders should monitor for newly registered domains with high SSL certificate turnover and deploy web application firewalls tuned to PhaaS patterns.

Source: https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/03/CSA_research_note_Tycoon2FA-PhaaS-resurrection-MaaS-resilience-20260326-csa-styled.pdf

## Zero-click email attacks: What businesses need to know

**PIR:** 1.g

This guide explains the mechanics of zero-click email attacks that exploit rendering engines and preview panes to execute code without user interaction. It outlines the risks to corporate email infrastructure and provides actionable defense strategies, including disabling automatic image loading, sandboxing email clients, and deploying advanced threat protection with heuristic analysis to harden email gateways.

Source: https://itpro.com/security/phishing/zero-click-email-attacks-what-businesses-need-to-know

