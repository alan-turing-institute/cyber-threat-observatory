# Daily phishing and identity campaigns

- **Report date:** 2026-09-04
- **Sources:** ketch OSINT (3 queries)

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.a

This campaign represents a major escalation in threat actor sophistication, shifting from static scripts to fully AI-driven infrastructure and end-to-end automation. Building on the Storm-2372 campaign from early 2025, attackers now leverage machine learning to dynamically generate phishing pages, optimize delivery timing, and evade detection. IT defenders must prioritize monitoring for automated device code requests, implement conditional access policies that restrict device code flows, and dep

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US

**PIR:** 1.b

Device code phishing continues to mature as a primary vector for identity takeover, bypassing traditional multi-factor authentication by leveraging legitimate OAuth 2.0 device authorization flows. Attackers trick users into entering codes on malicious sites, granting them direct access to corporate accounts without passwords or MFA prompts. Defenders should audit OAuth consent grants, enforce strict device code policies, and educate users on recognizing legitimate Microsoft/Google device code pr

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## When checking the URL isn’t enough: phishing via the Microsoft identity platform | Securelist

**PIR:** 1.c

Modern phishing campaigns increasingly exploit the Microsoft identity platform’s legitimate endpoints, making URL inspection insufficient for detection. Attackers host malicious pages on trusted domains or use URL shorteners and redirect chains that resolve to authentic Microsoft login flows. Security teams must shift from perimeter-based URL filtering to behavioral analytics, monitoring for anomalous authentication patterns, and implementing strict conditional access rules to mitigate identity 

Source: https://securelist.com/microsoft-device-code-phishing-attack/120350/

## Device Code Phishing: Turning a Convenience Feature Into an MFA Bypass | Trend Micro (US)

**PIR:** 1.d

Originally designed for seamless cross-device authentication, the device code flow has been weaponized to circumvent MFA protections. Threat actors distribute malicious links prompting users to visit legitimate authentication portals and enter generated codes, effectively handing over session tokens. Infrastructure defenders should disable unnecessary device code grants, enforce risk-based authentication, and deploy real-time alerting for high-privilege account logins originating from device cod

Source: https://www.trendmicro.com/en_us/research/26/g/device-code-phishing.html

## Microsoft 365 device code phishing campaign bypasses password stealing | RL Blog

**PIR:** 1.e

This campaign demonstrates a strategic pivot away from traditional credential harvesting toward direct session token acquisition via device code phishing. By targeting Microsoft 365 environments, attackers bypass password-based defenses and MFA entirely, gaining immediate access to email, files, and collaboration tools. Defenders must prioritize zero-trust identity controls, monitor for unusual OAuth token issuance, and implement automated response playbooks to revoke compromised sessions instan

Source: https://www.reversinglabs.com/blog/device-code-phishing-campaign

## Operation HookedWing: 4-Year Campaign Compromises 500 Orgs - Phishing

**PIR:** 1.f

Operation HookedWing reveals a persistent, multi-year phishing campaign that successfully infiltrated over 500 organizations through carefully crafted social engineering and infrastructure reuse. The threat actors maintained low visibility by rotating domains, leveraging compromised legitimate services, and targeting mid-tier employees with high-privilege access. Defenders should focus on threat hunting for dormant credentials, implementing continuous authentication monitoring, and conducting re

Source: https://dailysecurityreview.com/phishing/operation-hookedwing-4-year-campaign-compromises-500-orgs/

## Massive “TrustTrap” Phishing Campaign Exploits Human Perception, Targets Government Services Across US, India, and Beyond

**PIR:** 1.g

The TrustTrap campaign leverages advanced visual spoofing and psychological manipulation to mimic official government portals, successfully harvesting credentials from public sector employees across multiple regions. By exploiting cognitive biases and trusted branding, attackers bypass traditional security awareness training. Infrastructure teams should deploy AI-driven visual similarity detection, enforce strict domain reputation filtering, and implement multi-layered identity verification for 

Source: https://cyberp1.com/massive-trusttrap-phishing-campaign-exploits-human-perception-targets-government-services-across-us-india-and-beyond/

## Energy/Infrastructure Enterprises Targeted by HTML Phishing Campaign

**PIR:** 1.h

This campaign specifically targets critical energy and infrastructure sectors using sophisticated HTML-based phishing pages that dynamically load malicious payloads based on user interaction. Attackers exploit sector-specific compliance workflows and vendor communication patterns to increase click-through rates. Defenders must prioritize email security gateways with advanced HTML sandboxing, enforce strict web content filtering, and conduct sector-tailored phishing simulations to reduce suscepti

Source: https://cofense.com/blog/energy-infrastructure-enterprises-targeted-by-html-phishing-campaign

