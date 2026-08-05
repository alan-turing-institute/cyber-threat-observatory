# Daily phishing and identity campaigns

- **Report date:** 2026-08-04
- **Sources:** ketch OSINT (3 queries)

## Phishers are hijacking legitimate cloud infrastructure

**PIR:** 1.d

Attackers increasingly abuse legitimate cloud platforms to host phishing campaigns, bypassing traditional URL reputation filters. This report details how threat actors leverage cloud storage, serverless functions, and CDN services to dynamically serve malicious login pages. Defenders must implement strict cloud security posture management, monitor for anomalous resource creation, and deploy identity-aware web gateways to detect and block infrastructure abuse in real time.

Source: https://securelist.com/cloud-platforms-in-phishing/120832/

## When checking the URL isn’t enough: phishing via the Microsoft identity platform | Securelist

**PIR:** 1.b

Modern phishing campaigns exploit the Microsoft identity platform by leveraging legitimate OAuth endpoints and device code flows to bypass traditional URL-based defenses. Attackers craft convincing prompts that redirect users to authentic Microsoft domains, making visual inspection ineffective. Infrastructure defenders should enforce conditional access policies, monitor for suspicious device code requests, and deploy identity protection tools that analyze authentication context rather than relyi

Source: https://securelist.com/microsoft-device-code-phishing-attack/120350/

## Inside Kali365, a Device Code Phishing Ecosystem | Huntress

**PIR:** 1.c

Kali365 operates as a sophisticated Phishing-as-a-Service (PhaaS) platform specializing in device code attacks. The ecosystem provides affiliates with customizable landing pages, automated token harvesting, and real-time credential forwarding. Defenders must monitor for anomalous OAuth device code requests, implement step-up authentication for sensitive actions, and integrate threat intelligence feeds to block known Kali365 infrastructure and associated redirect domains.

Source: https://www.huntress.com/blog/kali365-device-code-phishing-kit

## Device Code Phishing: Turning a Convenience Feature Into an MFA Bypass | Trend Micro (US)

**PIR:** 1.b

Device code authentication, designed for screenless devices, is increasingly weaponized to bypass multi-factor authentication. Attackers trick users into entering codes on malicious sites, granting them direct access to accounts without triggering traditional MFA prompts. IT infrastructure teams should restrict device code flows to approved applications, enforce risk-based authentication, and deploy user education campaigns highlighting the dangers of entering verification codes on untrusted pla

Source: https://www.trendmicro.com/en_us/research/26/g/device-code-phishing.html

## IronToll: Global Government-Impersonation PhaaS | PhishEye

**PIR:** 1.c

IronToll is a large-scale PhaaS operation targeting government and enterprise sectors through highly customized impersonation campaigns. The platform offers affiliates modular phishing kits, automated domain generation, and credential harvesting dashboards. Defenders should monitor for newly registered domains mimicking government agencies, implement email authentication standards (DMARC/DKIM/SPF), and deploy AI-driven phishing detection to identify template variations and dynamic content inject

Source: https://phisheye.com/blog/irontoll-iron-man-phaas-campaign

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.e

Threat actors are integrating generative AI to automate and personalize device code phishing attacks at scale. AI models dynamically generate context-aware prompts, adapt language based on user interaction, and optimize landing pages for higher conversion rates. Infrastructure defenders must deploy behavioral analytics to detect AI-generated content patterns, enforce strict OAuth scope limitations, and implement continuous authentication monitoring to identify anomalous device code usage across 

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## Talos: Attackers Refine Phishing Playbook To Target Critical Infrastructure

**PIR:** 1.g

Cybercriminals are adapting phishing tactics to specifically target healthcare, local government, and critical infrastructure sectors. Campaigns leverage trusted technology abuse, supply chain impersonation, and sector-specific lures to evade detection. Defenders should implement zero-trust network architectures, enforce strict email filtering with AI-based content analysis, and conduct regular phishing simulations tailored to critical infrastructure workflows to strengthen human and technical d

Source: https://securityledger.com/2026/07/talos-attackers-refine-phishing-playbook-to-target-critical-infrastructure/

## Operation HookedWing: Four-Year Phishing Campaign Hits 500 ...

**PIR:** 1.g

Operation HookedWing represents a persistent, long-running credential harvesting campaign targeting aviation, critical infrastructure, and government entities. Attackers utilize rotating domains, legitimate cloud hosting, and social engineering tailored to sector-specific compliance requirements. Infrastructure defenders must maintain continuous threat hunting for known HookedWing indicators, enforce multi-factor authentication with phishing-resistant methods, and monitor for lateral movement fo

Source: https://cybersecurityjournal.ca/techtalk/84066-operation-hookedwing-phishing-aviation-critical-infrastructure-2026-05-11/

