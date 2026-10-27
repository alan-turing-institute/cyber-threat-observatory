# Daily phishing and identity campaigns

- **Report date:** 2026-10-26
- **Sources:** ketch OSINT (3 queries)

## Joint advisory: state-sponsored spear-phishing campaigns targeting ...

**PIR:** 1.a

A Five Eyes joint advisory warns critical infrastructure operators of state-sponsored spear-phishing campaigns targeting energy, transport, and water sectors. The threat actors deploy highly tailored lures and malicious attachments to establish initial access. Infrastructure defenders should review email filtering rules, segment OT/IT networks, and monitor for lateral movement indicators aligned with the provided IOCs.

Source: https://suvat.uk/blog/five-eyes-advisory.html

## Reports & advisories | National Cyber Security Centre

**PIR:** 1.a

The NCSC and international partners expose a Russian state-supported zero-click phishing campaign targeting Western organizations. The LAUNDRY BEAR threat group utilizes sophisticated exploit chains delivered via seemingly benign communications to bypass user interaction requirements. Infrastructure teams should prioritize patching known vulnerabilities, implementing network segmentation, and deploying advanced endpoint detection to mitigate silent compromises.

Source: https://www.ncsc.gov.uk/section/keep-up-to-date/reports-advisories

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.j.3

Microsoft security researchers detail a sophisticated campaign leveraging AI-generated lures to exploit OAuth device code flows. Attackers trick users into entering device codes on fraudulent portals, bypassing MFA and enabling full account takeover. The report provides technical indicators, mitigation strategies for identity providers, and guidance for monitoring anomalous OAuth consent events.

Source: https://microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026

## Operation HookedWing: 4-Year Campaign Compromises 500 Orgs - Phishing

**PIR:** 1.e

SOCRadar reveals Operation HookedWing, a long-running credential-harvesting operation that compromised thousands of accounts across critical infrastructure sectors. Attackers leveraged GitHub Pages to host persistent phishing infrastructure, evading traditional blocklists. The report details campaign timelines, targeted verticals, and defensive recommendations for monitoring code hosting platforms and enforcing passwordless authentication.

Source: https://dailysecurityreview.com/phishing/operation-hookedwing-4-year-campaign-compromises-500-orgs/

## AI-enabled device code phishing campaign exploits OAuth flow for account takeover

**PIR:** 1.j.3

This analysis breaks down how threat actors abuse the Microsoft device code authentication mechanism to circumvent multi-factor authentication. By hosting fake login pages that request device codes, attackers gain persistent access to enterprise accounts. The article outlines detection rules for SIEM platforms, recommended conditional access policies, and steps to revoke compromised OAuth grants.

Source: https://helpnetsecurity.com/2026/04/07/microsoft-device-code-phishing-campaign

## Device Code Phishing: How EvilTokens Hit 12,000+ Inboxes

**PIR:** 1.j.3

CTIA Academy examines the EvilTokens campaign, which successfully delivered device code phishing lures to over 12,000 corporate inboxes. The report highlights the technical mechanics of token theft, the role of compromised legitimate domains in hosting phishing pages, and actionable defense playbooks for email security gateways and identity protection teams.

Source: https://ctiacademy.io/blog/device-code-phishing

## Coordinated phishing campaign targeting UK public sector organisations

**PIR:** 1.e

SUVAT identifies a coordinated credential-harvesting campaign targeting UK public sector entities, including NHS trusts and local authorities. Attackers spoof official government domains and deploy realistic email lures to capture staff credentials. Defenders should implement strict DMARC enforcement, monitor for domain impersonation, and enforce multi-factor authentication across all public-facing identity portals.

Source: https://suvat.uk/blog/public-sector-phishing.html

## GhostCode: How Device-Code Phishing Is Hijacking Microsoft 365 Accounts

**PIR:** 1.j.3

GhostCode represents a persistent threat actor group specializing in device code phishing against Microsoft 365 tenants. The campaign uses highly convincing templates and automated infrastructure to harvest codes at scale. Defenders are advised to audit OAuth app permissions, enforce device compliance policies, and monitor for unusual sign-in patterns originating from unfamiliar IP ranges.

Source: https://9to5windows.com/ghostcode-device-code-phishing-microsoft-365-accounts

