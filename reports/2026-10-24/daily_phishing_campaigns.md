# Daily phishing and identity campaigns

- **Report date:** 2026-10-24
- **Sources:** ketch OSINT (3 queries)

## Joint advisory: state-sponsored spear-phishing campaigns targeting critical infrastructure

**PIR:** 1.h

A Five Eyes joint advisory warns of ongoing state-sponsored spear-phishing campaigns targeting energy, transport, and water sectors. The threat actors employ highly tailored lures, compromised legitimate domains, and advanced evasion techniques to infiltrate critical national infrastructure. Defenders are urged to enhance email authentication, segment OT/IT networks, and monitor for lateral movement indicators following initial compromise.

Source: https://suvat.uk/blog/five-eyes-advisory.html

## Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale | Microsoft Security Blog

**PIR:** 1.e

Microsoft Security researchers dissect the Tycoon2FA adversary-in-the-middle phishing kit, revealing how threat actors bypass multi-factor authentication at scale. The analysis details the kit’s proxy architecture, credential harvesting mechanisms, and infrastructure evasion tactics. IT defenders can leverage these insights to harden identity perimeters, deploy adaptive MFA policies, and detect real-time session hijacking attempts targeting enterprise accounts.

Source: https://www.microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale/

## The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime | Microsoft Security Blog

**PIR:** 1.a

This report maps the underground infrastructure supporting large-scale phishing operations, including domain generation algorithms, bulletproof hosting providers, and traffic routing techniques. Security teams gain actionable intelligence on infrastructure indicators, takedown strategies, and network-level detection rules to disrupt phishing campaigns before they reach end users.

Source: https://www.microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime/

## Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Security Blog

**PIR:** 1.f

Microsoft Security exposes the EvilTokens toolkit, a modular framework designed to automate device code phishing and token theft. The breakdown covers its command-and-control structure, token persistence methods, and abuse of Microsoft Graph APIs. Infrastructure teams can use these findings to tune identity protection alerts, revoke compromised tokens, and enforce conditional access restrictions.

Source: https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/

## Operation HookedWing: Four-Year Phishing Campaign Hits 500+ Organizations in Aviation, Critical Infrastructure, and Government

**PIR:** 1.i

SecurityWeek details Operation HookedWing, a persistent credential-harvesting campaign active since 2022 that has compromised over 500 organizations across aviation and critical infrastructure. The report outlines the attackers’ infrastructure rotation, domain spoofing tactics, and post-compromise data exfiltration. Infrastructure defenders can apply the provided IOCs, strengthen email filtering, and audit third-party access to mitigate similar long-term threats.

Source: https://cybersecurityjournal.ca/techtalk/84066-operation-hookedwing-phishing-aviation-critical-infrastructure-2026-05-11/

## Talos: Attackers Refine Phishing Playbook To Target Critical Infrastructure

**PIR:** 1.i

Cisco Talos reports that threat actors are increasingly abusing trusted cloud services and legitimate SaaS platforms to launch phishing campaigns against healthcare, local government, and critical infrastructure. The analysis highlights infrastructure pivoting, domain fronting, and supply chain email compromises. Defenders should implement strict email security policies, monitor for anomalous cloud API usage, and prioritize identity-centric detection controls.

Source: https://securityledger.com/2026/07/talos-attackers-refine-phishing-playbook-to-target-critical-infrastructure/

## Inside an AI‑enabled device code phishing campaign | Microsoft Security Blog

**PIR:** 1.f

Researchers analyze a sophisticated campaign leveraging generative AI to craft highly convincing device code phishing lures. The attack bypasses traditional email filters by targeting OAuth consent flows, tricking users into authorizing malicious applications. Defenders are advised to monitor for anomalous OAuth grants, restrict device code usage, and implement AI-detection heuristics in email gateways.

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## Inside Wazza: A Newly Observed Device Code Phishing Kit Targeting Microsoft 365 Accounts

**PIR:** 1.f

Level Blue SpiderLabs introduces Wazza, an emerging device code phishing kit specifically engineered to compromise Microsoft 365 tenants. The analysis details its deployment workflow, credential exfiltration endpoints, and evasion of standard MFA prompts. IT administrators should review OAuth application permissions, monitor for suspicious device code sign-ins, and update detection signatures to block Wazza infrastructure.

Source: https://www.levelblue.com/blogs/spiderlabs-blog/inside-wazza-a-newly-observed-device-code-phishing-kit-targeting-microsoft-365-accounts

