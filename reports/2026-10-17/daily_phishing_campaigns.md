# Daily phishing and identity campaigns

- **Report date:** 2026-10-17
- **Sources:** ketch OSINT (3 queries)

## Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale

**PIR:** 1.b

An in-depth technical breakdown of the Tycoon2FA Adversary-in-the-Middle phishing kit, revealing its proxy architecture, session hijacking mechanisms, and deployment tactics. The analysis provides actionable indicators of compromise and mitigation strategies for securing identity providers, blocking reverse proxy traffic, and educating users against real-time credential interception.

Source: https://www.microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale/

## Unmasking EvilTokens: Getting to the root of device code phishing

**PIR:** 1.c

A comprehensive threat intelligence report on the EvilTokens campaign, which abuses Microsoft 365 device code authentication to harvest valid access tokens. Defenders will find detailed telemetry on token exchange patterns, recommended identity protection rules, and architectural adjustments to limit device code abuse across enterprise environments.

Source: https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/

## The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime

**PIR:** 1.a

This report dissects the underground infrastructure supporting large-scale phishing operations, detailing how threat actors leverage cloud services, domain generation algorithms, and bulletproof hosting to evade takedowns. IT defenders can use these insights to enhance DNS filtering, implement stricter cloud posture management, and detect anomalous infrastructure patterns before campaigns scale.

Source: https://www.microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime/

## Device Code Phishing: Turning a Convenience Feature Into an MFA Bypass

**PIR:** 1.c

Analyzes the technical mechanics behind device code phishing attacks that circumvent multi-factor authentication by leveraging legitimate OAuth flows. The research provides network and identity administrators with detection signatures, conditional access policy templates, and user training frameworks to neutralize MFA-bypass attempts without disrupting legitimate remote access workflows.

Source: https://www.trendmicro.com/en_us/research/26/g/device-code-phishing.html

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.c

Explores how attackers weaponize generative AI to craft highly convincing device code phishing lures that bypass traditional email filters. The article outlines the OAuth 2.0 device authorization flow vulnerabilities exploited, offering infrastructure teams guidance on monitoring for suspicious device code requests, implementing conditional access policies, and detecting AI-generated social engineering patterns.

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## SideWinder APT Credential Harvesting Campaign — PaaS Platform Abuse at Scale

**PIR:** 1.d

Investigates how the SideWinder APT group leverages Platform-as-a-Service environments to host credential harvesting infrastructure at scale. The analysis covers PaaS abuse patterns, identity provider misconfigurations exploited, and defensive strategies for cloud workload protection, including runtime monitoring, least-privilege access controls, and automated credential rotation protocols.

Source: https://intel.breakglass.tech/post/sidewinder-mhil-zeabur

## Device Code Phishing: How EvilTokens Hit 12,000+ Inboxes

**PIR:** 1.c

Examines the operational scale and delivery tactics of the EvilTokens device code phishing campaign, highlighting how attackers bypass spam filters and target high-value accounts. Infrastructure teams gain insights into email gateway tuning, threat hunting queries for device code abuse, and incident response playbooks tailored for rapid containment of token-based account takeovers.

Source: https://ctiacademy.io/blog/device-code-phishing

## Three Active Microsoft 365 Phishing Campaigns Targeting Schools and Government Agencies

**PIR:** 1.d

Details three concurrent phishing campaigns exploiting Microsoft 365 login pages to harvest credentials from educational and public sector networks. The report includes campaign timelines, infrastructure indicators, and defensive recommendations for implementing multi-factor authentication enforcement, phishing-resistant credentials, and automated takedown procedures for compromised domains.

Source: https://forsyteit.com/three-active-microsoft-365-phishing-campaigns-targeting-schools-and-government-agencies

