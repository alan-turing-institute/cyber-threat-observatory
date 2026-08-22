# Daily phishing and identity campaigns

- **Report date:** 2026-08-20
- **Sources:** ketch OSINT (3 queries)

## OAuth Device Code Phishing: 37x Surge in Enterprise ATO

**PIR:** 1.e

This Cloud Security Alliance research note details a dramatic 37-fold increase in enterprise account takeover incidents driven by OAuth device code phishing. Attackers exploit the device authorization flow to bypass traditional MFA controls, tricking users into entering verification codes on malicious domains. The report provides infrastructure defenders with detection signatures, network traffic indicators, and policy recommendations to mitigate this rapidly escalating identity threat vector.

Source: https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/04/CSA_research_note_oauth-device-code-phishing-surge_20260405-csa-styled.pdf

## Device Code Phishing — The Attack That Makes MFA Irrelevant

**PIR:** 1.d

CyberGrind analyzes how device code phishing campaigns systematically neutralize multi-factor authentication by leveraging legitimate OAuth consent flows. The article breaks down the technical mechanics of the attack, highlighting how defenders can identify compromised sessions through anomalous token issuance patterns. It offers actionable mitigation strategies, including conditional access policy adjustments and real-time alerting configurations for identity protection platforms.

Source: https://cybergrind.org/blog/2026-06-02-device-code-phishing

## The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations

**PIR:** 1.f

This analysis explores the shift from manual, broad-spectrum phishing to fully autonomous, AI-driven campaigns that dynamically adapt content, timing, and targeting based on real-time user behavior. The article outlines how machine learning models enable attackers to generate highly personalized lures at scale, overwhelming traditional email security gateways. Defenders are advised to implement behavioral analytics and AI-augmented threat detection to counter these evolving tactics.

Source: https://itsecurityguru.org/2026/05/27/the-ai-phishing-revolution-from-spray-and-pray-to-autonomous-operations

## Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns

**PIR:** 1.g

CYFIRMA investigates how threat actors leverage compromised cloud workloads, serverless functions, and CDN edge nodes to host phishing infrastructure that evades traditional blocklists. The report details techniques for abusing legitimate cloud services to mirror corporate login pages and exfiltrate credentials. Infrastructure teams are provided with cloud security posture management recommendations and network egress filtering strategies to disrupt these resilient hosting environments.

Source: https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns

## Tycoon2FA Returns: PhaaS Platform Survives Law Enforcement Disruption

**PIR:** 1.j

Following a major law enforcement takedown, the Tycoon2FA Phishing-as-a-Service platform has rapidly reconstituted its operations using decentralized hosting and encrypted communication channels. This CSA research note examines the platform’s resilience, detailing how it facilitates MFA interception and session hijacking for affiliate operators. Defenders are guided through threat hunting methodologies focused on identifying PhaaS infrastructure patterns and blocking associated C2 domains.

Source: https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/03/CSA_research_note_Tycoon2FA-PhaaS-resurrection-MaaS-resilience-20260326-csa-styled.pdf

## Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA

**PIR:** 1.h

CISA has issued an alert regarding a zero-click phishing campaign targeting Zimbra email servers, exploiting a critical vulnerability to deliver malicious payloads without user interaction. The article outlines the attack chain, which leverages crafted email headers to trigger automatic rendering of malicious content. Infrastructure defenders are advised to apply emergency patches, restrict server exposure, and monitor for anomalous outbound connections indicative of compromised mail systems.

Source: https://tempmail.ninja/blog/laundry-bear-zimbra-phishing

## PhantomEnigma: How a Malware Crew Turned Brazilian Government Sites Into Trusted Malware Hubs

**PIR:** 1.i

This report details how the PhantomEnigma group compromised official Brazilian government websites to host phishing pages and malware distribution portals, leveraging inherent user trust to bypass security controls. The analysis covers the initial access vectors, persistence mechanisms, and infrastructure pivoting techniques used. Defenders are provided with indicators of compromise and recommendations for implementing strict web application firewalls and domain reputation monitoring.

Source: https://securebulletin.com/phantomenigma-how-a-malware-crew-turned-brazilian-government-sites-into-trusted-malware-hubs

## Three Active Microsoft 365 Phishing Campaigns Targeting Schools and Government Agencies

**PIR:** 1.b

Forsyte IT identifies three concurrent phishing campaigns specifically engineered to compromise Microsoft 365 accounts within educational and public sector environments. The campaigns utilize sophisticated domain spoofing and credential harvesting portals mimicking Microsoft login flows. The article provides detailed email headers, malicious URLs, and recommended Exchange Online Protection rules to help infrastructure teams rapidly block these targeted attacks and protect sensitive institutional

Source: https://forsyteit.com/three-active-microsoft-365-phishing-campaigns-targeting-schools-and-government-agencies

