# Daily phishing and identity campaigns

- **Report date:** 2026-08-07
- **Sources:** ketch OSINT (3 queries)

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.j.3

Threat actors are leveraging AI and end-to-end automation to scale device code phishing attacks, bypassing traditional email filters. This campaign generates live authentication codes on demand, significantly increasing success rates and enabling sustained post-compromise access. Infrastructure defenders must monitor OAuth consent grants and implement conditional access policies to mitigate these evolving identity takeover tactics.

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## When checking the URL isn’t enough: phishing via the Microsoft identity platform

**PIR:** 1.j.3

Attackers are exploiting legitimate Microsoft identity endpoints to conduct sophisticated phishing campaigns that evade standard URL-based detection. By leveraging authorized OAuth flows, threat actors trick users into granting malicious tokens, rendering traditional link inspection ineffective. Defenders should prioritize monitoring for anomalous token issuance, restrict third-party app permissions, and deploy identity-aware network controls to block unauthorized access.

Source: https://securelist.com/microsoft-device-code-phishing-attack/120350/

## New widespread EvilTokens kit: device code phishing as-a-service

**PIR:** 1.j.3

The EvilTokens toolkit has emerged as a commercialized device code phishing-as-a-service platform, lowering the barrier for credential theft. It automates the generation of malicious OAuth consent pages and token harvesting, targeting enterprise environments. Security teams must audit delegated permissions, enforce multi-factor authentication with phishing-resistant methods, and monitor for suspicious device code requests in identity logs.

Source: https://www.sekoia.com/blog/new-widespread-eviltokens-kit-device-code-phishing-as-a-service-part-1

## Device Code Phishing is an Evolution in Identity Takeover

**PIR:** 1.j.3

Device code phishing represents a significant shift in identity compromise tactics, moving beyond traditional credential harvesting to direct token theft. Attackers exploit legitimate authentication flows to bypass MFA and gain persistent access to cloud environments. Infrastructure defenders should implement strict OAuth consent policies, monitor for unusual device code usage patterns, and educate users on recognizing legitimate verification prompts.

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## Storm-2372 conducts device code phishing campaign

**PIR:** 1.j.3

The Storm-2372 threat group has adopted device code phishing to target government and enterprise networks, leveraging automated infrastructure to distribute malicious OAuth prompts. This campaign highlights the growing sophistication of state-aligned actors in exploiting identity platforms. Defenders must correlate identity telemetry with threat intelligence, restrict app consent workflows, and deploy behavioral analytics to detect anomalous authentication patterns.

Source: https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/

## UK and partners expose Russian state-supported actors for new zero-click phishing campaign

**PIR:** 1.a

Intelligence agencies have uncovered a zero-click phishing campaign orchestrated by Russian state-supported actors, exploiting vulnerabilities in messaging and identity services to compromise targets without user interaction. This technique bypasses traditional email security and user training defenses. Infrastructure teams should prioritize patching known vulnerabilities, segmenting critical identity systems, and monitoring for lateral movement indicators following silent compromises.

Source: https://www.ncsc.gov.uk/news/uk-and-partners-expose-russian-state-supported-actors-for-new-zero-click-phishing-campaign

## The Shadow Campaigns: Uncovering Global Espionage

**PIR:** 1.a

Unit 42 details a sprawling espionage operation utilizing highly targeted spearphishing emails to deploy custom malware across multiple sectors. The campaign leverages realistic document attachments and credential harvesting portals to establish initial access. Defenders should enhance email gateway filtering, deploy sandboxing for macro-enabled documents, and monitor for anomalous outbound connections indicative of command-and-control activity.

Source: https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/

## New APT group breached gov and critical infrastructure orgs in 37 countries

**PIR:** 1.a

A newly identified APT group has successfully breached government and critical infrastructure organizations across 37 nations using sophisticated spearphishing techniques. The attackers employ tailored lures and living-off-the-land binaries to evade detection. Infrastructure defenders must enforce least-privilege access, monitor for suspicious PowerShell execution, and implement robust identity governance to limit blast radius during breaches.

Source: https://www.csoonline.com/article/4128378/new-apt-group-breached-gov-and-critical-industrial-orgs-in-37-countries.html

