# Daily phishing and identity campaigns

- **Report date:** 2026-08-05
- **Sources:** ketch OSINT (3 queries)

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.j.3

Microsoft details an AI-driven device code phishing campaign that automates authentication code generation. Attackers bypass traditional defenses by dynamically creating valid codes, enabling persistent account access. Defenders should monitor for anomalous device code requests, enforce conditional access policies, and deploy AI-aware detection rules to mitigate this evolving identity threat.

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## Device Code Phishing is an Evolution in Identity Takeover

**PIR:** 1.j.3

Proofpoint analyzes how device code phishing has matured into a primary vector for identity takeover. Threat actors leverage automated infrastructure to harvest credentials and session tokens at scale. Infrastructure teams must implement strict MFA policies, monitor for suspicious OAuth consent grants, and educate users on recognizing dynamic code prompts to prevent account compromise.

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## When checking the URL isn’t enough: phishing via the Microsoft identity platform | Securelist

**PIR:** 1.j.3

Securelist examines phishing attacks exploiting the Microsoft identity platform, showing why URL inspection alone is insufficient. Attackers mimic legitimate Microsoft login flows to steal credentials and tokens. Defenders should implement application allow-listing, monitor for non-browser authentication methods, and deploy identity protection solutions that detect anomalous consent and device code usage.

Source: https://securelist.com/microsoft-device-code-phishing-attack/120350/

## New widespread EvilTokens kit: device code phishing as-a-service

**PIR:** 1.a

Sekoia.io uncovers the EvilTokens kit, a phishing-as-a-service platform specializing in device code attacks. The toolkit enables low-skill actors to deploy sophisticated identity theft campaigns rapidly. Defenders should block known malicious domains, analyze OAuth token lifecycles, and integrate threat intelligence feeds to detect EvilTokens infrastructure early.

Source: https://blog.sekoia.io/new-widespread-eviltokens-kit-device-code-phishing-as-a-service-part-1/

## Inside Kali365, a Device Code Phishing Ecosystem | Huntress

**PIR:** 1.a

Huntress dissects the Kali365 ecosystem, revealing a coordinated network of device code phishing kits. The campaign demonstrates advanced operational security and rapid infrastructure rotation. IT defenders must prioritize log analysis for unusual authentication patterns, enforce zero-trust identity controls, and collaborate with threat intel sharing communities to disrupt the ecosystem.

Source: https://www.huntress.com/blog/kali365-device-code-phishing-kit

## The Shadow Campaigns: Uncovering Global Espionage

**PIR:** 1.b

Unit 42 reveals Shadow Campaigns, a global espionage operation leveraging sophisticated spearphishing and supply chain compromises. The threat actor targets high-value infrastructure with custom malware and persistent access techniques. Defenders must enhance email security gateways, monitor for lateral movement indicators, and enforce strict network segmentation to mitigate advanced persistent threats.

Source: https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/

## Sophisticated Spearphishing Campaign Targets Government Organizations, IGOs, and NGOs | CISA

**PIR:** 1.b

CISA warns of a targeted spearphishing campaign against government and international organizations. The operation uses highly tailored lures and credential harvesting sites to gain initial access. Infrastructure teams should prioritize user awareness training, implement advanced email filtering, and establish rapid incident response playbooks for identity-based breaches.

Source: https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-148a

