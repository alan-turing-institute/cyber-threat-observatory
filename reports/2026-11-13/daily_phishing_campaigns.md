# Daily phishing and identity campaigns

- **Report date:** 2026-11-13
- **Sources:** ketch OSINT (3 queries)

## The Hidden Relay: Inside a Device Code Phishing Kit That Never Shows the Code

**PIR:** 1.b

Analyzes a novel device code phishing kit that bypasses traditional detection by never exposing the authorization code to the victim. Attackers use a hidden relay proxy to silently capture OAuth tokens, enabling seamless account takeover. Infrastructure defenders should monitor for anomalous OAuth consent requests, enforce conditional access policies requiring compliant devices, and deploy AI-driven behavioral analytics to detect proxy-mediated authentication flows.

Source: https://blog.knowbe4.com/the-hidden-relay-inside-a-device-code-phishing-kit-that-never-shows-the-code

## Joint advisory: state-sponsored spear-phishing campaigns targeting critical infrastructure - SUVAT

**PIR:** 1.c

Outlines coordinated campaigns by nation-state actors targeting critical infrastructure via highly tailored spearphishing emails with malicious RDP and document attachments. The advisory emphasizes the need for email gateway filtering, endpoint isolation, and strict remote access controls to prevent initial foothold and lateral movement across OT/IT networks. Defenders should prioritize threat hunting for known APT TTPs and harden remote management protocols.

Source: https://suvat.uk/blog/five-eyes-advisory.html

## The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime

**PIR:** 1.d

Maps the underground infrastructure supporting global phishing operations, revealing how threat actors leverage bulletproof hosting, domain generation algorithms, and compromised legitimate services to evade takedowns. Defenders must implement DNS sinkholing, integrate threat intelligence feeds for known phishing domains, and deploy network-level blocking rules to disrupt command-and-control channels before credential harvesting occurs.

Source: https://microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.b

Reveals how attackers integrate generative AI to dynamically craft phishing pages and automate device code authorization prompts. The campaign adapts in real-time to bypass WAF rules and user suspicion. Infrastructure teams should deploy AI-resistant CAPTCHAs, monitor for rapid consent request spikes, and enforce strict app registration policies in identity providers to mitigate automated token theft.

Source: https://microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026

## Microsoft 365 device code phishing campaign bypasses password stealing

**PIR:** 1.b

Details a campaign exploiting the device code flow to bypass password-based MFA and credential theft defenses. Attackers trick users into authorizing malicious apps, granting full tenant access. IT teams should restrict device code grant types in Azure AD, enforce risk-based conditional access, and monitor for high-privilege token issuance from unfamiliar IP ranges to prevent identity compromise.

Source: https://www.reversinglabs.com/blog/device-code-phishing-campaign

## Breaking the code: Multi-stage ‘code of conduct’ phishing campaign leads to AiTM token compromise

**PIR:** 1.a

Examines a multi-stage campaign using fake compliance portals to harvest OAuth tokens via AiTM proxies. The attack chain combines social engineering with automated token relay to defeat step-up authentication. Defenders should implement token binding, restrict third-party app consent, and deploy user training focused on recognizing spoofed corporate policy pages to block session hijacking.

Source: https://microsoft.com/en-us/security/blog/2026/05/04/breaking-the-code-multi-stage-code-of-conduct-phishing-campaign-leads-to-aitm-token-compromise

## Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US

**PIR:** 1.b

Explores how device code phishing has matured into a primary identity takeover vector, circumventing traditional password stealers. The article outlines detection strategies including monitoring for unusual device code grant patterns, enforcing hardware-backed MFA, and implementing zero-trust network access controls to limit lateral movement post-compromise across enterprise environments.

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale

**PIR:** 1.a

Dissects the Tycoon2FA AiTM kit, highlighting its modular architecture and automated proxy relay capabilities that capture live session cookies. The analysis provides IOCs and detection rules for SIEM integration. Defenders should prioritize blocking known AiTM domains, enforce certificate pinning for critical apps, and implement continuous authentication monitoring to detect anomalous session behavior.

Source: https://microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale

