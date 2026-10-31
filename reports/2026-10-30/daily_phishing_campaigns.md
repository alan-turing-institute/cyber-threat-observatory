# Daily phishing and identity campaigns

- **Report date:** 2026-10-30
- **Sources:** ketch OSINT (3 queries)

## Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale | Microsoft Security Blog

**PIR:** 1.b

An in-depth technical breakdown of the Tycoon2FA Adversary-in-the-Middle (AiTM) kit, detailing its reverse proxy architecture, session token theft mechanisms, and MFA bypass techniques. Infrastructure teams should review reverse proxy signatures, enforce certificate pinning, and deploy conditional access policies that detect anomalous session behaviors to mitigate AiTM threats.

Source: https://www.microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale/

## Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Security Blog

**PIR:** 1.c

Microsoft researchers expose EvilTokens, a sophisticated toolkit exploiting OAuth device authorization flows to bypass traditional MFA. The report outlines token validation bypasses, automated polling techniques, and infrastructure patterns. Defenders must monitor for unusual device code grant requests, restrict OAuth app permissions, and implement token binding to secure identity perimeters.

Source: https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/

## The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime | Microsoft Security Blog

**PIR:** 1.d

Microsoft Threat Intelligence dissects the underground infrastructure supporting modern phishing campaigns, revealing how threat actors leverage cloud services, domain generation algorithms, and proxy networks to evade detection. Defenders can use these indicators to harden email gateways, monitor DNS anomalies, and block malicious hosting providers before credential harvesting occurs.

Source: https://www.microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime/

## Inside an AI‑enabled device code phishing campaign | Microsoft Security Blog

**PIR:** 1.c

This analysis covers a campaign leveraging generative AI to craft highly personalized lures and automate device code phishing workflows. The attack chain combines AI-generated content with OAuth exploitation to harvest valid access tokens. IT defenders should deploy AI-aware email filtering, monitor for rapid device code polling, and enforce strict conditional access rules for token issuance.

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## Resecurity | Iron Man & YamStore: Powering a Global Phishing-as-a-Service Ecosystem

**PIR:** 1.d

Resecurity maps the Iron Man and YamStore PhaaS platforms, detailing their modular phishing kits, affiliate tracking systems, and infrastructure-as-a-service offerings. The report provides actionable IOCs and architectural insights to help security teams block PhaaS domains, disrupt affiliate networks, and harden web application firewalls against kit-generated payloads.

Source: https://www.resecurity.com/blog/article/iron-man-yamstore-powering-a-global-phishing-as-a-service-ecosystem

## Device Code Phishing is an Evolution in Identity Takeover

**PIR:** 1.j.3

Proofpoint examines the rapid proliferation of device code phishing tools and their role in modern identity takeover attacks. The article highlights how publicly available toolkits and PhaaS models lower the barrier for attackers. Defenders are advised to audit OAuth consent grants, implement token lifetime restrictions, and deploy identity threat detection platforms to catch anomalous authorization flows.

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## Microsoft 365 Device Code Phishing Campaign Bypasses Password Theft ...

**PIR:** 1.c

ReversingLabs documents an active campaign exploiting Microsoft 365’s Device Authorization Grant flow to achieve near-invisible account takeovers. The attack uses realistic business lures and polished kits to trick users into entering device codes. Infrastructure teams should monitor for high-frequency device code validations, restrict third-party app access, and educate users on recognizing OAuth phishing prompts.

Source: https://cybersecuritynews.com/microsoft-365-device-code-phishing-campaign/

## Storm-2372 conducts device code phishing campaign

**PIR:** 1.a

Microsoft tracks Storm-2372’s persistent use of device code phishing, mimicking messaging platforms like Teams and WhatsApp to harvest credentials. The campaign demonstrates how threat actors adapt lures to bypass user skepticism. Defenders should implement URL reputation filtering, monitor for messaging-app impersonation patterns, and enforce multi-factor authentication with phishing-resistant methods like FIDO2.

Source: https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/

