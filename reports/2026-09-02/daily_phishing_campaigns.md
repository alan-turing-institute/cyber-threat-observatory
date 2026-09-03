# Daily phishing and identity campaigns

- **Report date:** 2026-09-02
- **Sources:** ketch OSINT (3 queries)

## Inside Knight Office, a New M365 AiTM Phishing Kit | Huntress

**PIR:** 1.a

Huntress researchers dissect the Knight Office M365 AiTM phishing kit, detailing how threat actors proxy Microsoft 365 login flows to bypass MFA. The analysis covers infrastructure patterns, session hijacking techniques, and detection strategies for IT defenders managing cloud identity environments.

Source: https://www.huntress.com/blog/inside-knight-office-m365-aitm-attack

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.d

Microsoft details a sophisticated device code phishing campaign leveraging AI for end-to-end automation. Attackers generate live authentication codes on demand, significantly increasing account takeover success rates. Defenders are advised to monitor for anomalous device code flows and implement stricter session validation controls.

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale | Microsoft Security Blog

**PIR:** 1.a

Microsoft Security researchers expose the Tycoon2FA AiTM phishing kit, revealing its large-scale operational model. The report outlines how the framework intercepts authentication tokens in real-time, evades conditional access policies, and provides actionable indicators for infrastructure teams to block proxy-based credential theft.

Source: https://www.microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale/

## Device Code Phishing is an Evolution in Identity Takeover

**PIR:** 1.b

Proofpoint analyzes the evolution of device code phishing as a primary identity takeover vector. The campaign exploits corporate validation workflows and leverages account takeover jumping to propagate across contact networks. Infrastructure teams must review OAuth consent policies and deploy behavioral analytics to detect automated code generation.

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## Starkiller Phishing Framework Proxies Real Login Pages… | Abnormal AI

**PIR:** 1.g

Abnormal AI researchers analyze the Starkiller phishing framework, which proxies real login pages to capture credentials and MFA tokens. The toolkit’s architecture enables seamless session hijacking while evading traditional URL filtering. Defenders should implement certificate pinning, monitor for proxy traffic patterns, and enforce phishing-resistant MFA methods.

Source: https://abnormal.ai/blog/starkiller-phishing-kit

## NovaCookies at scale: Inside the $320 Phishing Service Targeting Hundreds of Organizations

**PIR:** 1.c

Island.io investigates the NovaCookies phishing service, a $320 PhaaS operation targeting hundreds of organizations. The report breaks down how the service harvests session cookies to bypass MFA and maintain persistent access. Defenders should focus on cookie security attributes, session rotation, and network-level blocking of known PhaaS infrastructure.

Source: https://www.island.io/blog/novacookies-at-scale-inside-the-320-phishing-service-targeting-hundreds-of-organizations

## Why do device code phishing campaigns create more account takeover risk ...

**PIR:** 1.e

NHIMG explains why device code phishing poses elevated account takeover risks compared to traditional methods. Successful attacks grant mailbox access, SaaS persistence, and token-based lateral movement, particularly where conditional access and session controls are weak. Infrastructure teams must prioritize token lifecycle management and zero-trust identity validation.

Source: https://nhimg.org/faq/why-do-device-code-phishing-campaigns-create-more-account-takeover-risk-than-tra/

## IronToll: Global Government-Impersonation PhaaS | PhishEye

**PIR:** 1.f

PhishEye uncovers IronToll, a global PhaaS campaign impersonating government entities. The framework automates credential harvesting and session hijacking across multiple cloud platforms. IT infrastructure defenders are urged to monitor for government-branded phishing domains, enforce strict conditional access rules, and deploy email authentication controls.

Source: https://phisheye.com/blog/irontoll-iron-man-phaas-campaign

