# Daily phishing and identity campaigns

- **Report date:** 2026-11-27
- **Sources:** ketch OSINT (3 queries)

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.j.3

Threat actors are now leveraging AI to automate device code phishing campaigns, generating live authentication codes on demand and sustaining post-compromise access. This analysis highlights the integration of machine learning for dynamic lure generation and real-time session management. Defenders must adopt AI-driven detection models, enforce strict conditional access, and monitor for automated consent patterns.

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## Unmasking EvilTokens: Getting to the root of device code phishing

**PIR:** 1.b

EvilTokens exploits Microsoft’s Device Authorization Grant flow to silently steal authentication tokens without requiring password entry. This breakdown reveals how threat actors automate device code generation and token exchange. Defenders should review OAuth consent policies, monitor for anomalous device code approvals, and enforce conditional access rules to block unauthorized token issuance.

Source: https://microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing?trk=article-ssr-frontend-pulse_little-text-block

## Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale

**PIR:** 1.a

Tycoon2FA represents a sophisticated Adversary-in-the-Middle phishing kit designed to bypass multi-factor authentication at scale. This report details its reverse proxy architecture, session hijacking mechanisms, and deployment tactics. Infrastructure teams can leverage these findings to implement advanced proxy detection, certificate pinning, and behavioral analytics to mitigate AiTM threats.

Source: https://microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale

## Resurgence of a multi‑stage AiTM phishing and BEC campaign abusing SharePoint

**PIR:** 1.c

This campaign combines AiTM proxy techniques with Business Email Compromise tactics, specifically abusing SharePoint for credential harvesting and lateral movement. The multi-stage approach demonstrates how attackers pivot from initial compromise to persistent access. IT teams must strengthen SharePoint security configurations, enforce strict MFA, and deploy email authentication protocols to disrupt these workflows.

Source: https://microsoft.com/en-us/security/blog/2026/01/21/multistage-aitm-phishing-bec-campaign-abusing-sharepoint

## Microsoft 365 Device Code Phishing Campaign Bypasses Password Theft ...

**PIR:** 1.b

ReversingLabs documents an active campaign exploiting Microsoft 365’s Device Authorization Grant to bypass traditional password theft. By combining realistic business lures with polished phishing kits, attackers achieve near-invisible account takeovers. Infrastructure defenders should audit OAuth app permissions, disable unnecessary device code flows, and deploy advanced email filtering to block these sophisticated lures.

Source: https://cybersecuritynews.com/microsoft-365-device-code-phishing-campaign/

## Device Code Phishing is an Evolution in Identity Takeover

**PIR:** 1.b

Device code phishing has surged due to publicly available toolkits and phishing-as-a-service models. This threat intelligence report outlines the operational shift from traditional credential harvesting to token-based identity takeover. Security leaders should prioritize monitoring OAuth consent logs, educating users on device code prompts, and implementing zero-trust identity validation to counter this evolving vector.

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime

**PIR:** 1.d

This analysis dissects the underground infrastructure ecosystem fueling global phishing operations. IT defenders will find critical insights into domain generation algorithms, bulletproof hosting networks, and proxy chaining techniques used to evade takedowns. Understanding these foundational layers is essential for proactive threat hunting and infrastructure hardening.

Source: https://microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime

## Sophisticated Spearphishing Campaign Targets Government Organizations, IGOs, and NGOs | CISA

**PIR:** 1.e

CISA warns of a targeted spearphishing campaign focusing on government and international organizations. The attack leverages highly customized lures and malicious attachments to establish initial footholds. IT infrastructure teams should enhance email gateway rules, enforce application allowlisting, and conduct regular phishing simulations to strengthen human and technical defenses against state-sponsored threats.

Source: https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-148a

