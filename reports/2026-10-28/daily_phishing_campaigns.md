# Daily phishing and identity campaigns

- **Report date:** 2026-10-28
- **Sources:** ketch OSINT (3 queries)

## Unmasking EvilTokens: Getting to the root of device code phishing

**PIR:** 1.e

This report dissects the EvilTokens campaign, revealing how threat actors exploit Microsoft’s device code authorization flow to bypass traditional MFA. By analyzing the underlying PhaaS infrastructure, defenders gain actionable insights into detecting and blocking device code phishing at the network and identity layers. Essential for teams managing cloud identity platforms.

Source: https://aka.ms/EvilTokens-PhaaS

## Breaking the code: Multi-stage ‘code of conduct’ phishing campaign leads to AiTM token compromise

**PIR:** 1.d

A detailed breakdown of a multi-stage phishing operation leveraging fake corporate compliance portals to harvest live authentication tokens. The campaign demonstrates how attackers chain social engineering with Adversary-in-the-Middle proxies to defeat step-up authentication. Infrastructure defenders can use the provided IOCs and detection logic to harden identity gateways.

Source: https://microsoft.com/en-us/security/blog/2026/05/04/breaking-the-code-multi-stage-code-of-conduct-phishing-campaign-leads-to-aitm

## Device Code Phishing is an Evolution in Identity Takeover

**PIR:** 1.e

Proofpoint analyzes the rapid proliferation of device code phishing, linking the surge to open-source criminal toolkits and PhaaS platforms. The report details how attackers manipulate OAuth consent flows to silently acquire valid tokens, effectively neutralizing MFA. Defenders are advised to implement conditional access policies, monitor for unusual device code requests, and deploy token revocation workflows.

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.g

Microsoft Threat Intelligence reveals how AI automation is scaling device code phishing operations. Attackers use generative AI to craft highly contextual lures and automate token harvesting in real time, significantly increasing compromise rates. The post provides detection signatures for AI-driven phishing infrastructure and recommends identity-centric controls to limit lateral movement post-compromise.

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## The ‘code of conduct’ phishing campaign: What MSPs need to know right now

**PIR:** 1.h

This advisory outlines how managed service providers are being specifically targeted by the ‘code of conduct’ phishing wave. Attackers exploit MSP trust relationships and delegated admin access to pivot across multiple client environments. The article provides mitigation strategies for MSPs and enterprise IT teams to restrict delegated permissions and monitor anomalous admin activity.

Source: https://blog.barracuda.com/2026/05/07/code-of-conduct-phishing-campaign-msp-response

## Storm-2372 conducts device code phishing campaign

**PIR:** 1.a

Tracking the Storm-2372 threat actor, this report documents a persistent device code phishing campaign mimicking popular messaging platforms. The group targets enterprise users with realistic lures to capture OAuth tokens. Infrastructure teams can leverage the shared TTPs and network indicators to update proxy filters, block malicious authorization endpoints, and enforce stricter consent policies.

Source: https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/

## Microsoft 365 Device Code Phishing Campaign Bypasses Password Theft ...

**PIR:** 1.e

ReversingLabs researchers document a sophisticated campaign that leverages Microsoft 365’s device authorization grant to bypass traditional credential theft. By combining polished phishing kits with legitimate OAuth flows, attackers achieve near-invisible account takeovers. The analysis highlights critical detection gaps and offers practical steps for securing identity providers against consent-based abuse.

Source: https://cybersecuritynews.com/microsoft-365-device-code-phishing-campaign/

## Device Code Phishing Drives Identity Takeover Risks

**PIR:** 1.e

This threat intelligence brief examines how device code phishing has become a primary vector for enterprise identity takeover. Attackers exploit corporate validation workflows to circumvent MFA controls, targeting high-value accounts. The report emphasizes the need for continuous identity monitoring, automated token lifecycle management, and user awareness training focused on OAuth consent prompts.

Source: https://gurucul.com/latest-threats/device-code-phishing-is-an-evolution-in-identity-takeover/

