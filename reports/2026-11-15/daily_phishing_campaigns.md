# Daily phishing and identity campaigns

- **Report date:** 2026-11-15
- **Sources:** ketch OSINT (3 queries)

## Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Security Blog

**PIR:** 1.d.2

This analysis exposes EvilTokens, a sophisticated toolkit enabling device code phishing attacks that bypass traditional MFA. Attackers trick users into entering device codes, granting threat actors direct OAuth tokens without passwords. The article outlines detection signatures, token revocation procedures, and architectural mitigations for identity platforms. Critical for defenders monitoring Azure AD/Entra ID sign-in logs and implementing conditional access policies.

Source: https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/

## Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale | Microsoft Security Blog

**PIR:** 1.c.1

Microsoft details the inner workings of Tycoon2FA, a prominent Adversary-in-the-Middle phishing kit that intercepts MFA challenges in real-time. The report explains how reverse proxies capture session cookies and bypass step-up authentication, alongside technical indicators and mitigation strategies. Infrastructure defenders can leverage these insights to harden web application firewalls, deploy FIDO2 security keys, and monitor for anomalous proxy traffic patterns.

Source: https://www.microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale/

## The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime | Microsoft Security Blog

**PIR:** 1.e.1

Microsoft Security researchers dissect the underground ecosystem fueling global phishing campaigns, revealing how threat actors rapidly provision domains, hosting, and proxy networks to evade takedowns. The report details infrastructure-as-a-service models, domain generation algorithms, and defensive strategies for blocking malicious networks at the DNS and proxy layers. Essential for infrastructure teams managing email security gateways and web filtering policies.

Source: https://www.microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime/

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.d.3

Researchers uncover a campaign leveraging AI to automate device code phishing at scale, dynamically generating authentication codes and managing victim interactions without human intervention. The attack chain combines LLM-driven social engineering with automated token harvesting, significantly increasing compromise rates. Defenders are advised to implement behavioral analytics for OAuth flows, restrict device code grant usage, and deploy AI-resistant authentication methods like phishing-resista

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## Device Code Phishing is an Evolution in Identity Takeover

**PIR:** 1.d.1

Proofpoint tracks the rapid proliferation of device code phishing, driven by publicly released toolkits and phishing-as-a-service platforms. The article explains how attackers exploit OAuth device authorization flows to harvest valid tokens, effectively neutralizing password-based MFA. It provides actionable guidance for identity administrators, including monitoring for suspicious device code grants, restricting OAuth app permissions, and educating users on code-entry prompts.

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## Microsoft 365 Device Code Phishing Campaign Bypasses Password Theft ...

**PIR:** 1.d.2

ReversingLabs documents an active campaign targeting Microsoft 365 environments using polished, business-themed lures combined with the Device Authorization Grant flow. The attack bypasses traditional password theft by directly harvesting OAuth tokens, enabling stealthy account takeover. The report includes campaign infrastructure details, email headers, and mitigation steps for M365 administrators, emphasizing the need for strict OAuth consent policies and user awareness training.

Source: https://cybersecuritynews.com/microsoft-365-device-code-phishing-campaign/

## Device Code Phishing Drives Identity Takeover Risks

**PIR:** 1.d.1

Gurucul highlights how device code phishing manipulates corporate validation workflows to compromise high-value employee accounts. The threat bypasses multi-factor authentication by exploiting legitimate OAuth mechanisms, granting attackers persistent access. The analysis recommends infrastructure teams audit delegated permissions, enforce conditional access rules, and monitor for unusual device code authentication patterns to mitigate identity takeover risks across enterprise environments.

Source: https://gurucul.com/latest-threats/device-code-phishing-is-an-evolution-in-identity-takeover/

## Russian hackers can steal government emails without victims clicking a link, cyber agencies warn

**PIR:** 1.f.1

Cyber agencies warn of Russian threat actors exploiting email client vulnerabilities to steal government credentials without requiring victim interaction. The zero-click technique leverages malicious attachments or rendering flaws to exfiltrate session tokens. Infrastructure teams must prioritize patching email clients, disable auto-preview features, and deploy network segmentation to limit lateral movement following silent compromises.

Source: https://nextgov.com/cybersecurity/2026/07/russian-hackers-can-steal-government-emails-without-victims-clicking-link-cyber-agencies-warn/414967

