# Daily phishing and identity campaigns

- **Report date:** 2026-08-16
- **Sources:** ketch OSINT (3 queries)

## Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale

**PIR:** 1.j

Microsoft Security researchers dissect the Tycoon2FA Adversary-in-the-Middle phishing kit, detailing its proxy architecture and large-scale deployment tactics. The report explains how attackers bypass multi-factor authentication by intercepting session cookies in real-time, providing defenders with critical indicators of compromise and mitigation strategies for enterprise identity infrastructure.

Source: https://www.microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale/

## Inside Kali365, a Device Code Phishing Ecosystem

**PIR:** 1.f

Huntress analyzes the Kali365 ecosystem, a sophisticated device code phishing framework that abuses OAuth consent flows to harvest valid access tokens. The breakdown covers infrastructure patterns, victim targeting methods, and detection rules for SIEM and identity protection platforms, offering actionable guidance for securing cloud environments against token theft.

Source: https://www.huntress.com/blog/kali365-device-code-phishing-kit

## The Illicit Consent Grant Part 2: Device-Code Phishing and the AI PhaaS Wave

**PIR:** 1.f

SlashID explores the intersection of illicit OAuth consent grants, device code phishing, and AI-driven PhaaS platforms. The technical deep dive covers API abuse patterns, token lifecycle manipulation, and automated campaign scaling. Infrastructure defenders receive guidance on configuring identity providers to restrict dangerous scopes and detect anomalous consent requests.

Source: https://slashid.com/blog/illicit-consent-grant-part-2

## New widespread EvilTokens kit: device code phishing as-a-service

**PIR:** 1.f

Sekoia details the EvilTokens kit, a rapidly proliferating device code phishing-as-a-service platform. The report maps its technical workflow, from initial lure delivery to token exfiltration, and provides YARA rules, network signatures, and identity governance recommendations to block unauthorized OAuth consent grants and protect enterprise directories.

Source: https://www.sekoia.com/blog/new-widespread-eviltokens-kit-device-code-phishing-as-a-service-part-1

## IronToll: Global Government-Impersonation PhaaS

**PIR:** 1.g

PhishEye exposes IronToll, a Phishing-as-a-Service operation specializing in government impersonation campaigns. The analysis reveals how the platform leverages AI-generated content and dynamic landing pages to target public sector employees. Defenders gain insight into campaign infrastructure, domain registration patterns, and email header anomalies to strengthen perimeter defenses.

Source: https://phisheye.com/blog/irontoll-iron-man-phaas-campaign

## Device Code Phishing is an Evolution in Identity Takeover

**PIR:** 1.j

Proofpoint examines how device code phishing has matured into a primary vector for identity compromise. The analysis contrasts traditional credential harvesting with modern token-based attacks, highlighting gaps in legacy MFA controls. Recommendations include enforcing conditional access policies, monitoring consent grant logs, and deploying phishing-resistant authentication methods.

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## The Device Code Phishing Tsunami: What We’re Seeing in the Wild

**PIR:** 1.f

Level Blue’s SpiderLabs team documents the surge in device code phishing attacks observed across multiple sectors. The article catalogs real-world campaign variants, analyzes attacker infrastructure reuse, and outlines detection strategies for endpoint and cloud security teams. It emphasizes the need for adaptive identity monitoring and user awareness training.

Source: https://www.levelblue.com/blogs/spiderlabs-blog/the-device-code-phishing-tsunami-what-were-seeing-in-the-wild

## Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA

**PIR:** 1.i

This report covers the Laundry Bear campaign, a zero-click phishing operation targeting Zimbra webmail deployments. CISA warnings highlight the exploit chain used to bypass user interaction requirements. The article provides patching priorities, network segmentation advice, and email gateway filtering rules to mitigate silent credential theft in legacy mail systems.

Source: https://tempmail.ninja/blog/laundry-bear-zimbra-phishing

