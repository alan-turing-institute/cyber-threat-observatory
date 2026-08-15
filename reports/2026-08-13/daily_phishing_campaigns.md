# Daily phishing and identity campaigns

- **Report date:** 2026-08-13
- **Sources:** ketch OSINT (3 queries)

## Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale | Microsoft Security Blog

**PIR:** 1.b

Microsoft Security researchers dissect the Tycoon2FA adversary-in-the-middle (AiTM) phishing kit, detailing its infrastructure, proxy mechanisms, and scale. The report provides actionable indicators of compromise, network-level detection strategies, and mitigation guidance for identity and infrastructure defenders managing cloud authentication flows.

Source: https://www.microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale/

## Inside Kali365, a Device Code Phishing Ecosystem | Huntress

**PIR:** 1.c

Huntress analyzes the Kali365 ecosystem, a sophisticated device code phishing framework that abuses OAuth 2.0 flows to bypass MFA. The breakdown covers infrastructure patterns, token persistence techniques, and defensive controls for securing identity providers and monitoring anomalous authorization requests.

Source: https://www.huntress.com/blog/kali365-device-code-phishing-kit

## New widespread EvilTokens kit: device code phishing as-a-service

**PIR:** 1.d

Sekoia.io reveals EvilTokens, a commercial device code phishing-as-a-service platform enabling low-skill actors to execute OAuth abuse campaigns. The analysis highlights infrastructure hosting patterns, automated token harvesting, and recommended identity governance policies to limit lateral movement post-compromise.

Source: https://www.sekoia.com/blog/new-widespread-eviltokens-kit-device-code-phishing-as-a-service-part-1

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.e

Microsoft documents a campaign leveraging AI to automate device code phishing, dynamically generating authentication prompts and scaling account compromises. Defenders gain insights into behavioral anomalies, AI-driven prompt engineering, and enhanced monitoring rules for OAuth consent and device authorization endpoints.

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## Access granted: phishing with device code authorization for account ...

**PIR:** 1.c

Proofpoint tracks multiple threat clusters exploiting the OAuth 2.0 device authorization grant flow to hijack M365 accounts. The analysis outlines infrastructure indicators, consent phishing patterns, and identity protection recommendations, including conditional access policies and token lifecycle management for enterprise environments.

Source: https://www.proofpoint.com/us/blog/threat-insight/access-granted-phishing-device-code-authorization-account-takeover

## Tycoon 2FA Takedown | Cloudflare

**PIR:** 1.g

Cloudflare details the infrastructure takedown of the Tycoon2FA phishing network, mapping domain registration patterns, CDN abuse, and proxy routing. The report offers network defenders actionable DNS and TLS telemetry, sinkholing strategies, and upstream filtering techniques to disrupt AiTM campaigns at the infrastructure layer.

Source: https://www.cloudflare.com/threat-intelligence/research/report/tycoon-2fa-takedown/

## IronToll: Global Government-Impersonation PhaaS | PhishEye

**PIR:** 1.d

PhishEye exposes IronToll, a phishing-as-a-service operation impersonating government agencies to harvest credentials and deploy malicious infrastructure. The report details campaign architecture, hosting infrastructure, and defensive playbooks for filtering impersonation domains and hardening email gateway rules.

Source: https://phisheye.com/blog/irontoll-iron-man-phaas-campaign

## Device Code Phishing Hits 340+ Microsoft 365 Orgs Across Five Countries ...

**PIR:** 1.c

An overview of a widespread device code phishing wave impacting over 340 Microsoft 365 organizations. The article summarizes attack vectors, persistent token abuse, and high-level mitigation steps, providing infrastructure teams with context on campaign scale and recommended identity monitoring enhancements.

Source: https://thehackernews.com/2026/03/device-code-phishing-hits-340-microsoft.html

