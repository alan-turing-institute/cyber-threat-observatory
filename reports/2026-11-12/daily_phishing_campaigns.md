# Daily phishing and identity campaigns

- **Report date:** 2026-11-12
- **Sources:** ketch OSINT (3 queries)

## The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime | Microsoft Security Blog

**PIR:** 1.a

Analyzes the underground infrastructure supporting large-scale phishing operations, detailing domain generation algorithms, bulletproof hosting networks, and CDN abuse tactics. Provides actionable IOCs and architectural insights for network defenders to block malicious traffic at the DNS and proxy layers before credential harvesting occurs.

Source: https://www.microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime/

## Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Security Blog

**PIR:** 1.b

Dissects the EvilTokens framework, which exploits OAuth device code flows to bypass traditional MFA. Explains how attackers automate token exchange and session persistence, offering detection strategies for identity teams to monitor anomalous device code requests and implement conditional access policies.

Source: https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/

## The Hidden Relay: Inside a Device Code Phishing Kit That Never Shows the Code

**PIR:** 1.c

Reveals a novel device code phishing kit that operates without displaying the verification code to victims, using background relay techniques to capture tokens. Details the attack chain, infrastructure footprint, and evasion methods. Provides actionable detection logic for SIEM and identity protection platforms.

Source: https://blog.knowbe4.com/the-hidden-relay-inside-a-device-code-phishing-kit-that-never-shows-the-code

## Inside Wazza: A Newly Observed Device Code Phishing Kit Targeting Microsoft 365 Accounts

**PIR:** 1.b

Examines the Wazza phishing kit, a newly identified tool targeting Microsoft 365 via device code authentication. Highlights its evasion techniques, infrastructure patterns, and user interface cloning methods. Recommends endpoint and identity monitoring controls to detect and mitigate unauthorized device code approvals.

Source: https://www.levelblue.com/blogs/spiderlabs-blog/inside-wazza-a-newly-observed-device-code-phishing-kit-targeting-microsoft-365-accounts

## Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US

**PIR:** 1.d

Explores the shift from password harvesting to device code phishing as a primary identity takeover vector. Discusses attacker motivations, campaign mechanics, and the limitations of traditional email security. Outlines defense-in-depth strategies focusing on user training, conditional access, and real-time identity analytics.

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## Microsoft 365 device code phishing campaign bypasses password stealing | RL Blog

**PIR:** 1.e

Documents a widespread campaign that circumvents traditional password theft by targeting the OAuth device code flow. Explains how attackers leverage legitimate authentication endpoints to steal access tokens. Recommends network segmentation, conditional access rules, and user awareness training to mitigate identity compromise.

Source: https://www.reversinglabs.com/blog/device-code-phishing-campaign

## Tracking BigBear 2.0 Evilginx2 Phishing Campaign | CloudSEK

**PIR:** 1.f

Chronicles the BigBear 2.0 campaign leveraging Evilginx2 for reverse proxy phishing. Details how the toolkit intercepts multi-factor authentication challenges and session cookies. Provides network-level detection rules and proxy configuration hardening steps to prevent credential relay attacks.

Source: https://www.cloudsek.com/blog/tracking-bigbear-2-0-evilginx2-phishing-campaign

## Inside an AI‑enabled device code phishing campaign | Microsoft Security Blog

**PIR:** 1.g

Investigates a campaign using generative AI to craft highly personalized device code phishing lures. Analyzes how AI accelerates campaign scaling and improves social engineering success rates. Offers guidance for security teams to implement AI-aware detection models and strengthen identity verification workflows.

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

