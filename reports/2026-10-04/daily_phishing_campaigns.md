# Daily phishing and identity campaigns

- **Report date:** 2026-10-04
- **Sources:** ketch OSINT (3 queries)

## Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Security Blog

**PIR:** 1.b.2

Microsoft researchers dissect the EvilTokens infrastructure, revealing how threat actors automate device code phishing to bypass MFA. The report details token validation endpoints, session hijacking techniques, and defensive strategies for identity protection teams to detect anomalous authorization requests and block malicious redirect URIs.

Source: https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/

## Tracking BigBear 2.0 Evilginx2 Phishing Campaign | CloudSEK

**PIR:** 1.a.1

CloudSEK analyzes the BigBear 2.0 campaign leveraging Evilginx2 to conduct advanced-in-the-middle attacks. Defenders learn how the proxy harvests session cookies and MFA tokens simultaneously, with actionable IOCs and network-level blocking rules to mitigate credential theft across enterprise environments.

Source: https://www.cloudsek.com/blog/tracking-bigbear-2-0-evilginx2-phishing-campaign

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.d.1

Microsoft Security details a novel campaign using AI to dynamically generate phishing prompts and adapt device code requests. The report highlights evasion techniques against automated scanners, provides telemetry for identity protection tools, and outlines mitigation steps for securing OAuth endpoints.

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## Exposed Server Reveals Three Microsoft 365 Phishing Campaigns

**PIR:** 1.c.1

BreachNews uncovers a compromised server hosting three active M365 phishing campaigns. The analysis highlights shared infrastructure, login page cloning techniques, and email header anomalies. IT teams can use the provided domains and IP ranges to update proxy filters and monitor for unauthorized OAuth app registrations.

Source: https://breachnews.com/research/exposed-phishing-infrastructure-reveals-three-active-microsoft-365-campaigns/

## We Need to Talk About Device Code Phishing | Huntress

**PIR:** 1.b.1

Huntress breaks down the mechanics of device code phishing, explaining how attackers exploit the OAuth 2.0 device authorization flow to bypass traditional email filters. The guide offers practical detection rules for SIEM platforms, user training recommendations, and architectural changes to limit device code abuse.

Source: https://www.huntress.com/blog/tradecraft-tuesday-device-code-phishing-explained

## CodeStorm - A Microsoft 365 AiTM Phishing Kit with Storm-1167 Overlap - Hexastrike Cybersecurity

**PIR:** 1.a.2

Hexastrike examines the CodeStorm kit, noting its overlap with Storm-1167 infrastructure. The report details how the kit automates AiTM attacks against M365 tenants, providing defenders with YARA rules, network signatures, and identity governance controls to disrupt the campaign’s token harvesting pipeline.

Source: https://hexastrike.com/resources/blog/threat-intelligence/codestorm-a-microsoft-365-aitm-phishing-kit-with-storm-1167-overlap/

## Device Code Phishing is an Evolution in Identity Takeover

**PIR:** 1.b.3

Proofpoint explores how device code phishing represents a tactical shift from email-borne lures to direct endpoint exploitation. The article outlines threat actor workflows, detection gaps in legacy email security, and recommends conditional access policies and user behavior analytics to strengthen identity perimeter defenses.

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## Massive “TrustTrap” Phishing Campaign Exploits Human Perception, Targets Government Services Across US, India, and Beyond

**PIR:** 1.e.1

CyberP1 investigates a large-scale campaign exploiting cognitive biases to target government and enterprise services. The analysis covers domain generation algorithms, landing page obfuscation, and cross-border targeting patterns. Infrastructure defenders gain insights into DNS sinkholing strategies and threat intelligence sharing.

Source: https://cyberp1.com/massive-trusttrap-phishing-campaign-exploits-human-perception-targets-government-services-across-us-india-and-beyond/

