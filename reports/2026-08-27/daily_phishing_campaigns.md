# Daily phishing and identity campaigns

- **Report date:** 2026-08-27
- **Sources:** ketch OSINT (3 queries)

## OAuth Device Code Phishing: 37x Surge in Enterprise ATO

**PIR:** 1.c

This research note documents a 37-fold increase in enterprise account takeover attacks leveraging OAuth device code flows. Attackers bypass traditional MFA by tricking users into entering authorization codes on malicious domains. The report details technical indicators, affected cloud providers, and mitigation strategies for identity architects, emphasizing the need for conditional access policies and device code flow monitoring.

Source: https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/04/CSA_research_note_oauth-device-code-phishing-surge_20260405-csa-styled.pdf

## Device Code Phishing is an Evolution in Identity Takeover

**PIR:** 1.c

Proofpoint analyzes how device code phishing has evolved from opportunistic scams into a structured identity takeover methodology. The article breaks down the OAuth 2.0 device authorization flow exploitation, highlighting how threat actors harvest tokens without credential theft. It provides actionable detection rules for SIEM platforms and recommends architectural changes to limit token scope and enforce continuous authentication.

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations

**PIR:** 1.d

This report examines the shift from manual, high-volume phishing to AI-driven, autonomous campaigns. Generative models now craft context-aware lures, dynamically adapt to user responses, and automate infrastructure provisioning. Defenders are advised to implement behavioral analytics, deploy AI-resistant email authentication, and prioritize zero-trust identity validation over perimeter-based filtering.

Source: https://itsecurityguru.org/2026/05/27/the-ai-phishing-revolution-from-spray-and-pray-to-autonomous-operations

## Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA

**PIR:** 1.e

CYFIRMA details how threat actors abuse serverless functions, container registries, and ephemeral cloud resources to host phishing infrastructure. These campaigns evade traditional IP-based blocking by leveraging legitimate cloud APIs. The analysis provides infrastructure defenders with detection patterns for anomalous cloud resource creation, DNS tunneling indicators, and cloud-native security posture recommendations.

Source: https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns

## Device Code Phishing — The Attack That Makes MFA Irrelevant

**PIR:** 1.b

CyberGrind explores how device code phishing effectively neutralizes multi-factor authentication by intercepting valid OAuth tokens. The article explains the technical mechanics of token hijacking, demonstrates real-world attack chains, and outlines defensive controls including token binding, certificate-based authentication, and strict conditional access rules to protect enterprise identity perimeters.

Source: https://cybergrind.org/blog/2026-06-02-device-code-phishing

## EvilTokens Abuses Microsoft Device Codes to Hijack Accounts Without Stealing Passwords

**PIR:** 1.c

This technical breakdown reveals how the EvilTokens group exploits Microsoft’s device code authentication to hijack accounts without capturing passwords. By leveraging legitimate OAuth endpoints, attackers obtain long-lived access tokens that bypass standard MFA prompts. The report includes network traffic analysis, token lifecycle details, and mitigation steps for Microsoft 365 administrators.

Source: https://gbhackers.com/microsoft-device-codes-abuse/amp

## Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA

**PIR:** 1.f

CISA warns of a zero-click phishing campaign targeting Zimbra email servers, attributed to the Laundry Bear threat group. The attack exploits unpatched server vulnerabilities to inject malicious payloads directly into user inboxes, requiring no user interaction. Infrastructure teams are urged to apply critical patches, monitor for anomalous server-side scripting, and isolate affected mail clusters immediately.

Source: https://tempmail.ninja/blog/laundry-bear-zimbra-phishing

## PhantomEnigma: How a Malware Crew Turned Brazilian Government Sites Into Trusted Malware Hubs

**PIR:** 1.g

SecureBulletin investigates how the PhantomEnigma crew compromised Brazilian government websites to distribute malware under trusted domains. By exploiting legacy CMS vulnerabilities and weak hosting configurations, attackers bypassed reputation-based security controls. The report outlines infrastructure hardening practices, DNS monitoring techniques, and supply chain validation steps for public-facing web assets.

Source: https://securebulletin.com/phantomenigma-how-a-malware-crew-turned-brazilian-government-sites-into-trusted-malware-hubs

