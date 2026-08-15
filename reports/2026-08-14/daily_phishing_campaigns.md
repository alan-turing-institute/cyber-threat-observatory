# Daily phishing and identity campaigns

- **Report date:** 2026-08-14
- **Sources:** ketch OSINT (3 queries)

## OAuth Device Code Phishing: 37x Surge in Enterprise ATO

**PIR:** 1.e

Highlights a 37-fold increase in enterprise account takeovers leveraging OAuth device code flows. Attackers bypass traditional MFA by prompting users to authorize malicious apps via short alphanumeric codes. The report details infrastructure-level indicators, compromised client IDs, and mitigation strategies for identity providers and cloud administrators.

Source: https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/04/CSA_research_note_oauth-device-code-phishing-surge_20260405-csa-styled.pdf

## Device Code Phishing — The Attack That Makes MFA Irrelevant

**PIR:** 1.f

Explores how device code phishing neutralizes multi-factor authentication by exploiting legitimate OAuth authorization endpoints. The analysis covers attacker infrastructure, phishing page hosting patterns, and real-world campaign timelines. Provides actionable detection rules for SIEM and identity governance platforms to block illicit consent grants and protect enterprise directories.

Source: https://cybergrind.org/blog/2026-06-02-device-code-phishing

## The Illicit Consent Grant Part 2: Device-Code Phishing and the AI PhaaS Wave | SlashID Blog

**PIR:** 1.e

Details the evolution of illicit consent grants combined with AI-generated phishing-as-a-service platforms. Attackers automate credential harvesting and OAuth abuse at scale, targeting enterprise identity ecosystems. The article provides technical breakdowns of malicious app registrations, token theft mechanisms, and defensive controls for identity architects and security operations teams.

Source: https://slashid.com/blog/illicit-consent-grant-part-2

## The Device Code Phishing Tsunami: What We’re Seeing in the Wild

**PIR:** 1.f

Provides field observations of the device code phishing surge, detailing attacker infrastructure, domain registration patterns, and phishing kit distributions. The report emphasizes the operational impact on enterprise identity platforms and offers technical guidance for blocking malicious OAuth flows, monitoring consent logs, and implementing conditional access policies.

Source: https://www.levelblue.com/blogs/spiderlabs-blog/the-device-code-phishing-tsunami-what-were-seeing-in-the-wild

## Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA

**PIR:** 1.g

Examines threat actors leveraging cloud-native services like serverless functions, object storage, and CDN networks to host phishing infrastructure. The research maps deployment patterns, cost-optimization tactics, and evasion techniques used to bypass traditional URL filtering. Offers infrastructure defenders guidance on cloud security posture management and automated takedown workflows.

Source: https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns

## Device Code Phishing is an Evolution in Identity Takeover

**PIR:** 1.f

Traces the tactical shift from traditional credential phishing to device code-based identity takeover campaigns. The analysis highlights how attackers exploit user trust in legitimate authorization prompts to bypass security controls. Includes infrastructure indicators, campaign attribution, and strategic recommendations for identity threat detection and user awareness programs.

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## The Microsoft 365 Account Takeover That Leaves No Trace

**PIR:** 1.d

Analyzes stealthy Microsoft 365 account takeover techniques that evade standard logging and alerting mechanisms. Attackers exploit legacy authentication protocols, token replay, and shadow IT integrations to maintain persistent access. The report outlines forensic artifacts, detection queries for Microsoft Sentinel, and hardening recommendations for enterprise email and collaboration platforms.

Source: https://deafnews.it/en/article/the-microsoft-365-account-takeover-that-leaves-no-trace

## Anatomy of a Modern Phishing Campaign

**PIR:** 1.a

Breaks down the full lifecycle of contemporary phishing operations, from initial reconnaissance and infrastructure provisioning to payload delivery and data exfiltration. The article highlights emerging evasion tactics, infrastructure reuse patterns, and defensive strategies for network and email security teams to improve early detection and incident response capabilities.

Source: https://ransomnews.com/anatomy-of-a-modern-phishing-campaign

