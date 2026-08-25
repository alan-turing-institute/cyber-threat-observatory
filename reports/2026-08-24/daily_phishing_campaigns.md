# Daily phishing and identity campaigns

- **Report date:** 2026-08-24
- **Sources:** ketch OSINT (3 queries)

## OAuth Device Code Phishing: 37x Surge in Enterprise ATO

**PIR:** 1.d

Enterprise account takeover attacks leveraging OAuth device code flows have surged by 37%, exploiting legitimate authentication mechanisms to bypass traditional MFA. Attackers trick users into entering device codes on malicious portals, granting them direct access to corporate accounts without password theft. This report outlines the technical mechanics of the exploit, detection signatures for anomalous device code grants, and mitigation strategies including conditional access policies and user 

Source: https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/04/CSA_research_note_oauth-device-code-phishing-surge_20260405-csa-styled.pdf

## Device Code Phishing — The Attack That Makes MFA Irrelevant

**PIR:** 1.g

Traditional MFA implementations are increasingly rendered ineffective by device code phishing, which exploits the trust inherent in OAuth authorization flows. Attackers no longer need to steal passwords or intercept one-time codes; instead, they manipulate users into voluntarily granting access. This article breaks down the attack lifecycle, highlights vulnerabilities in default identity provider configurations, and outlines defensive measures including phishing-resistant MFA adoption, continuou

Source: https://cybergrind.org/blog/2026-06-02-device-code-phishing

## The Illicit Consent Grant Part 2: Device-Code Phishing and the AI PhaaS Wave | SlashID Blog

**PIR:** 1.c

The convergence of illicit consent grants and AI-driven PhaaS platforms is accelerating the scale and sophistication of device code phishing. Attackers now use generative AI to craft highly personalized lures and automate infrastructure deployment, reducing campaign setup time to minutes. This analysis explores the technical intersection of OAuth abuse and cloud-native hosting, providing defenders with threat hunting queries, consent audit frameworks, and strategies to detect AI-generated phishi

Source: https://slashid.com/blog/illicit-consent-grant-part-2

## Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA

**PIR:** 1.c

Modern phishing campaigns increasingly leverage cloud-native infrastructure to bypass traditional security controls. Attackers abuse serverless functions, containerized environments, and ephemeral hosting to host credential-harvesting pages with high resilience. This report details how threat actors utilize legitimate cloud services to scale phishing operations, evade takedown requests, and maintain persistent access. IT defenders must implement cloud workload protection, monitor for anomalous r

Source: https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns

## Device Code Phishing is an Evolution in Identity Takeover

**PIR:** 1.b

Device code phishing represents a critical evolution in identity takeover tactics, effectively neutralizing traditional multi-factor authentication defenses. By leveraging legitimate OAuth flows, attackers bypass password requirements and MFA prompts, directly compromising user sessions. This report examines the technical progression from credential harvesting to consent-based attacks, providing actionable detection rules for SIEM platforms and recommending architectural changes to identity prov

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## The Device Code Phishing Tsunami: What We’re Seeing in the Wild

**PIR:** 1.d

Recent threat intelligence reveals a tsunami of device code phishing campaigns targeting enterprise environments across multiple sectors. Attackers are automating the generation of fake verification portals and distributing them via SMS, voice calls, and compromised messaging platforms. This analysis details observed TTPs, infrastructure footprints, and the rapid scaling of these operations. Defenders should prioritize identity-centric monitoring, implement strict OAuth consent governance, and d

Source: https://www.levelblue.com/blogs/spiderlabs-blog/the-device-code-phishing-tsunami-what-were-seeing-in-the-wild

## A New Era Of Social Engineering: The Device Code Phishing Boom

**PIR:** 1.a

The proliferation of device code phishing marks a significant shift in social engineering tactics, moving beyond traditional email lures to target authentication workflows directly. Threat actors craft highly contextual prompts that mimic legitimate SSO and MFA verification steps, significantly increasing success rates. This article explores the psychological triggers exploited, provides real-world campaign examples, and recommends infrastructure-level controls such as blocking unapproved OAuth 

Source: https://coalitioninc.com/blog/security-labs/a-new-era-of-social-engineering-the-device-code-phishing-boom

## Tycoon2FA Returns: PhaaS Platform Survives Law Enforcement Disruption

**PIR:** 1.g

Despite coordinated law enforcement actions, the Tycoon2FA PhaaS platform has resurfaced, demonstrating remarkable operational resilience. This analysis examines how the infrastructure-as-a-service model enables rapid redeployment across multiple cloud providers, allowing attackers to continue facilitating MFA bypass and account takeover campaigns. Defenders are advised to monitor for known Tycoon2FA infrastructure patterns, enforce strict OAuth consent policies, and deploy adaptive authenticati

Source: https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/03/CSA_research_note_Tycoon2FA-PhaaS-resurrection-MaaS-resilience-20260326-csa-styled.pdf

