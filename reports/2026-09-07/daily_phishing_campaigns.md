# Daily phishing and identity campaigns

- **Report date:** 2026-09-07
- **Sources:** ketch OSINT (3 queries)

## OAuth Device Code Phishing: 37x Surge in Enterprise ATO

**PIR:** 1.b

Enterprise account takeover attacks leveraging OAuth device code flows have surged 37x, bypassing traditional MFA controls. Attackers exploit legitimate consent prompts to harvest long-lived access tokens, enabling persistent infrastructure access. Defenders must implement conditional access policies, monitor for anomalous device code grants, and restrict OAuth app permissions to mitigate this escalating identity threat.

Source: https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/04/CSA_research_note_oauth-device-code-phishing-surge_20260405-csa-styled.pdf

## The Device Code Phishing Tsunami: What We’re Seeing in the Wild

**PIR:** 1.c

Real-world telemetry reveals a massive wave of device code phishing campaigns targeting cloud administrators and developers. Threat actors automate credential harvesting via QR codes and short URLs, circumventing phishing-resistant MFA. Infrastructure teams should deploy token lifecycle monitoring, enforce FIDO2 hardware keys, and block unauthorized OAuth consent requests to secure critical environments.

Source: https://www.levelblue.com/blogs/spiderlabs-blog/the-device-code-phishing-tsunami-what-were-seeing-in-the-wild

## Device Code Phishing is an Evolution in Identity Takeover

**PIR:** 1.c

Identity takeover tactics have evolved beyond credential stuffing to exploit OAuth device authorization flows. Attackers now target privileged accounts with tailored consent phishing, granting them direct API access without password interception. IT defenders must audit third-party app integrations, implement zero-trust identity policies, and educate users on recognizing illicit consent prompts.

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## Device Code Phishing — The Attack That Makes MFA Irrelevant

**PIR:** 1.h

Traditional multi-factor authentication is increasingly rendered obsolete by device code phishing, which leverages legitimate OAuth flows to bypass security controls. By tricking users into authorizing malicious apps, attackers obtain persistent tokens that evade MFA challenges. Infrastructure security teams must transition to phishing-resistant authentication, enforce strict consent policies, and monitor for token abuse.

Source: https://cybergrind.org/blog/2026-06-02-device-code-phishing

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.d

Microsoft researchers dissect a sophisticated campaign using AI to craft hyper-realistic device code phishing pages and automate victim targeting. The attack chain exploits OAuth flows to harvest credentials and tokens, bypassing standard MFA. Infrastructure defenders must prioritize phishing-resistant MFA, monitor for anomalous OAuth consent activity, and leverage AI-driven threat detection to identify emerging campaigns.

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## The Illicit Consent Grant Part 2: Device-Code Phishing and the AI PhaaS Wave

**PIR:** 1.e

The convergence of illicit consent grants and AI-driven Phishing-as-a-Service platforms has created a highly automated identity threat landscape. Attackers dynamically generate convincing OAuth consent pages, scaling device code phishing across enterprises. Defenders should implement automated consent policy enforcement, deploy AI-detection tools for phishing infrastructure, and restrict OAuth scope permissions.

Source: https://slashid.com/blog/illicit-consent-grant-part-2

## Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns

**PIR:** 1.a

Modern phishing operations increasingly leverage cloud-native services like serverless functions, object storage, and CDN networks to host malicious payloads and evade detection. This infrastructure abuse complicates takedown efforts and extends campaign lifespans. IT security teams must implement cloud security posture management, monitor for misconfigured cloud assets, and integrate cloud telemetry into phishing detection workflows.

Source: https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns

## Tycoon2FA Returns: PhaaS Platform Survives Law Enforcement Disruption

**PIR:** 1.e

Despite law enforcement takedowns, the Tycoon2FA Phishing-as-a-Service platform has rapidly resurfaced, demonstrating the resilience of underground identity theft ecosystems. The platform offers attackers customizable MFA bypass tools and automated phishing infrastructure. Defenders should track known PhaaS indicators, enforce strict OAuth consent policies, and prepare incident response playbooks for rapid token revocation.

Source: https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/03/CSA_research_note_Tycoon2FA-PhaaS-resurrection-MaaS-resilience-20260326-csa-styled.pdf

