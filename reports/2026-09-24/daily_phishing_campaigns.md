# Daily phishing and identity campaigns

- **Report date:** 2026-09-24
- **Sources:** ketch OSINT (3 queries)

## Microsoft 365: Block Device Code Flow Against GhostCode

**PIR:** 1.d

Microsoft recommends disabling the device code flow in Microsoft 365 to counter GhostCode, a threat actor leveraging OAuth 2.0 device authorization grants to bypass MFA. Attackers redirect authentication to legitimate desktop or mobile apps, capturing valid tokens. Infrastructure administrators should restrict device code flow usage, implement token lifetime policies, and monitor for suspicious app registrations.

Source: https://windowsforum.com/news/microsoft-365-block-device-code-flow-against-ghostcode.444973?amp=1

## Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA

**PIR:** 1.a

Attackers increasingly leverage serverless functions, containerized environments, and ephemeral cloud resources to host phishing infrastructure, evading traditional perimeter defenses. This report details TTPs for cloud-native abuse, including automated resource provisioning and DNS tunneling. Defenders must implement cloud workload protection platforms, enforce strict IAM policies, and monitor for anomalous resource creation patterns to disrupt these campaigns before they scale.

Source: https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns

## AI-Generated Lures Behind Microsoft Cloud Account Takeovers

**PIR:** 1.c

Generative AI is now crafting highly personalized phishing lures that successfully bypass traditional email security gateways, leading to widespread Microsoft cloud account takeovers. The campaign exploits AI-generated passkey prompts and contextual social engineering. Defenders must deploy AI-aware content inspection, enforce conditional access policies, and monitor for anomalous authentication patterns to mitigate identity compromise.

Source: https://labs.cloudsecurityalliance.org/research/csa-research-note-genai-passkey-phishing-msft-20260914-csa-s

## AI-Enabled Device Code Phishing Campaign Abuses Device Code Sign-In Flow

**PIR:** 1.g

A new campaign abuses the OAuth 2.0 device code sign-in flow using AI-generated prompts that perfectly mimic Microsoft authentication interfaces. Attackers exploit the flow’s lack of traditional web login pages to capture valid tokens. Infrastructure teams must restrict device code flow permissions, implement application allowlisting, and deploy behavioral analytics to detect automated authentication requests.

Source: https://captechgroup.com/threat-intelligence-center/ai-enabled-device-code-phishing-campaign-abuses-de-81a334

## Device Code Phishing: The MFA Bypass Without a Fake Login

**PIR:** 1.d.2

Device code phishing enables attackers to bypass MFA without deploying fake login pages by leveraging legitimate OAuth 2.0 device authorization grants. The technique redirects users to authenticate via trusted apps, capturing session tokens. Defenders should disable unnecessary device code flows, enforce phishing-resistant MFA, and monitor authentication logs for anomalous device code usage patterns.

Source: https://securityboulevard.com/2026/09/device-code-phishing-the-mfa-bypass-without-a-fake-login

## Tycoon2FA Returns: PhaaS Platform Survives Law Enforcement Disruption

**PIR:** 1.b

Following law enforcement disruption, the Tycoon2FA PhaaS platform rapidly migrated to alternative cloud providers, demonstrating remarkable infrastructure resilience. The analysis covers criminal MaaS adaptation, domain generation algorithms, and payment obfuscation. Infrastructure teams should prioritize continuous threat hunting, implement automated takedown workflows, and monitor for infrastructure reuse patterns to counter persistent PhaaS ecosystems.

Source: https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/03/CSA_research_note_Tycoon2FA-PhaaS-resurrection-MaaS-resilience-20260326-csa-styled.pdf

## EvilTokens made phishing-as-a-service look easy. Then it got taken down

**PIR:** 1.f

EvilTokens streamlined phishing-as-a-service by offering pre-built token-stealing campaigns, significantly lowering the barrier for credential harvesting. Following its takedown, threat actors rapidly forked the infrastructure. Defenders must focus on session token lifecycle management, implement strict conditional access rules, and monitor for anomalous token issuance to prevent account takeover.

Source: https://securityaffairs.com/199593/cyber-crime/eviltokens-made-phishing-as-a-service-look-easy-then-it-got-taken-down.html

## Microsoft Warns of EvilTokens AI Phishing Service Hijacking Thousands of Accounts

**PIR:** 1.e

Microsoft warns that EvilTokens leverages AI automation to hijack thousands of enterprise accounts through sophisticated phishing campaigns. The service combines machine learning-driven lure generation with scalable infrastructure. IT defenders should prioritize identity protection solutions, enforce multi-factor authentication with phishing-resistant methods, and conduct regular access reviews to detect compromised credentials.

Source: https://gbhackers.com/eviltokens-ai-phishing/amp

