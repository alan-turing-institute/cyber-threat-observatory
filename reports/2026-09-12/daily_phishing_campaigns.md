# Daily phishing and identity campaigns

- **Report date:** 2026-09-12
- **Sources:** ketch OSINT (3 queries)

## The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations

**PIR:** 1.e

Generative AI is transforming phishing from broad, low-success campaigns into highly targeted, autonomous operations. AI models now craft context-aware emails, generate realistic voice clones, and dynamically adapt landing pages based on victim behavior. Defenders should prioritize AI-driven email security, implement behavioral analytics, and train staff to recognize subtle linguistic and contextual anomalies in automated communications.

Source: https://itsecurityguru.org/2026/05/27/the-ai-phishing-revolution-from-spray-and-pray-to-autonomous-operations

## Device Code Phishing Surge — Threat Analysis

**PIR:** 1.i

A significant surge in device code phishing campaigns is exploiting OAuth 2.0 device authorization flows to bypass traditional MFA. Attackers trick users into entering short alphanumeric codes on malicious sites, granting them direct access to corporate accounts without passwords. Infrastructure teams must restrict device code flows to approved applications, monitor for anomalous token issuance, and educate users on recognizing these prompts.

Source: https://intel.threadlinqs.com/threat/TL-2026-2468

## When checking the URL isn’t enough: phishing via the Microsoft identity platform | Securelist

**PIR:** 1.f

Attackers are exploiting the Microsoft identity platform to host phishing pages that appear legitimate, rendering traditional URL inspection ineffective. By leveraging trusted Microsoft domains and OAuth flows, threat actors deceive users into surrendering credentials or device codes. Defenders should implement strict conditional access rules, monitor for anomalous sign-in patterns, and deploy identity-aware proxy solutions to block platform-abuse attacks.

Source: https://securelist.com/microsoft-device-code-phishing-attack/120350/

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.i

This analysis details a sophisticated campaign combining AI-generated lures with device code phishing to compromise Microsoft 365 accounts. Attackers use AI to personalize outreach and automate the collection of device codes, enabling rapid account takeover. Defenders should enforce conditional access policies, disable unnecessary device code grants, and deploy real-time alerting for suspicious OAuth consent requests.

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA

**PIR:** 1.g

CISA has issued a warning regarding Laundry Bear’s exploitation of a zero-click vulnerability in Zimbra email servers to deliver phishing payloads. This attack requires no user interaction, automatically compromising accounts and deploying malicious content. Infrastructure defenders must prioritize patching Zimbra instances, implement network segmentation for email servers, and deploy endpoint detection to catch post-exploitation activity.

Source: https://tempmail.ninja/blog/laundry-bear-zimbra-phishing

## Device Code Phishing is an Evolution in Identity Takeover

**PIR:** 1.j

Device code phishing represents a critical evolution in identity takeover tactics, shifting focus from credential theft to direct token acquisition. By exploiting legitimate authentication flows, attackers bypass password resets and MFA prompts. IT infrastructure defenders must audit OAuth application permissions, implement token lifecycle monitoring, and adopt zero-trust identity frameworks to mitigate these sophisticated account compromise vectors.

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## Microsoft 365 device code phishing campaign bypasses password stealing | RL Blog

**PIR:** 1.d

This campaign demonstrates how device code phishing effectively circumvents traditional password-stealing techniques and MFA protections. Attackers leverage legitimate Microsoft authentication endpoints to harvest valid access tokens directly from users. Infrastructure teams must prioritize token-based threat detection, restrict device code usage to essential applications, and enforce multi-factor authentication with phishing-resistant methods like FIDO2.

Source: https://www.reversinglabs.com/blog/device-code-phishing-campaign

## Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA

**PIR:** 1.f

Attackers are increasingly leveraging cloud-native services like serverless functions, object storage, and CDN networks to host phishing infrastructure. This approach bypasses traditional domain reputation filters and complicates takedown efforts. Infrastructure defenders must monitor cloud provider abuse reports, implement egress filtering, and adopt cloud-native security posture management to detect and mitigate these ephemeral phishing deployments.

Source: https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns

