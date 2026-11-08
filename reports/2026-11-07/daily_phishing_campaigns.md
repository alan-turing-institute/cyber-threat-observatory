# Daily phishing and identity campaigns

- **Report date:** 2026-11-07
- **Sources:** ketch OSINT (3 queries)

## Unmasking EvilTokens: Getting to the root of device code phishing

**PIR:** 1.c

This analysis details the EvilTokens infrastructure, revealing how threat actors exploit OAuth device code flows to bypass traditional MFA. Defenders learn to identify malicious redirect URIs, monitor anomalous device code authorization requests, and implement conditional access policies that restrict device code usage to trusted networks. The report provides actionable telemetry for detecting token theft before lateral movement occurs.

Source: https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.e

Explores how attackers leverage generative AI to automate device code phishing at scale, dynamically generating convincing landing pages and real-time proxy responses. The article outlines detection strategies for infrastructure teams, including monitoring for rapid session creation, analyzing proxy traffic patterns, and deploying AI-resistant authentication controls. Critical for securing cloud identity perimeters against automated credential harvesting.

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale

**PIR:** 1.b

A deep dive into the Tycoon2FA kit, which intercepts multi-factor authentication tokens in real-time via reverse proxy techniques. The breakdown highlights infrastructure indicators such as specific CDN abuse patterns, certificate pinning evasion, and automated session hijacking workflows. Security teams gain insights to block kit domains, update proxy signatures, and enforce token binding to mitigate AiTM compromises.

Source: https://microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale

## Breaking the code: Multi-stage ‘code of conduct’ phishing campaign leads to AiTM token compromise

**PIR:** 1.a

Documents a sophisticated multi-stage campaign using fake corporate compliance portals to harvest credentials and session tokens. The report maps the attack chain from initial spearphishing emails to AiTM proxy deployment, offering defenders network-level detection rules, email filtering enhancements, and user training recommendations to disrupt token theft pipelines targeting enterprise infrastructure.

Source: https://microsoft.com/en-us/security/blog/2026/05/04/breaking-the-code-multi-stage-code-of-conduct-phishing-campaign-leads-to-aitm-token-compromise

## GhostCode: Dissecting a Novel Device Code Phishing Kit

**PIR:** 1.c

Analyzes the GhostCode kit, which automates device code phishing by mimicking legitimate Microsoft login flows and capturing authorization codes. The technical breakdown reveals infrastructure footprints, including dynamic domain generation algorithms and cloud hosting patterns. IT defenders can leverage these IOCs to update firewall rules, monitor OAuth endpoints, and implement device code flow restrictions.

Source: https://www.esentire.com/blog/ghostcode-dissecting-a-novel-device-code-phishing-kit

## Device Code Phishing is an Evolution in Identity Takeover

**PIR:** 1.c

Examines the strategic shift from traditional credential harvesting to device code phishing, which circumvents password-based defenses and MFA. The article provides a threat landscape overview, detection methodologies, and mitigation frameworks for infrastructure teams. Recommendations include restricting device code grants, monitoring for anomalous authentication patterns, and integrating identity threat intelligence into SIEM workflows.

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## Joint advisory: state-sponsored spear-phishing campaigns targeting critical infrastructure - SUVAT

**PIR:** 1.d

A Five Eyes joint advisory detailing state-sponsored spearphishing operations targeting energy, transportation, and government sectors. The report outlines TTPs, including malicious document attachments, credential harvesting portals, and initial access brokers. Infrastructure defenders receive prioritized mitigation steps, network segmentation guidance, and threat hunting queries to identify early-stage compromises in critical systems.

Source: https://suvat.uk/blog/five-eyes-advisory.html

## Microsoft 365 device code phishing campaign bypasses password stealing

**PIR:** 1.c

Details a targeted campaign exploiting M365 device code authentication to bypass traditional password theft mechanisms. The analysis covers phishing email structures, malicious redirect flows, and token exchange patterns. Defenders are provided with actionable detection logic for Exchange Online, Azure AD sign-in logs, and proxy traffic analysis to block unauthorized device code authorizations.

Source: https://www.reversinglabs.com/blog/device-code-phishing-campaign

