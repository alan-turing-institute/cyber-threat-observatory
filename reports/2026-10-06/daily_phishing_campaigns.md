# Daily phishing and identity campaigns

- **Report date:** 2026-10-06
- **Sources:** ketch OSINT (3 queries)

## Passkey-themed social engineering leads to identity and cloud compromise

**PIR:** 1.h.3

Details a sophisticated campaign where attackers impersonate passkey enrollment prompts to trick users into surrendering authentication credentials. The attack bypasses traditional MFA by exploiting user trust in biometric flows, leading to full cloud identity compromise. Infrastructure teams should enforce conditional access policies and monitor for anomalous passkey registration events.

Source: https://www.microsoft.com/en-us/security/blog/2026/09/09/passkey-themed-social-engineering-leads-identity-cloud-compromise/

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.c.2

Examines a campaign combining AI-generated landing pages with OAuth device code flows to harvest valid access tokens. Attackers automate victim interaction, reducing friction and evading traditional URL filtering. Security operations should block unauthorized OAuth app registrations and monitor for high-volume device code authorization requests.

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA

**PIR:** 1.e.1

Explores how threat actors leverage cloud-native services like serverless functions, object storage, and CDN networks to host phishing infrastructure. Defenders must monitor cloud resource provisioning, implement strict IAM policies, and deploy cloud workload protection platforms to detect and dismantle ephemeral phishing environments before they scale.

Source: https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns

## Midnight Blizzard-Linked Actor GTG-20006 Automated Device Code Phishing With AI

**PIR:** 1.d.2

Reveals how a state-linked actor automates device code phishing using AI to generate localized, high-fidelity lures. The campaign demonstrates advanced tradecraft in evading cloud security controls and maintaining persistent access. Defenders should correlate threat intelligence feeds with identity logs and restrict OAuth app permissions to critical functions only.

Source: https://aegisai.ai/blog/anthropic-midnight-blizzard-ai-device-code-phishing

## AI-Generated Lures Behind Microsoft Cloud Account Takeovers

**PIR:** 1.d.1

Analyzes how generative AI crafts highly personalized, context-aware phishing lures targeting Microsoft 365 accounts. These AI-driven campaigns dynamically adapt to user roles and recent activities, significantly increasing click-through rates. Defenders must integrate AI detection tools into email gateways and train users to recognize synthetic content artifacts.

Source: https://labs.cloudsecurityalliance.org/research/csa-research-note-genai-passkey-phishing-msft-20260914-csa-s

## Device Code Phishing is an Evolution in Identity Takeover

**PIR:** 1.c.2

Tracks the maturation of device code phishing from manual spear-phishing to automated, infrastructure-scale operations. The technique now targets enterprise SSO environments, granting attackers persistent access without password theft. IT defenders must implement OAuth consent policies and deploy identity threat detection rules for anomalous token issuance.

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## Talos: Attackers Refine Phishing Playbook To Target Critical Infrastructure

**PIR:** 1.a.4

Outlines how threat groups are adapting phishing tactics to specifically target energy, utilities, and transportation sectors. Campaigns now mimic industry-specific compliance portals and operational technology dashboards. Infrastructure defenders must segment OT/IT networks, enforce strict email authentication, and monitor for lateral movement from compromised identity endpoints.

Source: https://securityledger.com/2026/07/talos-attackers-refine-phishing-playbook-to-target-critical-infrastructure/

## We Need to Talk About Device Code Phishing | Huntress

**PIR:** 1.c.2

Breaks down the technical mechanics of device code phishing, highlighting how it circumvents MFA and email-based security controls. The guide provides actionable detection strategies, including monitoring for specific OAuth scopes and implementing just-in-time access controls. Essential reading for identity security teams managing hybrid cloud environments.

Source: https://www.huntress.com/blog/tradecraft-tuesday-device-code-phishing-explained

