# **Infrastructure Daily Brief: 2026-10-06**

**Infrastructure Daily Report TLP:GREEN Alert Id: 77ef9c6f 2026-10-07 16:43:23**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                          | PIR(s)   |
|------------|---------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-59358 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-76750 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-76752 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-63692 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-106118 (Tier 2)                                                        | 3.k      |
| Cyber News | CVE-2026-106268 (Tier 2)                                                        | 3.k      |
| Threats    | Passkey-themed social engineering leads to identity and cloud compromise        | 1.h.3    |
| Threats    | Inside an AI‑enabled device code phishing campaign                              | 1.c.2    |
| Threats    | Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA     | 1.e.1    |
| Threats    | Midnight Blizzard-Linked Actor GTG-20006 Automated Device Code Phishing With AI | 1.d.2    |
| Threats    | AI-Generated Lures Behind Microsoft Cloud Account Takeovers                     | 1.d.1    |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover                       | 1.c.2    |
| Threats    | Talos: Attackers Refine Phishing Playbook To Target Critical Infrastructure     | 1.a.4    |
| Threats    | We Need to Talk About Device Code Phishing | Huntress                           | 1.c.2    |
| Threats    | CVE-2026-106488                                                                 | 1.b      |
| Threats    | CVE-2026-105307                                                                 | 1.b      |
| Threats    | CVE-2026-106457                                                                 | 1.b      |
| Threats    | CVE-2026-106460                                                                 | 1.b      |
| Threats    | CVE-2026-105306                                                                 | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Passkey-themed social engineering leads to identity and cloud compromise](https://www.microsoft.com/en-us/security/blog/2026/09/09/passkey-themed-social-engineering-leads-identity-cloud-compromise/)**

**PIR: 1.h.3**

Source: ketch Published: 2026-10-06

Details a sophisticated campaign where attackers impersonate passkey enrollment prompts to trick users into surrendering authentication credentials. The attack bypasses traditional MFA by exploiting user trust in biometric flows, leading to full cloud identity compromise. Infrastructure teams should enforce conditional access policies and monitor for anomalous passkey registration events.

___________________________________


# **[Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.c.2**

Source: ketch Published: 2026-10-06

Examines a campaign combining AI-generated landing pages with OAuth device code flows to harvest valid access tokens. Attackers automate victim interaction, reducing friction and evading traditional URL filtering. Security operations should block unauthorized OAuth app registrations and monitor for high-volume device code authorization requests.

___________________________________


# **[Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA](https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns)**

**PIR: 1.e.1**

Source: ketch Published: 2026-10-06

Explores how threat actors leverage cloud-native services like serverless functions, object storage, and CDN networks to host phishing infrastructure. Defenders must monitor cloud resource provisioning, implement strict IAM policies, and deploy cloud workload protection platforms to detect and dismantle ephemeral phishing environments before they scale.

___________________________________


# **[Midnight Blizzard-Linked Actor GTG-20006 Automated Device Code Phishing With AI](https://aegisai.ai/blog/anthropic-midnight-blizzard-ai-device-code-phishing)**

**PIR: 1.d.2**

Source: ketch Published: 2026-10-06

Reveals how a state-linked actor automates device code phishing using AI to generate localized, high-fidelity lures. The campaign demonstrates advanced tradecraft in evading cloud security controls and maintaining persistent access. Defenders should correlate threat intelligence feeds with identity logs and restrict OAuth app permissions to critical functions only.

___________________________________


# **[AI-Generated Lures Behind Microsoft Cloud Account Takeovers](https://labs.cloudsecurityalliance.org/research/csa-research-note-genai-passkey-phishing-msft-20260914-csa-s)**

**PIR: 1.d.1**

Source: ketch Published: 2026-10-06

Analyzes how generative AI crafts highly personalized, context-aware phishing lures targeting Microsoft 365 accounts. These AI-driven campaigns dynamically adapt to user roles and recent activities, significantly increasing click-through rates. Defenders must integrate AI detection tools into email gateways and train users to recognize synthetic content artifacts.

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.c.2**

Source: ketch Published: 2026-10-06

Tracks the maturation of device code phishing from manual spear-phishing to automated, infrastructure-scale operations. The technique now targets enterprise SSO environments, granting attackers persistent access without password theft. IT defenders must implement OAuth consent policies and deploy identity threat detection rules for anomalous token issuance.

___________________________________


# **[Talos: Attackers Refine Phishing Playbook To Target Critical Infrastructure](https://securityledger.com/2026/07/talos-attackers-refine-phishing-playbook-to-target-critical-infrastructure/)**

**PIR: 1.a.4**

Source: ketch Published: 2026-10-06

Outlines how threat groups are adapting phishing tactics to specifically target energy, utilities, and transportation sectors. Campaigns now mimic industry-specific compliance portals and operational technology dashboards. Infrastructure defenders must segment OT/IT networks, enforce strict email authentication, and monitor for lateral movement from compromised identity endpoints.

___________________________________


# **[We Need to Talk About Device Code Phishing | Huntress](https://www.huntress.com/blog/tradecraft-tuesday-device-code-phishing-explained)**

**PIR: 1.c.2**

Source: ketch Published: 2026-10-06

Breaks down the technical mechanics of device code phishing, highlighting how it circumvents MFA and email-based security controls. The guide provides actionable detection strategies, including monitoring for specific OAuth scopes and implementing just-in-time access controls. Essential reading for identity security teams managing hybrid cloud environments.

___________________________________


# **[CVE-2026-106488](https://nvd.nist.gov/vuln/detail/CVE-2026-106488)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-06

Backstage is an open framework for building developer portals. Prior to 0.4.20, the @backstage/plugin-auth-backend-module-oidc-provider package is affected by improper authentication in the oidc provider. Deployments using OIDC email-based identity resolution with a provider that permits unverified email addresses may allow an authenticated provider user to assume another catalog identity. This may grant access and permissions associated with that user. No direct availability impact is demonstra

___________________________________


# **[CVE-2026-105307](https://nvd.nist.gov/vuln/detail/CVE-2026-105307)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-05

A vulnerability was detected in Casdoor up to 3.161.1. Affected is the function ApiFilter of the file routers/authz_filter.go of the component API Endpoint. Performing a manipulation results in missing authentication. The attack can be initiated remotely. The exploit is now public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

___________________________________


# **[CVE-2026-106457](https://nvd.nist.gov/vuln/detail/CVE-2026-106457)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-06

Backstage is an open framework for building developer portals. From 0.1.0 until 0.5.0, the @backstage/plugin-auth-backend-module-cloudflare-access-provider package is affected by insufficient audience validation in the cloudflare access auth provider. The Cloudflare Access auth provider verifies a token's signature and team issuer, but affected versions do not verify that the token was issued for the Backstage application. A user holding a valid token for another Access application in the same C

___________________________________


# **[CVE-2026-106460](https://nvd.nist.gov/vuln/detail/CVE-2026-106460)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-06

Backstage is an open framework for building developer portals. From 0.3.0 until 0.6.15 and 0.7.5, the @backstage/plugin-auth-node package did not consistently honor explicit negative email verification during shared OAuth profile normalization. The affected paths include a selected profile email marked verified: false, a matching raw provider email marked email_verified: false, and an email obtained only from an ID token marked email_verified: false. Exploitation requires an admitted identity-pr

___________________________________


# **[CVE-2026-105306](https://nvd.nist.gov/vuln/detail/CVE-2026-105306)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-05

A flaw was found in the Dynamic Client Registration flow of the Keycloak identity and access management server. The issue occurs because the registration process fails to filter security-sensitive client attributes when a new client is created. An attacker with a valid Initial Access Token can register a client that bypasses audience checks during token introspection. This allows the attacker to view sensitive identity information, roles, and session details from access tokens belonging to other

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-59358 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-59358)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-06

Directly impacts Digital Identity infrastructure by enabling privilege escalation in Cloud Foundry UAA's OAuth token endpoint, compromising core IdAM and session management systems.

*Deep dive: `TIER_2_CVE-2026-59358.md`*

___________________________________


# **[CVE-2026-76750 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-76750)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-06

Unauthenticated RCE in HPE Aruba ClearPass NAC, a foundational network access control system explicitly deployed across Government, Healthcare, and Finance sectors to secure internal digital infrastructure.

*Deep dive: `TIER_2_CVE-2026-76750.md`*

___________________________________


# **[CVE-2026-76752 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-76752)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-06

Foundational NAC platform with unauthenticated admin bypass impacting network access controls and digital identity verification across Government, Healthcare, and Finance sectors.

*Deep dive: `TIER_2_CVE-2026-76752.md`*

___________________________________


# **[CVE-2026-63692 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-63692)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-06

General infrastructure (Kubernetes storage) explicitly tied to finance, healthcare, and government deployments; unauthenticated admin escalation impacts regulated cluster environments.

*Deep dive: `TIER_2_CVE-2026-63692.md`*

___________________________________


# **[CVE-2026-106118 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-106118)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-06

Tier 2 out-of-bounds write in foundational .NET image library (ImageSharp) exposes public-facing web apps and cloud services to unauthenticated DoS/RCE.

*Deep dive: `TIER_2_CVE-2026-106118.md`*

___________________________________


# **[CVE-2026-106268 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-106268)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-06

TIER 2 browser RCE affecting general infrastructure explicitly noted as used across Healthcare, Finance, and Government sectors.

*Deep dive: `TIER_2_CVE-2026-106268.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine