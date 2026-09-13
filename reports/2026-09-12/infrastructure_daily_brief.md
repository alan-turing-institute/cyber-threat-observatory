# **Infrastructure Daily Brief: 2026-09-12**

**Infrastructure Daily Report TLP:GREEN Alert Id: 0dcd612b 2026-09-13 02:51:30**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-75800 (Tier 2)                                                          | 3.k      |
| Threats    | The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations         | 1.e      |
| Threats    | Device Code Phishing Surge — Threat Analysis                                     | 1.i      |
| Threats    | When checking the URL isn’t enough: phishing via the Microsoft identity platform | 1.f      |
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.i      |
| Threats    | Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA                  | 1.g      |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover                        | 1.j      |
| Threats    | Microsoft 365 device code phishing campaign bypasses password stealing | RL Blog | 1.d      |
| Threats    | Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA      | 1.f      |
| Threats    | CVE-2026-90474                                                                   | 1.b      |
| Threats    | CVE-2026-90449                                                                   | 1.b      |
| Threats    | CVE-2026-89298                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations](https://itsecurityguru.org/2026/05/27/the-ai-phishing-revolution-from-spray-and-pray-to-autonomous-operations)**

**PIR: 1.e**

Source: ketch Published: 2026-09-12

Generative AI is transforming phishing from broad, low-success campaigns into highly targeted, autonomous operations. AI models now craft context-aware emails, generate realistic voice clones, and dynamically adapt landing pages based on victim behavior. Defenders should prioritize AI-driven email security, implement behavioral analytics, and train staff to recognize subtle linguistic and contextual anomalies in automated communications.

___________________________________


# **[Device Code Phishing Surge — Threat Analysis](https://intel.threadlinqs.com/threat/TL-2026-2468)**

**PIR: 1.i**

Source: ketch Published: 2026-09-12

A significant surge in device code phishing campaigns is exploiting OAuth 2.0 device authorization flows to bypass traditional MFA. Attackers trick users into entering short alphanumeric codes on malicious sites, granting them direct access to corporate accounts without passwords. Infrastructure teams must restrict device code flows to approved applications, monitor for anomalous token issuance, and educate users on recognizing these prompts.

___________________________________


# **[When checking the URL isn’t enough: phishing via the Microsoft identity platform | Securelist](https://securelist.com/microsoft-device-code-phishing-attack/120350/)**

**PIR: 1.f**

Source: ketch Published: 2026-09-12

Attackers are exploiting the Microsoft identity platform to host phishing pages that appear legitimate, rendering traditional URL inspection ineffective. By leveraging trusted Microsoft domains and OAuth flows, threat actors deceive users into surrendering credentials or device codes. Defenders should implement strict conditional access rules, monitor for anomalous sign-in patterns, and deploy identity-aware proxy solutions to block platform-abuse attacks.

___________________________________


# **[Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.i**

Source: ketch Published: 2026-09-12

This analysis details a sophisticated campaign combining AI-generated lures with device code phishing to compromise Microsoft 365 accounts. Attackers use AI to personalize outreach and automate the collection of device codes, enabling rapid account takeover. Defenders should enforce conditional access policies, disable unnecessary device code grants, and deploy real-time alerting for suspicious OAuth consent requests.

___________________________________


# **[Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA](https://tempmail.ninja/blog/laundry-bear-zimbra-phishing)**

**PIR: 1.g**

Source: ketch Published: 2026-09-12

CISA has issued a warning regarding Laundry Bear’s exploitation of a zero-click vulnerability in Zimbra email servers to deliver phishing payloads. This attack requires no user interaction, automatically compromising accounts and deploying malicious content. Infrastructure defenders must prioritize patching Zimbra instances, implement network segmentation for email servers, and deploy endpoint detection to catch post-exploitation activity.

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.j**

Source: ketch Published: 2026-09-12

Device code phishing represents a critical evolution in identity takeover tactics, shifting focus from credential theft to direct token acquisition. By exploiting legitimate authentication flows, attackers bypass password resets and MFA prompts. IT infrastructure defenders must audit OAuth application permissions, implement token lifecycle monitoring, and adopt zero-trust identity frameworks to mitigate these sophisticated account compromise vectors.

___________________________________


# **[Microsoft 365 device code phishing campaign bypasses password stealing | RL Blog](https://www.reversinglabs.com/blog/device-code-phishing-campaign)**

**PIR: 1.d**

Source: ketch Published: 2026-09-12

This campaign demonstrates how device code phishing effectively circumvents traditional password-stealing techniques and MFA protections. Attackers leverage legitimate Microsoft authentication endpoints to harvest valid access tokens directly from users. Infrastructure teams must prioritize token-based threat detection, restrict device code usage to essential applications, and enforce multi-factor authentication with phishing-resistant methods like FIDO2.

___________________________________


# **[Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA](https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns)**

**PIR: 1.f**

Source: ketch Published: 2026-09-12

Attackers are increasingly leveraging cloud-native services like serverless functions, object storage, and CDN networks to host phishing infrastructure. This approach bypasses traditional domain reputation filters and complicates takedown efforts. Infrastructure defenders must monitor cloud provider abuse reports, implement egress filtering, and adopt cloud-native security posture management to detect and mitigate these ephemeral phishing deployments.

___________________________________


# **[CVE-2026-90474](https://nvd.nist.gov/vuln/detail/CVE-2026-90474)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-12

MCPHub before 1.0.32 contains an authentication bypass vulnerability in its embedded OAuth 2.0 authorization server where client authentication is disabled by default and PKCE enforcement is optional. Attackers who obtain an authorization code through interception can redeem it for access tokens without providing a client secret or PKCE verifier, gaining access to victim accounts and their privileges.

___________________________________


# **[CVE-2026-90449](https://nvd.nist.gov/vuln/detail/CVE-2026-90449)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-11

When a particular authentication mode is configured, the reverse proxy forwards requests for a bundled third-party administrative interface directly to that interface without applying the gateway's own authentication requirement first. All access control for this administrative interface, which manages the credential store used to gate every other service in the deployment, is delegated entirely to that third-party interface's own login mechanism. Any authentication weakness in that bundled inte

___________________________________


# **[CVE-2026-89298](https://nvd.nist.gov/vuln/detail/CVE-2026-89298)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-11

A flaw was found in the Dynamic Client Registration service of Keycloak, an open-source identity and access management solution. The issue occurs when a user with the view-clients role accesses the client registration endpoint to retrieve client details. Due to a failure to mask sensitive information, the service returns the client's confidential secret in cleartext. This could allow a read-only administrator to obtain full access to the affected client's account and potentially escalate their p

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-75800 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-75800)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-12

Critical unauthenticated SAML/SSO bypass in a WordPress identity plugin, directly compromising digital identity infrastructure and administrative access controls.

*Deep dive: `TIER_2_CVE-2026-75800.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine