# **Infrastructure Daily Brief: 2026-09-20**

**Infrastructure Daily Report TLP:GREEN Alert Id: dea49a0b 2026-09-21 04:32:16**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-90817 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-94083 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-94109 (Tier 2)                                                          | 3.k      |
| Threats    | Microsoft 365: Block Device Code Flow Against GhostCode                          | 1.e      |
| Threats    | GhostCode Abuses Microsoft Entra Device Enrollment to Maintain Access After Toke | 1.f      |
| Threats    | Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA      | 1.f      |
| Threats    | GhostCode Phishing Kit Bypasses Microsoft 365 MFA to Hijack Accounts in 78 Secon | 1.d      |
| Threats    | Fast Flux Phishing Turns the Internet Into a Moving Target as Silent Push Uncove | 1.g      |
| Threats    | The Shadow Campaigns: Uncovering Global Espionage                                | 1.j.3    |
| Threats    | Operation HookedWing: 4-Year Phishing Campaign Hits 500+                         | 1.a      |
| Threats    | Government Leaders Face Evolving Phishing Attacks                                | 1.b      |
| Threats    | CVE-2026-94000                                                                   | 1.b      |
| Threats    | CVE-2026-94001                                                                   | 1.b      |
| Threats    | CVE-2026-93999                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Microsoft 365: Block Device Code Flow Against GhostCode](https://windowsforum.com/news/microsoft-365-block-device-code-flow-against-ghostcode.444973)**

**PIR: 1.e**

Source: ketch Published: 2026-09-20

GhostCode operators exploit the OAuth 2.0 Device Code Flow to authenticate on behalf of users without requiring interactive MFA prompts. This guide provides step-by-step PowerShell and Entra ID Conditional Access policies to restrict device code grants, enforce risk-based authentication, and audit legacy application permissions. Critical for M365 administrators seeking to close authentication bypass vectors.

___________________________________


# **[GhostCode Abuses Microsoft Entra Device Enrollment to Maintain Access After Token Revocation](https://gbhackers.com/ghostcode-abuses-microsoft-entra)**

**PIR: 1.f**

Source: ketch Published: 2026-09-20

Researchers detail how GhostCode registers rogue devices via Entra ID enrollment endpoints, creating persistent backdoors that survive password resets and token revocations. The technique abuses legitimate device management APIs to bypass conditional access restrictions. IT infrastructure defenders must audit device compliance policies, restrict enrollment permissions to approved administrators, and monitor for unauthorized device registration events.

___________________________________


# **[Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA](https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns)**

**PIR: 1.f**

Source: ketch Published: 2026-09-20

Threat actors increasingly leverage cloud-native services like serverless functions, object storage, and CDN networks to host phishing infrastructure. This report details how defenders can detect anomalous cloud resource provisioning, monitor for misconfigured IAM roles, and implement egress filtering to disrupt these ephemeral attack surfaces. Essential reading for cloud security architects managing hybrid environments.

___________________________________


# **[GhostCode Phishing Kit Bypasses Microsoft 365 MFA to Hijack Accounts in 78 Seconds](https://cybersecuritynews.com/ghostcode-phishing-kit/amp)**

**PIR: 1.d**

Source: ketch Published: 2026-09-20

Analysis reveals how the GhostCode phishing kit intercepts valid MFA tokens during the authentication handshake, granting attackers immediate account access. The kit utilizes real-time proxying to mirror legitimate Microsoft login pages while silently capturing session cookies. Defenders should prioritize phishing-resistant MFA methods like FIDO2 security keys and deploy token-binding policies to neutralize this rapid takeover technique.

___________________________________


# **[Fast Flux Phishing Turns the Internet Into a Moving Target as Silent Push Uncovers a Massive Canada-First Banking Operation + Video - UNDERCODE NEWS](https://undercodenews.com/fast-flux-phishing-turns-the-internet-into-a-moving-target-as-silent-push-uncovers-a-massive-canada-first-banking-operation-video)**

**PIR: 1.g**

Source: ketch Published: 2026-09-20

Silent Push researchers expose a sophisticated fast-flux network used to host credential-harvesting pages targeting Canadian banking customers. By rapidly rotating IP addresses and DNS records, attackers evade traditional blocklists and takedown requests. Infrastructure defenders are advised to deploy DNS sinkholing, monitor for high-entropy domain registrations, and integrate threat intelligence feeds that track flux network patterns.

___________________________________


# **[The Shadow Campaigns: Uncovering Global Espionage](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)**

**PIR: 1.j.3**

Source: ketch Published: 2026-09-20

Palo Alto Networks Unit 42 tracks a coordinated espionage operation utilizing multi-stage phishing campaigns to infiltrate critical infrastructure sectors. Attackers combine initial access brokers, custom malware loaders, and living-off-the-land techniques to establish long-term persistence. Network defenders should focus on endpoint detection tuning, lateral movement monitoring, and threat hunting for known APT infrastructure indicators.

___________________________________


# **[Operation HookedWing: 4-Year Phishing Campaign Hits 500+](https://cipherssecurity.com/operation-hookedwing-phishing-500/)**

**PIR: 1.a**

Source: ketch Published: 2026-09-20

A four-year spear-phishing operation compromised over 500 organizations by exploiting trusted vendor relationships and compromised email accounts. Attackers used highly customized lures and legitimate-looking document attachments to deploy credential stealers. Infrastructure teams must review email gateway rules, enforce strict DMARC/DKIM/SPF alignment, and monitor for anomalous outbound authentication attempts from compromised mailboxes.

___________________________________


# **[Government Leaders Face Evolving Phishing Attacks](https://statetechmagazine.com/article/2025/09/when-trust-becomes-weapon-government-leaders-face-evolving-phishing-attacks)**

**PIR: 1.b**

Source: ketch Published: 2026-09-20

State and local government executives are increasingly targeted by whaling campaigns that exploit public schedules and official correspondence. Attackers craft highly personalized messages mimicking inter-agency communications to extract sensitive policy documents and credentials. Defenders should implement executive protection programs, deploy AI-driven email classification, and enforce strict data loss prevention controls on high-privilege accounts.

___________________________________


# **[CVE-2026-94000](https://nvd.nist.gov/vuln/detail/CVE-2026-94000)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-19

A flaw was found in the Admin REST API of Keycloak, an open-source identity and access management solution. The issue occurs in the group-membership endpoints where the system fails to check if a group grants administrative privileges before allowing a user to be added. This allows a delegated administrator with limited permissions to add themselves to a high-privilege group, potentially gaining full control over the entire realm.

___________________________________


# **[CVE-2026-94001](https://nvd.nist.gov/vuln/detail/CVE-2026-94001)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-19

A flaw was found in the Admin REST API of Keycloak, an open-source identity and access management solution. The endpoint used for deleting user credentials does not correctly check for fine-grained reset-password permissions. This allows a delegated administrator, who should be restricted from resetting passwords, to delete a user's password credentials, resulting in the user being unable to log in.

___________________________________


# **[CVE-2026-93999](https://nvd.nist.gov/vuln/detail/CVE-2026-93999)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-19

A flaw was found in the OIDC protocol implementation of Keycloak, an open-source identity and access management solution. The issue occurs during the token refresh process when the server restores requested audiences from stored client IDs. Keycloak fails to verify if the target audience client is still enabled before issuing a new access token. This allows an application with an existing refresh token to continue obtaining valid access tokens for a disabled client, potentially bypassing adminis

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-90817 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-90817)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-20

Unauthenticated RCE in REDCap directly threatens Healthcare and Government research infrastructure by exposing clinical trial data and patient records on internet-facing deployments.

*Deep dive: `TIER_2_CVE-2026-90817.md`*

___________________________________


# **[CVE-2026-94083 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-94083)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-20

Foundational IDS/IPS infrastructure securing network fabric for critical sectors and DPI services; default-enabled DoH2 parser crash poses high availability risk.

*Deep dive: `TIER_2_CVE-2026-94083.md`*

___________________________________


# **[CVE-2026-94109 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-94109)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-20

Government sector: Authenticated RCE in openEQUELLA threatens public research institutions and national libraries managing critical digital assets and research outputs.

*Deep dive: `TIER_2_CVE-2026-94109.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine