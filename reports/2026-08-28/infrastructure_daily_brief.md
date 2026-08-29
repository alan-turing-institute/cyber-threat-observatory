# **Infrastructure Daily Brief: 2026-08-28**

**Infrastructure Daily Report TLP:GREEN Alert Id: dd2b3c25 2026-08-29 15:27:08**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                      | PIR(s)   |
|------------|-----------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-18918 (Tier 2)                                                     | 3.k      |
| Cyber News | CVE-2026-82262 (Tier 2)                                                     | 3.k      |
| Cyber News | CVE-2026-27852 (Tier 2)                                                     | 3.k      |
| Cyber News | CVE-2026-42007 (Tier 2)                                                     | 3.k      |
| Cyber News | CVE-2026-55552 (Tier 2)                                                     | 3.k      |
| Cyber News | CVE-2026-55559 (Tier 2)                                                     | 3.k      |
| Cyber News | CVE-2026-38820 (Tier 2)                                                     | 3.k      |
| Cyber News | CVE-2026-38821 (Tier 2)                                                     | 3.k      |
| Cyber News | CVE-2026-38822 (Tier 2)                                                     | 3.k      |
| Cyber News | CVE-2026-42391 (Tier 2)                                                     | 3.k      |
| Cyber News | CVE-2026-55848 (Tier 2)                                                     | 3.k      |
| Cyber News | CVE-2026-82078 (Tier 2)                                                     | 3.k      |
| Cyber News | CVE-2026-82244 (Tier 2)                                                     | 3.k      |
| Cyber News | CVE-2026-82266 (Tier 2)                                                     | 3.k      |
| Threats    | Inside an AI‑enabled device code phishing campaign                          | 1.j.3    |
| Threats    | OAuth Device Code Phishing: 37x Surge in Enterprise ATO                     | 1.j.3    |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover                   | 1.j.3    |
| Threats    | Microsoft 365 Device Code Phishing Campaign Bypasses Password Theft ...     | 1.j.3    |
| Threats    | Device Code Phishing Hits 340+ Microsoft 365 Orgs Across Five Countries ... | 1.j.3    |
| Threats    | Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA | 1.a      |
| Threats    | Device Code Phishing Drives Identity Takeover Risks                         | 1.j.3    |
| Threats    | CVE-2026-59354                                                              | 1.b      |
| Threats    | CVE-2026-81826                                                              | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.j.3**

Source: ketch Published: 2026-08-28

Microsoft researchers uncover a sophisticated campaign leveraging AI and end-to-end automation to scale device code phishing. Threat actors generate live authentication codes on demand, significantly increasing compromise success rates and maintaining persistent access. The report highlights technical indicators, AI-driven lure generation, and recommends enforcing strict OAuth consent policies and continuous identity monitoring.

___________________________________


# **[OAuth Device Code Phishing: 37x Surge in Enterprise ATO](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/04/CSA_research_note_oauth-device-code-phishing-surge_20260405-csa-styled.pdf)**

**PIR: 1.j.3**

Source: ketch Published: 2026-08-28

The Cloud Security Alliance documents a dramatic 37-fold increase in enterprise account takeovers driven by OAuth device code phishing. Attackers exploit the legitimate device authorization flow to bypass multi-factor authentication, tricking users into entering codes on malicious sites. This research outlines mitigation strategies, including conditional access policies, user training, and monitoring for anomalous OAuth consent grants.

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.j.3**

Source: ketch Published: 2026-08-28

Device code phishing is rapidly expanding across the threat landscape, fueled by newly released criminal toolkits and phishing-as-a-service platforms. Attackers utilize automated techniques to generate convincing lures that manipulate corporate validation workflows. Security teams must prioritize identity-centric defenses, monitor for suspicious OAuth token issuance, and educate users on recognizing device code prompts.

___________________________________


# **[Microsoft 365 Device Code Phishing Campaign Bypasses Password Theft ...](https://cybersecuritynews.com/microsoft-365-device-code-phishing-campaign/)**

**PIR: 1.j.3**

Source: ketch Published: 2026-08-28

ReversingLabs analysts detail an active campaign targeting Microsoft 365 environments by combining realistic business-themed emails with a polished phishing kit. Attackers abuse Microsoft’s Device Authorization Grant flow to execute near-invisible account takeovers without stealing passwords. Defenders should implement application consent restrictions, monitor for unusual sign-in patterns, and disable unnecessary OAuth flows.

___________________________________


# **[Device Code Phishing Hits 340+ Microsoft 365 Orgs Across Five Countries ...](https://thehackernews.com/2026/03/device-code-phishing-hits-340-microsoft.html)**

**PIR: 1.j.3**

Source: ketch Published: 2026-08-28

A widespread device code phishing campaign has compromised over 340 Microsoft 365 organizations across five countries since February 2026. By abusing OAuth protocols, attackers achieve persistent token hijacking and seamless account takeover. The article provides actionable guidance for IT defenders, including tightening conditional access rules, auditing third-party app permissions, and deploying identity threat detection solutions.

___________________________________


# **[Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA](https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns)**

**PIR: 1.a**

Source: ketch Published: 2026-08-28

Threat actors increasingly leverage cloud-native services to host phishing infrastructure, evading traditional blocklists and detection mechanisms. This report details how attackers abuse serverless functions, object storage, and dynamic DNS to create resilient, ephemeral phishing campaigns. Defenders must shift from static URL filtering to behavioral analysis and cloud workload protection to mitigate these evolving tactics.

___________________________________


# **[Device Code Phishing Drives Identity Takeover Risks](https://gurucul.com/latest-threats/device-code-phishing-is-an-evolution-in-identity-takeover/)**

**PIR: 1.j.3**

Source: ketch Published: 2026-08-28

Corporate security leaders face escalating identity attacks that circumvent traditional multi-factor authentication. This analysis examines a device code phishing campaign that manipulates corporate validation workflows to seize high-value employee accounts. The report emphasizes the need for zero-trust identity architectures, real-time threat intelligence integration, and proactive user awareness programs to counter these sophisticated tactics.

___________________________________


# **[CVE-2026-59354](https://nvd.nist.gov/vuln/detail/CVE-2026-59354)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-27

In versions of Spring Security's OAuth2 Authorization Server module 7.0.0 through 7.0.4, when Dynamic Client Registration is explicitly enabled, the registration endpoint performs insufficient validation of certain client metadata fields supplied by the registering client. An attacker who possesses a valid Initial Access Token can register a malicious client with crafted metadata, which, depending on server configuration and how the metadata is later rendered or used, may result in Stored Cross-

___________________________________


# **[CVE-2026-81826](https://nvd.nist.gov/vuln/detail/CVE-2026-81826)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-27

Affected versions of Flowintel do not revoke existing authenticated sessions when a user’s password is changed.


This means that if an attacker already possesses a valid session—for example, from prior access or a stolen session token—the victim changing their password does not terminate that attacker’s access. The session remains usable until it expires naturally. The upstream commit describes this directly as:


“session keeps working until it expires.”

The fix detects password changes and e

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-18918 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-18918)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-28

Critical OAuth authorization bypass in Eclipse Lyo directly undermines trusted client validation and access control in Digital Identity and IdAM systems.

*Deep dive: `TIER_2_CVE-2026-18918.md`*

___________________________________


# **[CVE-2026-82262 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-82262)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-28

SSRF in Logto IdAM platform enables internal network recon and cloud metadata exfiltration via tenant admin APIs, directly impacting digital identity infrastructure.

*Deep dive: `TIER_2_CVE-2026-82262.md`*

___________________________________


# **[CVE-2026-27852 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-27852)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-28

Foundational enterprise email backend widely deployed across Government, Finance, and Healthcare; targeted IMAP DoS disrupts critical communication continuity.

*Deep dive: `TIER_2_CVE-2026-27852.md`*

___________________________________


# **[CVE-2026-42007 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-42007)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-28

Foundational email infrastructure vulnerability enabling RCE and data exfiltration across government, finance, healthcare, and identity systems.

*Deep dive: `TIER_2_CVE-2026-42007.md`*

___________________________________


# **[CVE-2026-55552 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-55552)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-28

Unauthenticated path traversal in Yamcs mission control framework impacts government space agencies and national security infrastructure.

*Deep dive: `TIER_2_CVE-2026-55552.md`*

___________________________________


# **[CVE-2026-55559 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-55559)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-28

TIER 2 RCE in Yamcs mission control framework directly impacts the Government sector by compromising critical national space agency telemetry and satellite command infrastructure.

*Deep dive: `TIER_2_CVE-2026-55559.md`*

___________________________________


# **[CVE-2026-38820 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-38820)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-28

Unauthenticated RCE in openNDS captive portals impacts municipal public Wi-Fi and government/healthcare guest networks, compromising foundational public access infrastructure.

*Deep dive: `TIER_2_CVE-2026-38820.md`*

___________________________________


# **[CVE-2026-38821 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-38821)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-28

Unauthenticated RCE in openNDS captive portal daemon impacts municipal Wi-Fi and public venue networks, threatening foundational public connectivity infrastructure.

*Deep dive: `TIER_2_CVE-2026-38821.md`*

___________________________________


# **[CVE-2026-38822 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-38822)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-28

TIER 2 RCE in openNDS captive portal daemon impacts municipal Wi-Fi and public sector guest networks, posing pivoting and traffic interception risks to civic connectivity infrastructure.

*Deep dive: `TIER_2_CVE-2026-38822.md`*

___________________________________


# **[CVE-2026-42391 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-42391)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-28

Unauthenticated DoS on foundational enterprise IMAP/email infrastructure that underpins operational communications across public and private sectors.

*Deep dive: `TIER_2_CVE-2026-42391.md`*

___________________________________


# **[CVE-2026-55848 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-55848)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-28

Unauthenticated XXE in MapFish Print, a GIS component widely deployed in public-sector mapping and civic spatial services, enables credential theft and SSRF.

*Deep dive: `TIER_2_CVE-2026-55848.md`*

___________________________________


# **[CVE-2026-82078 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-82078)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-28

Actively exploited RCE in enterprise print management software explicitly impacts government and higher education deployments due to potential internet exposure of user portals.

*Deep dive: `TIER_2_CVE-2026-82078.md`*

___________________________________


# **[CVE-2026-82244 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-82244)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-28

Critical RCE in a low-code platform explicitly tied to public-sector and enterprise infrastructure, risking full host compromise and credential theft.

*Deep dive: `TIER_2_CVE-2026-82244.md`*

___________________________________


# **[CVE-2026-82266 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-82266)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-28

Critical default-auth bypass in Redpanda data streaming platform, a foundational backend component for regulated sector data pipelines (finance, healthcare, government).

*Deep dive: `TIER_2_CVE-2026-82266.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine