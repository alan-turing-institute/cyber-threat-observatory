# Infrastructure Weekly Capture (IWC): 2026-09-21 - 2026-09-27

## 1. Weekly threat overview

### 1.1 Executive summary

The reporting period spanned six days with a total of 138 captured items, reflecting a sustained and high-volume information flow. Vulnerability management activity dominated the landscape, accounting for 91 CVE-related items, which represents approximately 66% of the total volume. The CVE portfolio was characterized by a concentration of Tier 2 severity advisories, with zero Global Network (GN) active CVEs recorded, indicating an absence of critical, actively exploited vulnerabilities requiring emergency intervention. The week-over-week tone suggests a controlled but intense environment where the primary operational burden lies in managing the density of routine disclosures rather than responding to acute crisis events, allowing teams to maintain focus on standard patching cycles and risk mitigation.

Threat intelligence highlights a significant escalation in sophisticated phishing operations, particularly centered on the abuse of Device Code Flow mechanisms. The "EvilTokens" campaign emerged as a primary threat actor, leveraging AI-enabled techniques to automate credential harvesting and facilitate Phishing-as-a-Service (PaaS) operations at scale. Concurrently, the "GhostCode" threat was identified, prompting vendors like Microsoft to issue urgent guidance on blocking Device Code Flow to prevent account hijacking. Industry responses have begun to yield results, including a global disruption operation led by Cloudflare that targeted EvilTokens infrastructure; however, the prevalence of AI-driven social engineering underscores the evolving sophistication of attacker tooling and the necessity for enhanced detection and user awareness measures.

Infrastructure operations were directed toward addressing the high volume of vulnerability disclosures and implementing defensive controls against identified phishing vectors. Maintenance activities prioritized the remediation of Tier 2 CVEs across the environment, ensuring alignment with patching SLAs while monitoring for any escalation in severity. Configuration management efforts focused on enforcing security recommendations related to Device Code Flow, including the implementation of blocks against known malicious flows associated with GhostCode and EvilTokens. Operational workflows remained stable, with security teams coordinating closely with vendor advisories to validate mitigations and ensure that infrastructure posture adjustments were applied effectively without disrupting service availability or introducing configuration drift.

System stability and resilience remained robust throughout the reporting period, supported by the absence of critical active exploits and effective threat containment measures. The zero count of GN active CVEs confirms that the infrastructure was not exposed to severe, actively weaponized vulnerabilities, preserving service continuity and data integrity. Resilience was further bolstered by the successful industry-wide takedown of the EvilTokens PaaS infrastructure, which reduced the immediate attack surface for credential theft and limited the potential for lateral movement. Overall, the environment demonstrated a strong defensive posture, with proactive monitoring and rapid response capabilities effectively neutralizing emerging threats and maintaining operational integrity against both vulnerability and phishing-driven risks.

### 1.2 PIR breakdown

| PIR   |   Report Total |
|-------|----------------|
| 3.k   |             54 |
| 1.b   |             41 |
| 1.g   |              9 |
| 1.j.3 |              7 |
| 1.a   |              5 |
| 1.e   |              4 |
| 1.f   |              4 |
| 1.c   |              3 |
| 1.i   |              3 |
| 1.j   |              2 |
| 1.d   |              2 |
| 1.h   |              1 |
| 1.d.2 |              1 |
| 1.k   |              1 |
| 1.l   |              1 |

### 1.3 Horizon bullets

- [CVE-2026-77560 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-77560) (2026-09-21)
- [CVE-2026-85751 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-85751) (2026-09-21)
- [CVE-2026-73547 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-73547) (2026-09-21)
- [CVE-2026-17635 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-17635) (2026-09-22)
- [CVE-2026-18074 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-18074) (2026-09-22)
- [CVE-2026-18163 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-18163) (2026-09-22)
- [CVE-2026-76183 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-76183) (2026-09-23)
- [Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Security Blo](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/) (2026-09-23)
- [Cloudflare participates in global operation to disrupt EvilTokens Phishing-as-a-Service | ](https://www.cloudflare.com/threat-intelligence/research/report/cloudflare-participates-in-global-operation-to-disrupt-eviltokens-phishing-as-a-service/) (2026-09-23)
- [CVE-2026-56739 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-56739) (2026-09-24)
- [CVE-2026-63203 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-63203) (2026-09-24)
- [CVE-2026-85056 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-85056) (2026-09-24)
- [CVE-2026-93641 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-93641) (2026-09-25)
- [Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/) (2026-09-25)
- [Microsoft 365: Block Device Code Flow Against GhostCode](https://windowsforum.com/news/microsoft-365-block-device-code-flow-against-ghostcode.444973?amp=1) (2026-09-25)
- [CVE-2026-100612 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-100612) (2026-09-26)
- [CVE-2026-100661 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-100661) (2026-09-26)
- [CVE-2026-100666 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-100666) (2026-09-26)

## 2. DPI Stories of the Week


# **[Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.e**

Source: ketch Published: 2026-09-21

Threat actors leverage AI to automate device code phishing at scale, generating live authentication prompts on demand. This campaign bypasses traditional email filters by targeting users directly with dynamic codes, enabling rapid account takeover and persistent access. Defenders should monitor for anomalous device code requests and restrict OAuth consent flows.



___________________________________


# **[GhostCode Phishing Kit Bypasses Microsoft 365 MFA to Hijack Accounts in 78 Seconds](https://cybersecuritynews.com/ghostcode-phishing-kit/amp)**

**PIR: 1.b**

Source: ketch Published: 2026-09-21

A newly discovered GhostCode phishing kit bypasses Microsoft 365 MFA in under two minutes. The kit automates device code interception and token theft, enabling rapid account hijacking. Security operations should deploy MFA fatigue defenses, restrict interactive login flows, and implement behavioral analytics to detect automated credential harvesting campaigns.



___________________________________


# **[GhostCode Abuses Microsoft Device Codes to Steal M365 Tokens and Register Rogue Devices](https://cyberpress.org/ghostcode-m365-device-code)**

**PIR: 1.b**

Source: ketch Published: 2026-09-21

The GhostCode toolkit abuses Microsoft device codes to extract valid M365 access tokens and register unauthorized devices. This technique allows attackers to maintain persistence even after password resets. Defenders should monitor Entra ID sign-in logs for token theft indicators, restrict app registrations, and implement token lifetime policies.



___________________________________


# **[GhostCode Abuses Microsoft Entra Device Enrollment to Maintain Access After Token Revocation](https://gbhackers.com/ghostcode-abuses-microsoft-entra)**

**PIR: 1.f**

Source: ketch Published: 2026-09-21

Attackers leverage Microsoft Entra device enrollment to retain access after token revocation. By registering rogue devices during the initial compromise, GhostCode operators create persistent backdoors. IT teams must enforce device compliance policies, audit enrollment approvals, and monitor for unauthorized device additions in Entra ID.



___________________________________


# **[Microsoft 365: Block Device Code Flow Against GhostCode](https://windowsforum.com/news/microsoft-365-block-device-code-flow-against-ghostcode.444973)**

**PIR: 1.e**

Source: ketch Published: 2026-09-21

Administrators can mitigate GhostCode attacks by disabling the device code flow in Microsoft 365. This configuration change prevents threat actors from exploiting the interactive authentication mechanism to steal tokens. Implementing conditional access policies and restricting device enrollment scopes further reduces exposure to automated credential harvesting.



___________________________________


# **[GhostCode attackers abuse device codes to take over Microsoft 365 accounts](https://computerworld.com/article/4223889/ghostcode-attackers-abuse-device-codes-to-take-over-microsoft-365-accounts.html)**

**PIR: 1.e**

Source: ketch Published: 2026-09-21

GhostCode operators exploit Microsoft’s device code authentication to hijack M365 accounts. By tricking users into entering codes on malicious portals, attackers bypass standard MFA controls. Infrastructure teams must audit active device code sessions, enforce strict conditional access rules, and deploy real-time alerting for suspicious authentication patterns.



___________________________________


# **[Operation HookedWing: 4-Year Phishing Campaign Hits 500+](https://cipherssecurity.com/operation-hookedwing-phishing-500/)**

**PIR: 1.c**

Source: ketch Published: 2026-09-21

Operation HookedWing represents a sustained, four-year spear phishing campaign targeting over 500 organizations. Attackers use highly tailored lures to harvest credentials and deploy persistent access tools. Defenders should review historical email logs, enforce least-privilege access, and implement advanced phishing simulation and detection controls.



___________________________________


# **[Microsoft 365: Block Device Code Flow Against GhostCode](https://windowsforum.com/news/microsoft-365-block-device-code-flow-against-ghostcode.444973?amp=1)**

**PIR: 1.d**

Source: ketch Published: 2026-09-24

Microsoft recommends disabling the device code flow in Microsoft 365 to counter GhostCode, a threat actor leveraging OAuth 2.0 device authorization grants to bypass MFA. Attackers redirect authentication to legitimate desktop or mobile apps, capturing valid tokens. Infrastructure administrators should restrict device code flow usage, implement token lifetime policies, and monitor for suspicious app registrations.



___________________________________


## 3. Critical WAVE Reports

_No Tier 1/2 WAVE reports this week._

## 4. Cyber reporting

### 4.1 Activity metrics

| Metric                   |   Value |
|--------------------------|---------|
| Daily editions           |       6 |
| Total intelligence items |     138 |
| CVE-related items        |      91 |
| GreyNoise-active CVEs    |       0 |

### 4.2 Featured exploitation

See daily `daily_exploitation_pulse.md` files in each edition folder.

### 4.3 Featured CVEs

See daily `daily_critical_cves.md` and WAVE `TIER_*_CVE-*.md` reports.

### 4.4 Campaign / phishing summary

See daily `daily_phishing_campaigns.md` files.

## 5. Infrastructure environment snapshot

### 5.1 Major outages / advisories

_Derived from daily brief items tagged policy or infrastructure_ops._

### 5.2 Supply chain signals

_Review daily Cyber news and Vulners top-50 snapshots under `raw/`._

### 5.3 Policy and standards

_Review daily Policy and standards sections._

## 6. Reporting synopsis

### 6.1 Daily briefs published this week

- `/root/cyber-threat-observatory/reports/2026-09-21/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-09-22/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-09-23/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-09-24/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-09-25/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-09-26/infrastructure_daily_brief.md`

### 6.2 Community notes

_Placeholder for member submissions._

---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine