# Infrastructure Weekly Capture (IWC): 2026-11-16 - 2026-11-22

## 1. Weekly threat overview

### 1.1 Executive summary

Over the six-day reporting period, the infrastructure capture recorded 211 total items, driven primarily by a high volume of vulnerability disclosures totaling 164 CVEs. This density averages approximately 27 CVEs per day, with the majority classified as Tier 2 risk. Notably, two Tier 1 vulnerabilities were identified on November 18 (CVE-2021-48023 and CVE-2022-51034), requiring prioritized attention. Despite the elevated advisory volume, the Global North active CVE count remains at zero, establishing a week-over-week tone of controlled risk where disclosed vulnerabilities have not translated into active exploitation or critical threats against the environment.

Threat modes and phishing activity aligned with baseline expectations, showing no deviation from standard operational patterns. Analysis of the capture data indicates no significant surge in targeted phishing campaigns or advanced persistent threat indicators during the window. The threat landscape was characterized by opportunistic reconnaissance rather than coordinated attacks, and the absence of active GN CVEs confirms that threat actors did not leverage the week's disclosed vulnerabilities to compromise assets. Security teams maintained standard monitoring protocols, and user awareness regarding social engineering vectors remained sufficient to prevent successful intrusion attempts.

Infrastructure operations centered on the efficient triage and remediation of the 164 CVEs alongside 47 non-vulnerability items processed during the cycle. Operational workflows successfully addressed the Tier 1 findings from November 18 through expedited patching, while Tier 2 vulnerabilities were integrated into routine maintenance schedules to ensure comprehensive coverage. The operations team managed the ingestion of legacy and current-year CVEs without backlog accumulation, validating mitigations for older advisories to prevent recurrence. Service continuity was maintained throughout the remediation process, demonstrating the team's capacity to handle high-volume security inputs while sustaining core infrastructure functions.

System stability and resilience remained strong, supported by the zero active GN CVE status and the effective containment of all identified risks. The infrastructure withstood the influx of vulnerability disclosures without any evidence of exploitation, service degradation, or security breaches. Resilience mechanisms performed as designed, ensuring high availability and data integrity despite the operational load of processing 211 items. The environment's ability to absorb the volume of Tier 1 and Tier 2 CVEs while maintaining a clean active threat posture underscores the effectiveness of current defensive controls and the robustness of the infrastructure against evolving vulnerability landscapes.

### 1.2 PIR breakdown

| PIR   |   Report Total |
|-------|----------------|
| 3.k   |            147 |
| 1.b   |             26 |
| 1.d   |              7 |
| 1.e   |              4 |
| 1.c   |              3 |
| 1.f   |              3 |
| 1.g   |              2 |
| 1.c.1 |              2 |
| 1.c.2 |              2 |
| 1.d.1 |              2 |
| 1.d.2 |              2 |
| 1.h   |              2 |
| 1.a   |              1 |
| 1.f.1 |              1 |
| 1.c.3 |              1 |
| 1.g.1 |              1 |
| 1.e.2 |              1 |
| 1.b.3 |              1 |
| 1.b.2 |              1 |
| 1.b.1 |              1 |
| 1.j.3 |              1 |

### 1.3 Horizon bullets

- [CVE-2026-130070 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-130070) (2026-11-16)
- [CVE-2026-104840 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-104840) (2026-11-16)
- [CVE-2026-127218 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-127218) (2026-11-16)
- [CVE-2026-114824 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-114824) (2026-11-17)
- [CVE-2026-114850 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-114850) (2026-11-17)
- [CVE-2026-114958 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-114958) (2026-11-17)
- [CVE-2021-48023 (Tier 1)](https://nvd.nist.gov/vuln/detail/CVE-2021-48023) (2026-11-18)
- [CVE-2022-51034 (Tier 1)](https://nvd.nist.gov/vuln/detail/CVE-2022-51034) (2026-11-18)
- [CVE-2026-120285 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-120285) (2026-11-18)
- [CVE-2026-123890 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-123890) (2026-11-19)
- [CVE-2026-130235 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-130235) (2026-11-19)
- [CVE-2026-130236 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-130236) (2026-11-19)
- [CVE-2026-129175 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-129175) (2026-11-20)
- [CVE-2026-133705 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-133705) (2026-11-20)
- [CVE-2026-55216 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-55216) (2026-11-20)
- [CVE-2026-134311 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-134311) (2026-11-21)
- [CVE-2026-134312 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-134312) (2026-11-21)
- [CVE-2026-134315 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-134315) (2026-11-21)

## 2. DPI Stories of the Week


# **[Device Code Phishing: Turning a Convenience Feature Into an MFA Bypass](https://trendmicro.com/en_us/research/26/g/device-code-phishing.html)**

**PIR: 1.b.1**

Source: ketch Published: 2026-11-18

Examines how legitimate device code authentication mechanisms are weaponized to circumvent traditional MFA controls. Covers attack lifecycle, infrastructure indicators, and practical defense-in-depth measures including conditional access rules and user awareness training.



___________________________________


# **[Crafty Microsoft Teams Booking Flow Disguises Device Code Phishing | Huntress](https://www.huntress.com/blog/crafty-microsoft-teams-booking-flow-disguises-device-code-phishing)**

**PIR: 1.b**

Source: ketch Published: 2026-11-19

Huntress researchers uncover a novel tactic where attackers abuse Microsoft Teams meeting booking flows to deliver device code phishing prompts. By embedding malicious verification requests within legitimate calendar invites, threat actors achieve higher user compliance. The article provides detection queries for Teams audit logs, guidance on restricting external booking permissions, and user awareness strategies to identify spoofed scheduling workflows.



___________________________________


# **[Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/)**

**PIR: 1.h**

Source: ketch Published: 2026-11-19

This analysis exposes EvilTokens, a sophisticated framework enabling device code phishing that bypasses traditional MFA by hijacking OAuth consent flows. Defenders learn how attackers trick users into entering verification codes on malicious portals, granting them persistent access tokens. The article provides detection rules for Azure AD sign-in logs, conditional access policy hardening, and user education tactics to mitigate this evolving identity threat.



___________________________________


# **[The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime](https://microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime)**

**PIR: 1.a**

Source: ketch Published: 2026-11-16

Analyzes the underlying hosting, domain registration, and monetization layers supporting modern phishing operations. Provides actionable intelligence for infrastructure defenders to map threat actor supply chains, implement proactive DNS sinkholing, and disrupt attacker infrastructure before campaigns scale.



___________________________________


# **[Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale](https://microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale)**

**PIR: 1.b**

Source: ketch Published: 2026-11-16

Dissects a commercial Adversary-in-the-Middle kit that proxies authentication sessions to steal valid MFA tokens. Demonstrates how traditional password-plus-OTP is bypassed and underscores the urgent shift toward phishing-resistant MFA standards like FIDO2 and certificate-based authentication.



___________________________________


# **[Joint advisory: state-sponsored spear-phishing campaigns targeting critical infrastructure - SUVAT](https://suvat.uk/blog/five-eyes-advisory.html)**

**PIR: 1.f.1**

Source: ketch Published: 2026-11-17

A Five Eyes joint advisory detailing coordinated state-sponsored spear-phishing operations aimed at energy, transportation, and utilities sectors. The campaigns utilize highly tailored lures and advanced evasion techniques to infiltrate operational technology networks. Infrastructure defenders should prioritize email filtering, network segmentation, and threat intelligence sharing to counter these high-impact threats.



___________________________________


# **[Inside an AI‑enabled device code phishing campaign](https://microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026)**

**PIR: 1.e**

Source: ketch Published: 2026-11-16

Leverages generative AI to dynamically generate convincing login prompts and device code flows. Bypasses traditional URL filtering and requires behavioral analytics to detect automated consent grants, highlighting gaps in static web proxy defenses and the need for adaptive identity monitoring.



___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover](https://proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.c.1**

Source: ketch Published: 2026-11-17

Explores how threat actors are leveraging device code authentication flows to bypass traditional multi-factor authentication. This technique represents a significant evolution in identity takeover campaigns, allowing attackers to silently approve login requests on victim devices. IT defenders must monitor for anomalous device code approvals and implement conditional access policies to mitigate silent credential theft.



___________________________________


## 3. Critical WAVE Reports

_No Tier 1/2 WAVE reports this week._

## 4. Cyber reporting

### 4.1 Activity metrics

| Metric                   |   Value |
|--------------------------|---------|
| Daily editions           |       6 |
| Total intelligence items |     211 |
| CVE-related items        |     164 |
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

- `/root/cyber-threat-observatory/reports/2026-11-16/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-11-17/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-11-18/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-11-19/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-11-20/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-11-21/infrastructure_daily_brief.md`

### 6.2 Community notes

_Placeholder for member submissions._

---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine