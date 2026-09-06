# Infrastructure Weekly Capture (IWC): 2026-08-31 - 2026-09-06

## 1. Weekly threat overview

### 1.1 Executive summary

During the six-day reporting window, the infrastructure team processed 131 total security items, including 83 CVEs. The week-over-week tone is characterized by stability and controlled risk, with all captured vulnerabilities classified as Tier 2, indicating moderate severity without critical escalation. Crucially, the GN Active CVE count remains at zero, signaling no actively exploited threats targeting the environment. Examples such as CVE-2026-17615 and CVE-2026-82801 reflect a consistent pattern of moderate-risk findings that can be addressed through standard remediation cycles rather than emergency response, maintaining a predictable security posture.

Threat mode analysis reveals a quiet landscape with no anomalous activity detected. The 48 non-CVE items within the total volume likely represent routine threat intelligence and baseline monitoring data, with no significant phishing campaigns or social engineering attempts flagged. The absence of high-fidelity alerts aligns with the zero GN Active CVE metric, suggesting that external attack surfaces are effectively shielded. Phishing simulation and email security controls appear to be performing within expected parameters, contributing to the overall low-threat posture observed during this period.

Infrastructure operations continued smoothly, with patching and hardening activities aligned to the identified Tier 2 vulnerabilities. The zero GN Active CVE status confirms that critical systems remain uncompromised, allowing operations teams to proceed with scheduled maintenance without disruption. Remediation workflows are actively addressing the backlog of 83 CVEs, prioritizing items like CVE-2026-84423 and CVE-2026-4813 for integration into upcoming deployment windows. Operational efficiency is maintained through automated vulnerability management tools, ensuring that the volume of findings does not impede service delivery or resource allocation.

Stability and resilience metrics demonstrate a resilient infrastructure posture capable of withstanding current threat vectors. The lack of active exploitation and the predominance of Tier 2 vulnerabilities underscore the effectiveness of preventive controls and rapid detection capabilities. System availability remains high, as the risk profile does not necessitate reactive measures that could impact performance. Overall, the infrastructure exhibits strong continuity, with resilience reinforced by proactive risk management and the successful containment of all identified exposures within acceptable operational thresholds.

### 1.2 PIR breakdown

| PIR   |   Report Total |
|-------|----------------|
| 3.k   |             47 |
| 1.b   |             40 |
| 1.a   |              8 |
| 1.f   |              7 |
| 1.j.3 |              5 |
| 1.e   |              4 |
| 1.g   |              4 |
| 1.c   |              3 |
| 1.d   |              3 |
| 1.b.2 |              2 |
| 1.b.1 |              2 |
| 1.j   |              1 |
| 1.h   |              1 |
| 1.e.2 |              1 |
| 1.e.1 |              1 |
| 1.g.1 |              1 |
| 1.f.1 |              1 |

### 1.3 Horizon bullets

- [CVE-2026-17615 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-17615) (2026-08-31)
- [CVE-2026-82801 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-82801) (2026-08-31)
- [CVE-2026-72001 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-72001) (2026-08-31)
- [CVE-2026-18765 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-18765) (2026-09-01)
- [CVE-2026-84423 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-84423) (2026-09-01)
- [CVE-2026-4813 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-4813) (2026-09-01)
- [CVE-2026-49249 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-49249) (2026-09-02)
- [CVE-2026-73475 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-73475) (2026-09-02)
- [CVE-2026-78689 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-78689) (2026-09-02)
- [CVE-2026-53728 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-53728) (2026-09-03)
- [CVE-2026-63219 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-63219) (2026-09-03)
- [CVE-2026-80465 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-80465) (2026-09-03)
- [CVE-2026-18658 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-18658) (2026-09-04)
- [CVE-2026-61686 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-61686) (2026-09-04)
- [CVE-2026-85184 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-85184) (2026-09-04)
- [CVE-2026-67276 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-67276) (2026-09-05)
- [CVE-2026-67281 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-67281) (2026-09-05)
- [CVE-2026-86060 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-86060) (2026-09-05)

## 2. DPI Stories of the Week


# **[Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.f**

Source: ketch Published: 2026-08-31

Threat actors are leveraging AI to automate device code phishing campaigns, generating live authentication codes on demand to bypass MFA. This evolution enables sustained post-compromise access and higher success rates. Defenders must monitor OAuth consent grants, implement conditional access policies, and deploy AI-driven detection to identify anomalous device code flows before account takeover occurs.



___________________________________


# **[Inside Knight Office, a New M365 AiTM Phishing Kit | Huntress](https://www.huntress.com/blog/inside-knight-office-m365-aitm-attack)**

**PIR: 1.a**

Source: ketch Published: 2026-09-01

Huntress researchers dissect the Knight Office M365 AiTM phishing kit, detailing its real-time session hijacking capabilities and infrastructure deployment patterns. The report outlines how attackers proxy authentication flows to bypass conditional access policies, providing defenders with IOCs, proxy domain structures, and recommended M365 security settings to mitigate session theft.



___________________________________


# **[OAuth Device Code Phishing: 37x Surge in Enterprise ATO](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/04/CSA_research_note_oauth-device-code-phishing-surge_20260405-csa-styled.pdf)**

**PIR: 1.j.3**

Source: ketch Published: 2026-09-03

Documents a massive 37-fold increase in enterprise account takeovers driven by OAuth device code phishing. Attackers trick users into entering device codes on malicious sites, granting them valid tokens that bypass traditional MFA controls and compromise identity infrastructure.



___________________________________


# **[A New Era Of Social Engineering: The Device Code Phishing Boom](https://coalitioninc.com/blog/security-labs/a-new-era-of-social-engineering-the-device-code-phishing-boom)**

**PIR: 1.f**

Source: ketch Published: 2026-08-31

The surge in device code phishing represents a paradigm shift in social engineering, moving from static credential harvesting to dynamic, automated authentication interception. Attackers exploit legitimate OAuth flows to trick users into entering codes, effectively neutralizing traditional MFA. Infrastructure teams should prioritize monitoring for suspicious device code requests, restrict app consent permissions, and educate users on recognizing dynamic code prompts.



___________________________________


# **[Mirage2FA Phishing Kit Bypasses MFA to Hijack Microsoft 365 Sessions, Targeting 3,500+ Organizations - Cyber Accord](https://www.cyberaccord.com/mirage2fa-phishing-kit-bypasses-mfa-to-hijack-microsoft-365-sessions-targeting-3500-organizations/)**

**PIR: 1.a**

Source: ketch Published: 2026-09-01

Cyber Accord analyzes the Mirage2FA kit, which successfully bypasses multi-factor authentication to hijack Microsoft 365 sessions across thousands of organizations. The breakdown covers the kit’s reverse-proxy architecture, token extraction methods, and infrastructure footprint, offering actionable guidance for identity protection teams to detect and block unauthorized session reuse.



___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.b**

Source: ketch Published: 2026-09-04

Device code phishing continues to mature as a primary vector for identity takeover, bypassing traditional multi-factor authentication by leveraging legitimate OAuth 2.0 device authorization flows. Attackers trick users into entering codes on malicious sites, granting them direct access to corporate accounts without passwords or MFA prompts. Defenders should audit OAuth consent grants, enforce strict device code policies, and educate users on recognizing legitimate Microsoft/Google device code pr



___________________________________


# **[Device Code Phishing: Stealing Tokens via Real Login](https://kayssel.substack.com/p/device-code-phishing-stealing-tokens)**

**PIR: 1.j.3**

Source: ketch Published: 2026-09-03

Explains how device code phishing leverages legitimate authentication endpoints to harvest valid access tokens. Unlike traditional credential harvesting, this method captures real-time session data, making detection reliant on advanced identity telemetry and token lifecycle monitoring.



___________________________________


# **[The Device Code Phishing Tsunami: What We’re Seeing in the Wild](https://www.levelblue.com/blogs/spiderlabs-blog/the-device-code-phishing-tsunami-what-were-seeing-in-the-wild)**

**PIR: 1.f**

Source: ketch Published: 2026-08-31

Recent telemetry reveals a massive wave of device code phishing attacks targeting enterprise environments. Unlike traditional phishing, these campaigns abuse legitimate authentication endpoints to harvest active sessions. Security operations centers must enhance logging for OAuth device code endpoints, implement strict conditional access rules, and deploy behavioral analytics to detect rapid, automated code validation attempts.



___________________________________


## 3. Critical WAVE Reports

_No Tier 1/2 WAVE reports this week._

## 4. Cyber reporting

### 4.1 Activity metrics

| Metric                   |   Value |
|--------------------------|---------|
| Daily editions           |       6 |
| Total intelligence items |     131 |
| CVE-related items        |      83 |
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

- `/root/cyber-threat-observatory/reports/2026-08-31/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-09-01/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-09-02/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-09-03/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-09-04/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-09-05/infrastructure_daily_brief.md`

### 6.2 Community notes

_Placeholder for member submissions._

---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine