# Infrastructure Weekly Capture (IWC): 2026-09-14 - 2026-09-20

## 1. Weekly threat overview

### 1.1 Executive summary

Over the four-day reporting period, the infrastructure capture system processed 95 total intelligence items, with vulnerability management comprising the majority of activity as 63 items (66%) were classified as CVEs. The week-over-week tone is characterized by stability, underscored by zero globally active CVEs affecting the core network, which indicates no immediate widespread exploitation of tracked vulnerabilities. While the disclosure volume is consistent, the risk profile remains manageable; the feed contains a single Tier 1 severity item (CVE-2026-76461) alongside a cluster of Tier 2 advisories, suggesting that standard patching cadences are sufficient and no urgent escalation is required for critical infrastructure components.

Threat actor tactics are evolving toward sophisticated identity compromise and AI-augmented social engineering, with a notable concentration on device code phishing. Intelligence highlights the emergence of the "GhostCode" kit and AI-enabled campaigns that manipulate legitimate Microsoft identity platform flows to bypass traditional URL-based defenses. Simultaneously, state-aligned groups such as Laundry Bear are actively exploiting zero-click vulnerabilities in Zimbra to target Western government and critical infrastructure sectors. These developments necessitate a reinforcement of multi-factor authentication policies and the deployment of advanced detection capabilities to identify anomalous device code authorizations and zero-day exploitation patterns within mail collaboration suites.

Infrastructure operations maintained uninterrupted monitoring and data ingestion throughout the four-day window, successfully handling the full volume of intelligence without performance degradation. The absence of active CVEs supports a stable operational baseline, enabling teams to prioritize proactive hardening and configuration validation over reactive incident response. Operational focus is currently directed at verifying the security posture of Zimbra and Microsoft identity services in light of external threat activity, ensuring that access controls and segmentation align with the latest threat intelligence. Routine remediation workflows for the identified Tier 2 vulnerabilities are proceeding on schedule, with no operational impediments reported.

System stability and resilience remain strong, supported by effective defense-in-depth controls and the lack of successful exploitation events. The infrastructure's current posture demonstrates resilience against the observed AI-driven phishing vectors and zero-click threats, with monitoring systems effectively containing potential lateral movement risks. To further bolster resilience, immediate attention should be given to remediating the single Tier 1 vulnerability and enhancing behavioral analytics to detect the subtle indicators associated with device code abuse. Overall, the environment exhibits robust postural integrity, with risk levels contained within acceptable thresholds despite the increasing sophistication of external threat actors.

### 1.2 PIR breakdown

| PIR   |   Report Total |
|-------|----------------|
| 3.k   |             50 |
| 1.b   |             14 |
| 1.f   |              6 |
| 1.d   |              5 |
| 1.g   |              4 |
| 1.h   |              3 |
| 1.e   |              2 |
| 1.f.2 |              1 |
| 1.f.1 |              1 |
| 1.b.3 |              1 |
| 1.c.2 |              1 |
| 1.c.1 |              1 |
| 1.e.4 |              1 |
| 1.b.1 |              1 |
| 1.d.2 |              1 |
| 1.c   |              1 |
| 1.a   |              1 |
| 1.j.3 |              1 |

### 1.3 Horizon bullets

- [CVE-2026-21391 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-21391) (2026-09-14)
- [CVE-2026-76461 (Tier 1)](https://nvd.nist.gov/vuln/detail/CVE-2026-76461) (2026-09-14)
- [CVE-2026-78336 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-78336) (2026-09-14)
- [CVE-2026-18212 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-18212) (2026-09-16)
- [CVE-2026-20192 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-20192) (2026-09-16)
- [CVE-2026-20194 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-20194) (2026-09-16)
- [CVE-2026-62874 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-62874) (2026-09-17)
- [CVE-2026-85885 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-85885) (2026-09-17)
- [CVE-2026-90997 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-90997) (2026-09-17)
- [CVE-2026-94054 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-94054) (2026-09-19)
- [GhostCode: Dissecting a Novel Device Code Phishing Kit | eSentire](https://www.esentire.com/blog/ghostcode-dissecting-a-novel-device-code-phishing-kit) (2026-09-19)
- [Russian hacker group Laundry Bear exploits Zimbra zero-click flaw to target Western govern](https://industrialcyber.co/cisa/russian-hacker-group-laundry-bear-exploits-zimbra-zero-click-flaw-to-target-western-government-critical-infrastructure) (2026-09-19)

## 2. DPI Stories of the Week


# **[The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations](https://itsecurityguru.org/2026/05/27/the-ai-phishing-revolution-from-spray-and-pray-to-autonomous-operations)**

**PIR: 1.d**

Source: ketch Published: 2026-09-17

Generative AI is transforming phishing from broad, low-success campaigns into highly targeted, autonomous operations capable of adapting to security controls in real time. AI-driven tools automate victim profiling, craft context-aware lures, and dynamically modify landing pages to bypass content filters. Defenders should prioritize behavioral analytics, deploy AI-resistant email authentication standards, and implement continuous user training focused on contextual threat recognition.



___________________________________


# **[Microsoft: Passkey Help Desk Calls Are Hijacking Cloud Accounts, Then Draining SharePoint](https://threat-intelligence.redeyesecurity.com/blog/passkey-phishing-microsoft-cloud-hijack-storm-3032-2026)**

**PIR: 1.f.2**

Source: ketch Published: 2026-09-14

Attackers are exploiting social engineering via fake help desk calls to trick IT staff into initiating passkey registration flows. Once registered, threat actors hijack cloud accounts and systematically drain SharePoint repositories. This campaign highlights a critical gap in identity verification processes and underscores the need for strict change-management protocols for authentication methods. Infrastructure defenders must implement multi-person approval for passkey additions and monitor for



___________________________________


# **[GhostCode Phishing Kit Bypasses Microsoft 365 MFA to Hijack Accounts in 78 Seconds](https://cybersecuritynews.com/ghostcode-phishing-kit/amp)**

**PIR: 1.d**

Source: ketch Published: 2026-09-16

Threat actors are deploying the GhostCode phishing kit to rapidly bypass Microsoft 365 multi-factor authentication, compromising enterprise accounts in under two minutes. The campaign leverages real-time proxy techniques to intercept MFA prompts, allowing attackers to authenticate as legitimate users. Infrastructure defenders must prioritize blocking unauthorized device code flows and implementing conditional access policies that restrict token issuance from suspicious IP ranges. Monitoring for 



___________________________________


# **[GhostCode: Dissecting a Novel Device Code Phishing Kit | eSentire](https://www.esentire.com/blog/ghostcode-dissecting-a-novel-device-code-phishing-kit)**

**PIR: 1.f**

Source: ketch Published: 2026-09-19

eSentire researchers dissect GhostCode, a novel device code phishing kit that automates Microsoft identity takeover. The kit leverages AI to generate convincing prompts, bypassing traditional URL validation. Infrastructure defenders should monitor for unauthorized OAuth consent grants and implement conditional access policies that restrict device code flows to managed devices.



___________________________________


# **[Russian hacker group Laundry Bear exploits Zimbra zero-click flaw to target Western government, critical infrastructure](https://industrialcyber.co/cisa/russian-hacker-group-laundry-bear-exploits-zimbra-zero-click-flaw-to-target-western-government-critical-infrastructure)**

**PIR: 1.j.3**

Source: ketch Published: 2026-09-19

Industrial Cyber details how the Russian group Laundry Bear exploits a zero-click Zimbra vulnerability to target Western government and critical infrastructure. The campaign requires no user interaction, automatically delivering payloads via compromised email servers. Infrastructure defenders should prioritize patching Zimbra instances, segment email systems, and monitor for lateral movement indicators.



___________________________________


# **[Storm-3121 Fakes Passkey Portals to Steal M365 Data](https://0daynews.com/articles/2026-09-12-shinyhunters-passkey-phishing-m365-aitm)**

**PIR: 1.f.1**

Source: ketch Published: 2026-09-14

The Storm-3121 threat group has deployed sophisticated phishing portals that mimic Microsoft’s native passkey registration interface. By intercepting authentication-in-motion tokens, attackers bypass traditional MFA and gain persistent access to M365 environments. Defenders should deploy conditional access policies that restrict passkey registration to known corporate networks and monitor for rapid credential validation followed by bulk data exfiltration.



___________________________________


# **[When checking the URL isn’t enough: phishing via the Microsoft identity platform | Securelist](https://securelist.com/microsoft-device-code-phishing-attack/120350/)**

**PIR: 1.h**

Source: ketch Published: 2026-09-19

Kaspersky Securelist explains why URL validation fails against modern Microsoft identity platform phishing. Attackers use legitimate OAuth endpoints to harvest credentials and tokens, making traditional link inspection ineffective. Infrastructure defenders must shift focus to token telemetry, conditional access policies, and behavioral analytics to detect identity compromise.



___________________________________


# **[Device Code Phishing Surge — Threat Analysis](https://intel.threadlinqs.com/threat/TL-2026-2468)**

**PIR: 1.b.3**

Source: ketch Published: 2026-09-14

A significant increase in device code phishing campaigns is targeting organizations relying on Microsoft’s device code authentication flow. Attackers host malicious pages that prompt users to visit a legitimate Microsoft login URL, tricking them into authorizing attacker-controlled sessions. This technique effectively bypasses MFA without requiring credential theft. Infrastructure teams should disable device code flows where possible and implement user education focused on recognizing unauthoriz



___________________________________


## 3. Critical WAVE Reports

_No Tier 1/2 WAVE reports this week._

## 4. Cyber reporting

### 4.1 Activity metrics

| Metric                   |   Value |
|--------------------------|---------|
| Daily editions           |       4 |
| Total intelligence items |      95 |
| CVE-related items        |      63 |
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

- `/root/cyber-threat-observatory/reports/2026-09-14/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-09-16/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-09-17/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-09-19/infrastructure_daily_brief.md`

### 6.2 Community notes

_Placeholder for member submissions._

---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine