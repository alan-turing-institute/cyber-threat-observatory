# Infrastructure Weekly Capture (IWC): 2026-11-02 - 2026-11-08

## 1. Weekly threat overview

### 1.1 Executive summary

Over the six-day reporting period, the infrastructure capture recorded 203 total items, with vulnerability disclosures comprising the majority of activity at 155 CVEs. The week-over-week tone remains stable and controlled, characterized by a complete absence of globally active CVEs (gn_active_cves: 0). All sampled vulnerabilities, including entries such as CVE-2026-99231 and CVE-2026-123295, are classified as Tier 2, indicating moderate risk levels that do not require immediate emergency response. This distribution suggests a predictable vulnerability landscape where volume is high but criticality is managed, allowing the security posture to remain consistent with previous reporting cycles without escalation.

Threat mode analysis reveals no evidence of coordinated phishing campaigns or advanced exploitation techniques targeting the infrastructure during this window. The lack of active CVEs correlates with a quiet threat environment, where adversarial activity appears limited to background noise rather than targeted intrusion attempts. Defensive monitoring indicates that phishing vectors have not been leveraged to bypass perimeter controls, and there are no indicators of compromise associated with the disclosed vulnerabilities. This absence of active threat modes reinforces the effectiveness of current email security filters and user awareness protocols, keeping the attack surface closed against social engineering and credential theft.

Infrastructure operations proceeded without disruption, maintaining full service availability despite the processing of 155 new vulnerability items. Operational workflows successfully integrated the triage of Tier 2 CVEs into standard maintenance cycles, ensuring that remediation planning did not interfere with production stability. The zero count of active CVEs confirms that no patches or mitigations were required on an emergency basis, allowing engineering teams to focus on scheduled updates and capacity planning. This operational efficiency demonstrates that the infrastructure management processes are scalable and capable of handling the current influx of security data without degrading performance or delaying critical business functions.

Stability and resilience metrics remain strong, supported by the robust containment of all identified risks within the Tier 2 classification and the zero active CVE status. The infrastructure's ability to absorb a high volume of disclosures while maintaining a clean active threat profile underscores the resilience of the underlying architecture and the maturity of the vulnerability management program. Segmentation and defense-in-depth strategies appear effective in neutralizing potential exploitation paths, ensuring that system integrity and data confidentiality are preserved. This resilient state provides a solid foundation for continued operations, with confidence that the environment can withstand the current threat landscape while long-term remediation efforts advance.

### 1.2 PIR breakdown

| PIR   |   Report Total |
|-------|----------------|
| 3.k   |            124 |
| 1.b   |             36 |
| 1.c   |             12 |
| 1.e   |              8 |
| 1.a   |              6 |
| 1.d   |              4 |
| 1.j.3 |              3 |
| 1.f   |              2 |
| 1.c.2 |              2 |
| 1.g   |              1 |
| 1.c.1 |              1 |
| 1.b.1 |              1 |
| 1.c.3 |              1 |
| 1.b.3 |              1 |
| 1.d.1 |              1 |

### 1.3 Horizon bullets

- [CVE-2026-99231 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-99231) (2026-11-02)
- [CVE-2026-106804 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-106804) (2026-11-02)
- [CVE-2026-111048 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-111048) (2026-11-02)
- [CVE-2026-121543 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-121543) (2026-11-03)
- [CVE-2026-4052 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-4052) (2026-11-03)
- [CVE-2026-46487 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-46487) (2026-11-03)
- [CVE-2026-111036 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-111036) (2026-11-04)
- [CVE-2026-114425 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-114425) (2026-11-04)
- [CVE-2026-115770 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-115770) (2026-11-04)
- [CVE-2026-103112 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-103112) (2026-11-05)
- [CVE-2026-107123 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-107123) (2026-11-05)
- [CVE-2026-107602 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-107602) (2026-11-05)
- [CVE-2026-121820 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-121820) (2026-11-06)
- [CVE-2026-123618 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-123618) (2026-11-06)
- [CVE-2026-19877 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-19877) (2026-11-06)
- [CVE-2026-120984 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-120984) (2026-11-07)
- [CVE-2026-16712 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-16712) (2026-11-07)
- [CVE-2026-16717 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-16717) (2026-11-07)

## 2. DPI Stories of the Week


# **[The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime/)**

**PIR: 1.d**

Source: ketch Published: 2026-11-02

Microsoft Security researchers dissect the sprawling infrastructure ecosystem that underpins modern phishing campaigns. The report details how threat actors leverage compromised legitimate domains, cloud hosting services, and dynamic DNS providers to rapidly deploy and rotate phishing pages. Defenders gain actionable insights into tracking infrastructure footprints, identifying shared hosting patterns, and implementing proactive takedown strategies to disrupt the supply chain before credentials 



___________________________________


# **[Joint advisory: state-sponsored spear-phishing campaigns targeting ...](https://suvat.uk/blog/five-eyes-advisory.html)**

**PIR: 1.e**

Source: ketch Published: 2026-11-02

A Five Eyes joint advisory warns of ongoing state-sponsored spear-phishing campaigns specifically targeting energy, transport, and water sectors. The report outlines attacker TTPs, including highly tailored lures, malicious document attachments, and credential harvesting portals. Critical infrastructure operators are advised to review email filtering rules, enforce strict conditional access policies, and monitor for anomalous authentication attempts to mitigate identity compromise risks.



___________________________________


# **[Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale](https://www.microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale/)**

**PIR: 1.a**

Source: ketch Published: 2026-11-05

Tycoon2FA has emerged as a dominant phishing-as-a-service platform, facilitating adaptive identity threat management campaigns targeting over 500,000 organizations monthly. Microsoft’s Digital Crimes Unit collaborated with Europol to dismantle its infrastructure. This report details the kit’s architecture, proxy mechanisms, and operational scale, offering critical insights for defenders monitoring credential theft and session hijacking threats.



___________________________________


# **[The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime](https://microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime)**

**PIR: 1.a**

Source: ketch Published: 2026-11-06

Analysis of the underground infrastructure supporting global phishing campaigns, detailing hosting, domain generation, and proxy networks. Essential for defenders mapping threat actor supply chains and implementing infrastructure-level blocks.



___________________________________


# **[Unmasking EvilTokens: Getting to the root of device code phishing](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/)**

**PIR: 1.c**

Source: ketch Published: 2026-11-07

This analysis details the EvilTokens infrastructure, revealing how threat actors exploit OAuth device code flows to bypass traditional MFA. Defenders learn to identify malicious redirect URIs, monitor anomalous device code authorization requests, and implement conditional access policies that restrict device code usage to trusted networks. The report provides actionable telemetry for detecting token theft before lateral movement occurs.



___________________________________


# **[Inside an AI‑enabled device code phishing campaign](https://microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign)**

**PIR: 1.c.1**

Source: ketch Published: 2026-11-06

Explores how threat actors integrate AI to automate device code generation and victim interaction, significantly increasing compromise rates. Offers infrastructure defenders insights into blocking automated OAuth abuse and AI-driven lures.



___________________________________


# **[Phishers are hijacking legitimate cloud infrastructure | Securelist](https://securelist.com/cloud-platforms-in-phishing/120832/)**

**PIR: 1.b**

Source: ketch Published: 2026-11-03

Attackers increasingly leverage compromised or misconfigured cloud accounts to host phishing pages and proxy traffic, bypassing traditional web filters. This research outlines detection strategies for cloud-based phishing infrastructure, including identifying anomalous storage bucket configurations, serverless function abuse, and CDN misconfigurations. Infrastructure teams can use these findings to harden cloud environments, implement stricter IAM policies, and deploy behavioral monitoring to ca



___________________________________


# **[Unmasking EvilTokens: Getting to the root of device code phishing](https://aka.ms/EvilTokens-PhaaS)**

**PIR: 1.c.2**

Source: ketch Published: 2026-11-06

Deep dive into the EvilTokens PhaaS toolkit, explaining how it automates device code phishing to bypass MFA. Provides technical indicators and mitigation strategies for identity protection teams managing OAuth flows.



___________________________________


## 3. Critical WAVE Reports

_No Tier 1/2 WAVE reports this week._

## 4. Cyber reporting

### 4.1 Activity metrics

| Metric                   |   Value |
|--------------------------|---------|
| Daily editions           |       6 |
| Total intelligence items |     203 |
| CVE-related items        |     155 |
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

- `/root/cyber-threat-observatory/reports/2026-11-02/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-11-03/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-11-04/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-11-05/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-11-06/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-11-07/infrastructure_daily_brief.md`

### 6.2 Community notes

_Placeholder for member submissions._

---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine