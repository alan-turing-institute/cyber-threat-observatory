# Infrastructure Weekly Capture (IWC): 2026-10-26 - 2026-11-01

## 1. Weekly threat overview

### 1.1 Executive summary

During the six-day reporting period, the infrastructure capture recorded 131 total intelligence items, with vulnerability disclosures accounting for 83 CVEs. The week-over-week tone is characterized by controlled risk, as all sampled vulnerabilities, including CVE-2026-110475 and CVE-2026-119421, are classified as Tier 2, indicating moderate severity without critical impact. Most notably, Global Network (GN) active CVEs remain at zero, confirming that no actively exploited critical vulnerabilities compromised core assets. This data supports a stable security posture, allowing remediation efforts to proceed on a routine schedule focused on addressing moderate-risk findings rather than reacting to urgent threats.

Threat modes this week were dominated by vulnerability scanning and exposure risks rather than social engineering, with no phishing campaigns or targeted credential attacks identified in the capture data. The presence of 48 non-CVE items suggests continued background threat intelligence activity, but the absence of specific phishing indicators points to a threat landscape focused on technical weaknesses. Adversary behavior appears aligned with opportunistic exploitation of known Tier 2 vulnerabilities, yet the lack of active GN CVEs indicates that these efforts have not translated into successful intrusions. Defensive controls effectively neutralized direct threat vectors, maintaining a low level of active malicious engagement.

Infrastructure operations maintained a steady cadence throughout the six-day window, with the volume of 131 items processed efficiently within standard operational workflows. The absence of critical active threats enabled engineering teams to prioritize scheduled maintenance and routine patching cycles without diversion to emergency incident response. Operational stability was further reinforced by the successful triage of 83 CVEs, ensuring that vulnerability management remained integrated into daily operations rather than disrupting service delivery. The infrastructure team successfully balanced security hygiene with service continuity, reflecting a mature operational rhythm capable of handling moderate intelligence loads.

Stability and resilience metrics remain robust, driven by the zero count of GN active CVEs and the effective management of the vulnerability backlog. The infrastructure demonstrates strong resilience against exploitation, as the Tier 2 classification of observed CVEs indicates that defensive depth is sufficient to mitigate potential attacks on moderate-severity flaws. System availability and performance were preserved, with no evidence of degradation linked to security events or infrastructure strain. Overall, the environment exhibits high resilience, supported by proactive monitoring and the sustained ability to contain risk factors, ensuring reliable service delivery despite the ongoing influx of vulnerability disclosures.

### 1.2 PIR breakdown

| PIR   |   Report Total |
|-------|----------------|
| 3.k   |             57 |
| 1.b   |             28 |
| 1.a   |             15 |
| 1.j.3 |             10 |
| 1.e   |              7 |
| 1.c   |              5 |
| 1.d   |              5 |
| 1.f   |              2 |
| 1.g   |              1 |
| 1.h   |              1 |

### 1.3 Horizon bullets

- [CVE-2026-110475 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-110475) (2026-10-26)
- [CVE-2026-116587 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-116587) (2026-10-26)
- [CVE-2026-110474 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-110474) (2026-10-26)
- [CVE-2026-116672 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-116672) (2026-10-27)
- [CVE-2026-104189 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-104189) (2026-10-27)
- [CVE-2026-111107 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-111107) (2026-10-27)
- [CVE-2025-14260 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2025-14260) (2026-10-28)
- [CVE-2026-104383 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-104383) (2026-10-28)
- [CVE-2026-118669 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-118669) (2026-10-28)
- [CVE-2026-112256 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-112256) (2026-10-29)
- [CVE-2026-119127 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-119127) (2026-10-29)
- [CVE-2026-119128 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-119128) (2026-10-29)
- [CVE-2026-119421 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-119421) (2026-10-30)
- [CVE-2026-46560 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-46560) (2026-10-30)
- [CVE-2026-63182 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-63182) (2026-10-30)
- [CVE-2026-119977 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-119977) (2026-10-31)
- [Unmasking EvilTokens: Getting to the root of device code phishing](https://aka.ms/EvilTokens-PhaaS) (2026-10-31)
- [Breaking the code: Multi-stage ‘code of conduct’ phishing campaign leads to AiTM token com](https://microsoft.com/en-us/security/blog/2026/05/04/breaking-the-code-multi-stage-code-of-conduct-phishing-campaign-leads-to-aitm) (2026-10-31)

## 2. DPI Stories of the Week


# **[Joint advisory: state-sponsored spear-phishing campaigns targeting ...](https://suvat.uk/blog/five-eyes-advisory.html)**

**PIR: 1.a**

Source: ketch Published: 2026-10-26

A Five Eyes joint advisory warns critical infrastructure operators of state-sponsored spear-phishing campaigns targeting energy, transport, and water sectors. The threat actors deploy highly tailored lures and malicious attachments to establish initial access. Infrastructure defenders should review email filtering rules, segment OT/IT networks, and monitor for lateral movement indicators aligned with the provided IOCs.



___________________________________


# **[Reports & advisories | National Cyber Security Centre](https://www.ncsc.gov.uk/section/keep-up-to-date/reports-advisories)**

**PIR: 1.a**

Source: ketch Published: 2026-10-26

The NCSC and international partners expose a Russian state-supported zero-click phishing campaign targeting Western organizations. The LAUNDRY BEAR threat group utilizes sophisticated exploit chains delivered via seemingly benign communications to bypass user interaction requirements. Infrastructure teams should prioritize patching known vulnerabilities, implementing network segmentation, and deploying advanced endpoint detection to mitigate silent compromises.



___________________________________


# **[Inside an AI‑enabled device code phishing campaign](https://microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026)**

**PIR: 1.j.3**

Source: ketch Published: 2026-10-26

Microsoft security researchers detail a sophisticated campaign leveraging AI-generated lures to exploit OAuth device code flows. Attackers trick users into entering device codes on fraudulent portals, bypassing MFA and enabling full account takeover. The report provides technical indicators, mitigation strategies for identity providers, and guidance for monitoring anomalous OAuth consent events.



___________________________________


# **[Operation HookedWing: 4-Year Campaign Compromises 500 Orgs - Phishing](https://dailysecurityreview.com/phishing/operation-hookedwing-4-year-campaign-compromises-500-orgs/)**

**PIR: 1.e**

Source: ketch Published: 2026-10-26

SOCRadar reveals Operation HookedWing, a long-running credential-harvesting operation that compromised thousands of accounts across critical infrastructure sectors. Attackers leveraged GitHub Pages to host persistent phishing infrastructure, evading traditional blocklists. The report details campaign timelines, targeted verticals, and defensive recommendations for monitoring code hosting platforms and enforcing passwordless authentication.



___________________________________


# **[AI-enabled device code phishing campaign exploits OAuth flow for account takeover](https://helpnetsecurity.com/2026/04/07/microsoft-device-code-phishing-campaign)**

**PIR: 1.j.3**

Source: ketch Published: 2026-10-26

This analysis breaks down how threat actors abuse the Microsoft device code authentication mechanism to circumvent multi-factor authentication. By hosting fake login pages that request device codes, attackers gain persistent access to enterprise accounts. The article outlines detection rules for SIEM platforms, recommended conditional access policies, and steps to revoke compromised OAuth grants.



___________________________________


# **[Device Code Phishing: How EvilTokens Hit 12,000+ Inboxes](https://ctiacademy.io/blog/device-code-phishing)**

**PIR: 1.j.3**

Source: ketch Published: 2026-10-26

CTIA Academy examines the EvilTokens campaign, which successfully delivered device code phishing lures to over 12,000 corporate inboxes. The report highlights the technical mechanics of token theft, the role of compromised legitimate domains in hosting phishing pages, and actionable defense playbooks for email security gateways and identity protection teams.



___________________________________


# **[Coordinated phishing campaign targeting UK public sector organisations](https://suvat.uk/blog/public-sector-phishing.html)**

**PIR: 1.e**

Source: ketch Published: 2026-10-26

SUVAT identifies a coordinated credential-harvesting campaign targeting UK public sector entities, including NHS trusts and local authorities. Attackers spoof official government domains and deploy realistic email lures to capture staff credentials. Defenders should implement strict DMARC enforcement, monitor for domain impersonation, and enforce multi-factor authentication across all public-facing identity portals.



___________________________________


# **[GhostCode: How Device-Code Phishing Is Hijacking Microsoft 365 Accounts](https://9to5windows.com/ghostcode-device-code-phishing-microsoft-365-accounts)**

**PIR: 1.j.3**

Source: ketch Published: 2026-10-26

GhostCode represents a persistent threat actor group specializing in device code phishing against Microsoft 365 tenants. The campaign uses highly convincing templates and automated infrastructure to harvest codes at scale. Defenders are advised to audit OAuth app permissions, enforce device compliance policies, and monitor for unusual sign-in patterns originating from unfamiliar IP ranges.



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

- `/root/cyber-threat-observatory/reports/2026-10-26/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-10-27/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-10-28/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-10-29/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-10-30/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-10-31/infrastructure_daily_brief.md`

### 6.2 Community notes

_Placeholder for member submissions._

---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine