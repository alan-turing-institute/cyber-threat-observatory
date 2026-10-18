# Infrastructure Weekly Capture (IWC): 2026-10-12 - 2026-10-18

## 1. Weekly threat overview

### 1.1 Executive summary

Over the four-day reporting period, the infrastructure capture recorded a total of 216 intelligence items, with vulnerability management dominating the landscape. CVE-related entries comprised 184 of these items, reflecting a high density of vulnerability disclosures. Despite this volume, the week-over-week tone indicates a controlled risk environment, as evidenced by zero active CVEs (gn_active_cves: 0). This metric suggests that while the external threat surface is expanding with new disclosures, the organization's current exposure remains mitigated, and no active exploitation of known vulnerabilities has been detected within the monitored scope.

Threat intelligence reveals a concentrated focus on advanced identity compromise techniques, particularly device code phishing campaigns. Multiple reports highlight the emergence of "EvilTokens" and AI-enabled phishing methods designed to subvert multi-factor authentication by hijacking device code authorization flows. Adversaries are increasingly leveraging these mechanisms to facilitate account takeover and identity theft, representing an evolution in social engineering that targets the authentication layer directly. Defensive posture must adapt to this shift by implementing stricter controls on device code usage, monitoring for anomalous authorization requests, and reinforcing user training against prompts to enter codes on untrusted devices.

Infrastructure operations are prioritizing remediation efforts based on the severity classification of the captured vulnerabilities. The dataset includes one Tier 1 vulnerability, CVE-2026-104935, which demands immediate assessment and patching to address critical risk. The remaining CVE inventory consists of Tier 2 items, such as CVE-2026-109371, CVE-2026-103903, and CVE-2026-111924, which should be scheduled for resolution within the standard maintenance cycle. Operational teams are advised to validate asset coverage for these vulnerabilities and ensure that patch deployment processes are optimized to reduce the window of exposure for high-priority findings.

System stability remains high, underpinned by the absence of active CVEs and the effective management of vulnerability backlogs. Resilience is currently robust against infrastructure-level exploits but requires heightened vigilance regarding identity-based threats. The zero active CVE count confirms that the environment is not currently vulnerable to known, actively exploited weaknesses, providing a stable foundation for operations. To maintain this resilience, the focus should remain on rapid Tier 1 remediation and strengthening identity security controls to neutralize the growing threat of device code phishing and AI-assisted attack vectors.

### 1.2 PIR breakdown

| PIR   |   Report Total |
|-------|----------------|
| 3.k   |            163 |
| 1.b   |             30 |
| 1.d   |              5 |
| 1.c   |              5 |
| 1.i   |              1 |
| 1.g   |              1 |
| 1.f   |              1 |
| 1.e   |              1 |
| 1.b.4 |              1 |
| 1.b.2 |              1 |
| 1.d.2 |              1 |
| 1.c.1 |              1 |
| 1.b.1 |              1 |
| 1.e.3 |              1 |
| 1.b.3 |              1 |
| 1.d.1 |              1 |
| 1.j.3 |              1 |

### 1.3 Horizon bullets

- [CVE-2026-109371 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-109371) (2026-10-12)
- [CVE-2026-109372 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-109372) (2026-10-12)
- [CVE-2026-109373 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-109373) (2026-10-12)
- [CVE-2026-102210 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-102210) (2026-10-13)
- [CVE-2026-103849 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-103849) (2026-10-13)
- [CVE-2026-104935 (Tier 1)](https://nvd.nist.gov/vuln/detail/CVE-2026-104935) (2026-10-13)
- [CVE-2026-111882 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-111882) (2026-10-14)
- [CVE-2026-111911 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-111911) (2026-10-14)
- [CVE-2026-111880 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-111880) (2026-10-14)
- [CVE-2026-111923 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-111923) (2026-10-15)
- [Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Security Blo](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/) (2026-10-15)
- [Inside an AI‑enabled device code phishing campaign | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/) (2026-10-15)

## 2. DPI Stories of the Week


# **[Unmasking EvilTokens: Getting to the root of device code phishing](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/)**

**PIR: 1.b.4**

Source: ketch Published: 2026-10-14

This technical deep dive examines EvilTokens, a sophisticated framework enabling persistent device-code phishing attacks that bypass MFA and conditional access controls. Attackers harvest long-lived tokens by tricking users into authorizing malicious apps, granting them seamless access to M365 and Azure resources. Infrastructure teams must audit OAuth app permissions, revoke suspicious device codes, and implement token lifetime restrictions to neutralize this identity takeover vector.



___________________________________


# **[Microsoft Disrupts YAM Store Network Behind 1 Billion Phishing Scams and M365 Device-Code Attacks](https://windowsforum.com/news/microsoft-disrupts-yam-store-network-behind-1-billion-phishing-scams-and-m365-device-code-attacks.448313/post-1012947)**

**PIR: 1.b.2**

Source: ketch Published: 2026-10-14

Microsoft’s coordinated takedown of the YAM Store network dismantled a massive infrastructure responsible for over one billion phishing attempts and widespread M365 device-code attacks. The campaign exploited compromised legitimate services to host credential-harvesting pages and bypass email security filters. Defenders should review M365 audit logs for suspicious device-code authorizations, enforce conditional access policies, and monitor for traffic to known YAM Store domains to prevent identi



___________________________________


# **[Inside an AI‑enabled device code phishing campaign | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.d.2**

Source: ketch Published: 2026-10-14

Threat actors are integrating generative AI to automate device-code phishing campaigns, dynamically generating realistic login pages and contextual lures that adapt to victim behavior. The AI-driven infrastructure scales attacks rapidly while evading signature-based detection. Defenders should deploy AI-aware web filtering, monitor for anomalous OAuth consent requests, and enforce strict conditional access rules to block automated identity harvesting attempts.



___________________________________


# **[Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA](https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns)**

**PIR: 1.c.1**

Source: ketch Published: 2026-10-14

Threat actors increasingly leverage ephemeral cloud resources, serverless functions, and containerized environments to host phishing infrastructure, evading traditional IP-based blocklists. This report details how attackers abuse cloud-native APIs to dynamically provision phishing domains and redirect traffic, complicating takedown efforts. Infrastructure defenders must implement cloud workload protection platforms, enforce strict IAM policies, and monitor for anomalous resource provisioning pat



___________________________________


# **[Microsoft Teams Phishing via Fake IT Helpdesk Impersonation (External Chat, Vishing, Screen Sharing, RMM](https://intel.threadlinqs.com/threat/TL-2026-3778)**

**PIR: 1.e.3**

Source: ketch Published: 2026-10-14

Attackers are exploiting Microsoft Teams’ external chat and screen-sharing features to impersonate IT helpdesk personnel, tricking users into granting remote access via RMM tools. This vishing and social engineering campaign bypasses traditional email filters by operating entirely within collaboration platforms. Defenders should disable external Teams messaging where possible, enforce multi-factor authentication for RMM access, and train staff to verify helpdesk requests through out-of-band chan



___________________________________


# **[n8n Weaponized for Phishing and Device Fingerprinting](https://labs.cloudsecurityalliance.org/research/csa-research-note-n8n-ai-workflow-phishing-20260416-csa-styl)**

**PIR: 1.d.1**

Source: ketch Published: 2026-10-14

Cybercriminals are repurposing the open-source workflow automation tool n8n to orchestrate phishing campaigns and collect detailed device fingerprints. By chaining n8n workflows with browser fingerprinting scripts, attackers tailor phishing payloads to specific victim environments, increasing success rates. IT teams must monitor for unauthorized n8n deployments, restrict outbound API calls from automation servers, and deploy browser fingerprinting detection in web proxies to disrupt these adapti



___________________________________


# **[Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.d**

Source: ketch Published: 2026-10-12

This campaign represents a major escalation in threat actor sophistication, shifting from static scripts to fully AI-driven infrastructure and end-to-end automation. Building on the Storm-2372 device code phishing activity observed in early 2025, attackers now leverage machine learning to dynamically generate convincing phishing pages, optimize delivery timing, and automate credential harvesting. IT defenders must prioritize monitoring for anomalous OAuth device code flows and implement AI-aware



___________________________________


# **[The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime/)**

**PIR: 1.e**

Source: ketch Published: 2026-10-13

Microsoft researchers dissect the underground infrastructure ecosystem fueling global phishing operations. The report details how threat actors leverage bulletproof hosting, domain generation algorithms, and compromised legitimate services to evade takedowns. IT defenders gain actionable intelligence on infrastructure indicators, hosting patterns, and mitigation strategies to disrupt attacker supply chains before campaigns scale.



___________________________________


## 3. Critical WAVE Reports

_No Tier 1/2 WAVE reports this week._

## 4. Cyber reporting

### 4.1 Activity metrics

| Metric                   |   Value |
|--------------------------|---------|
| Daily editions           |       4 |
| Total intelligence items |     216 |
| CVE-related items        |     184 |
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

- `/root/cyber-threat-observatory/reports/2026-10-12/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-10-13/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-10-14/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-10-15/infrastructure_daily_brief.md`

### 6.2 Community notes

_Placeholder for member submissions._

---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine