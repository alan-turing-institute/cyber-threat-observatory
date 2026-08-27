# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-08-27 11:53:23Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-08-26`
- **Included count:** 8

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 4 | 2 | CVE-2026-18664 | Foundational DNS infrastructure flaw enabling unauthorized zone transfers and data leakage across all regulated/public sectors relying on NSD. | DNS is the backbone of digital public infrastructure. This TIER 2 flaw in NSD allows attackers to bypass access controls and steal zone data, threatening the reliability and confidentiality of government, healthcare, and financial services. Patch or refactor IP range configs now. |
| 4 | 2 | CVE-2026-54569 | Critical unauthenticated RCE in SENAITE LIMS, widely deployed in clinical diagnostics and public health laboratories, directly threatening patient data integrity and healthcare workflow continuity. | A critical, unauthenticated RCE in SENAITE LIMS (CVE-2026-54569) poses a direct threat to clinical and public health laboratories. With a ready-to-use PoC and default misconfigurations enabling trivial exploitation, healthcare and government lab operators must prioritize patching to protect patient data and diagnostic workflows. |
| 4 | 2 | CVE-2026-81036 | OAuth redirect bypass in widely deployed mail server enables account takeover, directly impacting Digital Identity and secure communications across Government, Finance, and Healthcare sectors. | A default OAuth misconfiguration in Stalwart Mail Server could hand attackers full account access via simple phishing links. For DPI operators, this underscores the critical need to harden identity flows and enforce redirect URI validation in public-facing email infrastructure. |
| 3 | 2 | CVE-2026-77537 | Unauthenticated RCE in Ubiquiti surveillance hardware widely deployed across municipal and critical infrastructure networks. | Municipal and enterprise networks using Ubiquiti UniFi Protect for physical security face immediate risk from an unauthenticated RCE flaw. Prompt patching and strict network segmentation are essential to protect public-sector surveillance infrastructure from compromise and lateral movement. |
| 3 | 2 | CVE-2026-77546 | Physical access control consoles manage civic and enterprise building security; authenticated RCE poses a direct risk to the physical-digital infrastructure bridge. | Building security isn't just physical—it's a digital attack surface. CVE-2026-77546 shows how authenticated RCE in access control consoles can compromise civic and enterprise infrastructure, reinforcing the need for network segmentation and rapid patching. |
| 3 | 2 | CVE-2026-77548 | Critical command injection in Ubiquiti UniFi Protect surveillance software, explicitly tied to government facilities and public infrastructure security. | Video surveillance underpins modern public safety and government facility operations. This critical RCE in Ubiquiti UniFi Protect underscores the necessity of strict patching and network segmentation for civic infrastructure deployments. |
| 3 | 2 | CVE-2026-77550 | Critical unauthenticated auth-bypass in Ubiquiti UniFi OS networking controllers, explicitly deployed across government and enterprise infrastructure. | A CVSS 10.0 CRLF injection in Ubiquiti UniFi OS allows unauthenticated attackers to bypass authentication and seize full admin control. Given its widespread use in government and enterprise networks, internet-exposed controllers require immediate patching and strict access controls. |
| 2 | 2 | CVE-2026-80428 | Unauthenticated RCE in ILIAS LMS impacts public education infrastructure, risking compromise of student/staff data and learning platforms. | Public education platforms face critical exposure: an unauthenticated RCE in ILIAS LMS allows full server compromise via default Shibboleth/LTI endpoints. Institutions should prioritize patching to protect student data and learning continuity. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-15203.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16444.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19042.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19271.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19401.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47836.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47841.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54245.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54511.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54550.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55228.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58089.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58090.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58091.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58094.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58097.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61792.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64632.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65641.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65642.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66003.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68861.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70419.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71171.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-74770.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75896.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77317.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77368.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77532.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77534.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77535.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77538.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77539.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77540.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77541.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77542.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77543.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77545.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77547.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77549.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77551.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77552.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77553.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77554.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77557.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77611.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78236.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78237.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79619.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79921.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79938.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-80183.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-80205.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-80214.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-80233.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-80236.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-80237.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-80346.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-80347.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-80426.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81029.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81031.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81034.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81035.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81202.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81421.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-68863.md` — heuristic TIER 3/4
