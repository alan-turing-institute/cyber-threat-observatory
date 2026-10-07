# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-10-07 16:43:23Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-10-06`
- **Included count:** 6

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-59358 | Directly impacts Digital Identity infrastructure by enabling privilege escalation in Cloud Foundry UAA's OAuth token endpoint, compromising core IdAM and session management systems. | A TIER 2 flaw in Cloud Foundry UAA allows attackers to replay user tokens and seize full OAuth admin rights, underscoring the critical need to audit identity configurations and separate public from machine-to-machine flows in regulated environments. |
| 4 | 2 | CVE-2026-76750 | Unauthenticated RCE in HPE Aruba ClearPass NAC, a foundational network access control system explicitly deployed across Government, Healthcare, and Finance sectors to secure internal digital infrastructure. | Critical unauthenticated RCE in HPE Aruba ClearPass Policy Manager threatens the network access control foundations of government, healthcare, and finance environments. While typically internal-facing, compromising this NAC system enables credential harvesting and lateral movement, making immediate patching and strict network segmentation essential for regulated infrastructure. |
| 4 | 2 | CVE-2026-76752 | Foundational NAC platform with unauthenticated admin bypass impacting network access controls and digital identity verification across Government, Healthcare, and Finance sectors. | HPE ClearPass Policy Manager faces a critical unauthenticated bypass (CVE-2026-76752) that could grant full admin control over enterprise NAC. For public infrastructure, this underscores the need to harden internal management networks and prioritize patching for cross-sector access controls. |
| 3 | 2 | CVE-2026-63692 | General infrastructure (Kubernetes storage) explicitly tied to finance, healthcare, and government deployments; unauthenticated admin escalation impacts regulated cluster environments. | Unauthenticated admin takeover in Dell's Kubernetes storage module poses a silent risk to regulated sectors. Even internal-only flaws can cascade across finance, healthcare, and government clusters if network segmentation fails. |
| 2 | 2 | CVE-2026-106118 | Tier 2 out-of-bounds write in foundational .NET image library (ImageSharp) exposes public-facing web apps and cloud services to unauthenticated DoS/RCE. | A ready-to-exploit OOB write in SixLabors ImageSharp (CVE-2026-106118) threatens any .NET web service processing user uploads. Patch to 4.1.1 immediately to prevent unauthenticated crashes and potential RCE. |
| 2 | 2 | CVE-2026-106268 | TIER 2 browser RCE affecting general infrastructure explicitly noted as used across Healthcare, Finance, and Government sectors. | Chrome WebRTC use-after-free (CVE-2026-106268) highlights the persistent risk to client-side access in regulated environments; ensure automated updates are enforced. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-101152.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101153.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101154.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101155.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101156.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101158.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101207.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101258.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102155.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102158.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102159.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102160.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102161.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102162.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102163.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102165.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102167.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102168.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102169.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102406.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103007.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103009.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103346.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103831.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104073.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104850.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105776.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105788.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105791.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105793.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105794.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105796.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105801.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105806.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105811.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105812.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105834.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105840.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105841.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105849.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105860.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105861.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105862.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105867.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105868.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106100.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106107.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106110.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106203.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106211.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106218.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106233.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106255.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106257.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106318.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106346.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106393.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106411.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106439.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106440.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106441.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106442.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106447.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106451.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106455.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106459.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106486.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106488.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106492.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106498.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106500.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106501.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106503.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106505.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106509.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106512.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106547.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-26287.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-43598.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-4889.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54472.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56906.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59357.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61411.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63688.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63697.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65142.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67269.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67270.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67273.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70411.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71168.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76105.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76743.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76745.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76746.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76747.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76748.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76754.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79794.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79797.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79798.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79799.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79800.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79801.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79802.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79803.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79805.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79806.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79807.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79808.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79809.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79810.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79811.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82162.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83550.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86361.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86362.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91140.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94114.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96890.md` — heuristic TIER 3/4
