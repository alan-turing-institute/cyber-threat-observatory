# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-07-01 09:00:11Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-06-30`
- **Included count:** 8

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 4 | 2 | CVE-2026-14162 | This vulnerability affects healthcare infrastructure, specifically hospital queuing systems that manage patient data flows, making it relevant to the Healthcare sector. | A sensitive data exposure in Advantech's Hospital Queuing Management software could aid attackers in mapping internal APIs. This highlights the importance of securing healthcare IT systems where patient data is handled. |
| 4 | 2 | CVE-2026-50110 | Affects industrial control systems in Healthcare, Energy, and Digital Identity sectors with hardcoded credentials that can enable lateral movement across critical infrastructure. | A TIER 2 vulnerability in StoneFly Storage Concentrators exposes hardcoded credentials that could allow attackers to move laterally within ICS environments. This impacts critical infrastructure sectors including healthcare and energy, where such systems manage sensitive data and access controls. |
| 4 | 2 | CVE-2026-52868 | Healthcare sector relevance due to exposure of patient worklist records in DICOM medical imaging systems; also involves digital identity through access control mechanisms. | A path traversal flaw in OFFIS DCMTK could let attackers access unauthorized patient data across healthcare departments. This highlights the importance of securing medical imaging systems that handle sensitive health information. |
| 4 | 2 | CVE-2026-56230 | This CVE impacts Digital Identity infrastructure by enabling cross-tenant resource access through a Broken Object Level Authorization (BOLA) flaw in Capgo's API key system, which manages authentication and authorization for multi-tenant applications. | A BOLA vulnerability in Capgo’s API key handling allows authenticated users to bypass tenant boundaries and access unauthorized resources. This highlights the importance of robust authorization controls in multi-tenant platforms managing digital identity and access. |
| 4 | 2 | CVE-2026-56286 | Affects Digital Identity through an authentication bypass in Capgo's account deletion endpoint, which could facilitate unauthorized account takeovers and data loss. | A critical auth bypass in Capgo’s account deletion flow can lead to unauthorized account deletions and takeover. This highlights the importance of re-authentication for destructive actions in identity platforms. |
| 4 | 2 | CVE-2026-58138 | Affects Digital Identity systems as Orkes Conductor is used for access control and authorization workflows in enterprise environments. | Orkes Conductor RCE vulnerability (CVE-2026-58138) could allow attackers to execute arbitrary code in identity and access management workflows. A critical unauthenticated RCE in workflow orchestration systems impacts digital identity infrastructure. |
| 3 | 2 | CVE-2026-48285 | Affects Digital Identity infrastructure as Adobe ColdFusion is used for enterprise authentication and access control systems. | Adobe ColdFusion SSRF vulnerability (CVE-2026-48285) could impact enterprise identity management platforms. Security teams should review configurations and apply patches to prevent unauthorized internal data access. |
| 3 | 2 | CVE-2026-56320 | Relevant to Digital Identity due to API key-based access control and authorization boundary bypass in mobile app management platform. | A TIER 2 vulnerability in Capgo's device creation endpoint could allow unauthorized device record creation across organizational boundaries, impacting identity and access management for mobile applications. This highlights the importance of strict authorization controls in digital infrastructure platforms. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2025-71349.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-71350.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-71352.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-71374.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-7406.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-10513.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-10816.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-11541.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-11589.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-11590.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12578.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12818.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13149.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13449.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13474.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14161.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-35505.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-44628.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-44946.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-45822.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48307.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48315.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-49432.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-49434.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50003.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50254.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50734.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50750.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53916.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53917.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54475.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54672.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55721.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56137.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56247.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56328.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56413.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57080.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57585.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57995.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58014.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58016.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58172.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58176.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58447.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-8402.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-8451.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-8452.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-8655.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-8864.md` — heuristic TIER 3/4
