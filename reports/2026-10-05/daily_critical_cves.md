# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-10-06 22:50:04Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-10-05`
- **Included count:** 12

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-105307 | Unauthenticated authentication bypass in Casdoor, an open-source IAM/SSO platform, directly compromises Digital Identity infrastructure by enabling remote attackers to manipulate credential flows and access controls. | A critical unauthenticated bypass in Casdoor (CVE-2026-105307) exposes public-facing SSO endpoints to remote attackers, underscoring the urgent need to patch open-source IAM platforms that underpin digital identity infrastructure. |
| 5 | 2 | CVE-2026-105384 | Unauthenticated SQLi in a Hospital Management System enables full extraction of patient PII and clinical records, directly impacting Healthcare DPI and triggering HIPAA/GDPR compliance risks. | A ready-to-exploit SQL injection in an open-source Hospital Management System allows attackers to dump patient records and admin credentials without authentication. Healthcare IT teams must prioritize patching and input validation to protect clinical data and maintain regulatory compliance. |
| 4 | 2 | CVE-2026-104891 | Finance sector: payment verification bypass in crypto payment gateway middleware allows unauthenticated attackers to spoof wallet ownership and bypass financial controls. | A trivial bypass in popular crypto payment middleware lets attackers spoof wallet ownership and access paid services for free. Platforms relying on the MPP ecosystem should patch immediately to safeguard transaction integrity and revenue. |
| 4 | 2 | CVE-2026-105385 | Unauthenticated SQLi in a hospital management system risks patient data breaches and financial record corruption, directly impacting healthcare digital infrastructure. | Healthcare systems face critical risks from unauthenticated SQL injection flaws that can expose patient records and corrupt financial data. Patching hospital management portals is essential to protect clinical infrastructure and maintain patient trust. |
| 4 | 2 | CVE-2026-105387 | Healthcare sector: Unauthenticated SQLi and auth bypass in a public-facing clinic appointment system exposes patient records and disrupts clinical scheduling. | Healthcare providers relying on open-source booking portals face immediate risk: a trivial SQLi bypasses patient login, exposing schedules and records. Deploy WAF rules or restrict access until a patch is available. |
| 4 | 2 | CVE-2026-105470 | Unauthenticated SQLi in a public-facing healthcare appointment booking system exposes patient PII and disrupts clinical administrative workflows. | Healthcare digital infrastructure faces direct risks from unpatched web apps. This TIER 2 SQLi in a clinic booking system highlights the critical need for secure coding practices to protect patient data and maintain service availability. |
| 4 | 2 | CVE-2026-105471 | Unauthenticated SQLi in a public-facing healthcare appointment system exposes patient records and credentials, posing direct HIPAA/GDPR compliance risks. | Healthcare digital infrastructure faces a critical risk from an unauthenticated SQL injection in an open-source appointment booking system, enabling trivial extraction of patient data and plaintext credentials. |
| 4 | 2 | CVE-2026-21589 | Impacts Atlassian Crowd (enterprise IdAM) and widely deployed collaboration suites across government, finance, and healthcare, posing a read-only file access risk to authentication and service infrastructure. | Atlassian’s Crowd IdAM and Data Center suites face a critical path traversal flaw (CVE-2026-21589) that could expose sensitive configs across government, finance, and healthcare deployments. While exploitation requires exact file paths, immediate WAF/Tomcat mitigations and patching are essential for regulated environments. |
| 3 | 2 | CVE-2026-105383 | Unauthenticated SQLi in a hospital management system exposes patient records and clinical transaction data, directly impacting Healthcare DPI. | Even internal or academic hospital management tools can become critical attack vectors. This unauthenticated SQLi highlights the need for strict input validation and network segmentation in clinical environments. |
| 3 | 2 | CVE-2026-55280 | Remote privilege escalation in Android OS impacts enterprise and public-sector mobile deployments, threatening endpoint integrity and internal network access. | A critical remote privilege escalation in Android 16/17 requires zero user interaction, posing a direct threat to enterprise and public-sector mobile fleets. Patching via MDM and enforcing network segmentation are essential to protect regulated endpoint ecosystems. |
| 3 | 2 | CVE-2026-79820 | Critical server management firmware (HPE iLO 7) underpins data center infrastructure hosting regulated and public digital services; authentication bypass risks full host compromise. | Unauthenticated remote bypass in HPE iLO 7 firmware highlights the hidden risks in out-of-band management networks. Even when isolated, BMC vulnerabilities can cascade into full server compromise, making firmware hygiene and network segmentation essential for DPI resilience. |
| 2 | 2 | CVE-2026-49885 | Tier 2 local privilege escalation in Android OS, foundational mobile infrastructure explicitly deployed across enterprise and government sectors. | With Android powering enterprise and government mobile fleets, this Tier 2 local privilege escalation demands immediate patching via MDM to prevent post-compromise sandbox escapes. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-101919.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102282.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103507.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103510.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104706.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104805.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104809.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104810.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104811.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104892.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104966.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104968.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104970.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104971.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104974.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104976.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104977.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105223.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105314.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105382.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105386.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105628.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105630.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105632.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105633.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105635.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105637.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105639.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105640.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105761.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105763.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105782.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19184.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19185.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20521.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20522.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20523.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20524.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20526.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20531.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-45524.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-49878.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-49937.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55266.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55269.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55270.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58865.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63277.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77226.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88395.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93316.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93318.md` — heuristic TIER 3/4
