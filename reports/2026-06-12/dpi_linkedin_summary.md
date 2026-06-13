# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-06-13 08:58:18Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-06-12`
- **Included count:** 5

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 4 | 2 | CVE-2026-10557 | Affects Digital Identity and Government sectors through hard-coded MQTT credentials in Yarbo robot control apps, enabling unauthorized access to global robot fleets. | A critical vulnerability in Yarbo's mobile app exposes hard-coded MQTT credentials, allowing attackers to take full control of robot fleets. This impacts both Digital Identity and Government infrastructure used in commercial facilities. |
| 4 | 2 | CVE-2026-50090 | Aqara's OAuth redirect_uri bypass impacts Digital Identity infrastructure by enabling account takeover through flawed SSO validation. | Aqara's cloud OAuth vulnerability demonstrates how IoT device management platforms can be exploited for account takeovers via insecure redirect URI handling. This highlights the importance of robust identity and access controls in connected ecosystems. |
| 4 | 2 | CVE-2026-53868 | Affects Digital Identity infrastructure by disrupting authentication and account management in a SaaS platform through unverified email registration and deletion. | A denial-of-service flaw in Capgo's SaaS platform could lock legitimate users out for 30 days by exploiting weak account lifecycle controls. This highlights the importance of robust identity management practices in cloud-based services. |
| 4 | 2 | CVE-2026-54361 | Affects MISP, a threat intelligence platform used in government sectors for national security operations and information sharing among public sector organizations. | A mass assignment vulnerability in MISP (Malware Information Sharing Platform) could allow authenticated attackers to manipulate ownership fields and transfer sensitive threat intelligence between organizations. This impacts government agencies relying on MISP for collaborative threat analysis. |
| 4 | 2 | CVE-2026-8828 | Impacts Digital Identity infrastructure through an authorization bypass that compromises tenant isolation in multi-tenant AI applications. | A TIER 2 vulnerability in ChromaDB allows authenticated users to access any tenant's data, highlighting critical gaps in multi-tenant identity and access management. This poses a serious risk for AI platforms relying on secure tenant boundaries. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2025-14098.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-7002.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-7003.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-7004.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-7008.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-7011.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-7017.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-9032.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-9033.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-11845.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-11846.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-11849.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-11967.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12043.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12068.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-3840.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-42306.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-42850.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-44168.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-44892.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-44893.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-44894.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-44990.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-45169.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-45170.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-45832.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46340.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47196.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47216.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47367.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47370.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48006.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48059.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48119.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48165.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48612.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-4870.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48748.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50011.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50088.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50091.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50101.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50108.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50631.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50632.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50633.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50645.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53821.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53822.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53825.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53829.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53831.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53832.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54056.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54057.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54358.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-6676.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-7368.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-9266.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-9638.md` — heuristic TIER 3/4
