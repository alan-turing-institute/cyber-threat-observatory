# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-07-09 09:30:24Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-07-08`
- **Included count:** 5

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-54782 | Impacts Digital Identity systems through SAML token validation bypass allowing full impersonation of any principal, including administrative accounts. | A critical authentication bypass in CoreWCF could allow attackers to fully impersonate users—including admins—via SAML tokens. This affects federated identity systems and requires immediate patching. |
| 5 | 2 | CVE-2026-55471 | High-impact XXE vulnerability in HAPI FHIR library used for healthcare data exchange, affecting digital public infrastructure in healthcare systems. | A critical XXE flaw (CVE-2026-55471) in the HAPI FHIR Java library could lead to local file disclosure and SSRF in healthcare IT systems. This vulnerability impacts FHIR servers used for medical data interoperability—key components of digital public infrastructure. |
| 4 | 2 | CVE-2026-55429 | Affects Digital Identity by enabling authorization bypass in Coder's workspace management, allowing impersonation of user development environments. | A high-severity authorization bypass in Coder allows attackers with elevated privileges to rebind workspace apps and proxy user sessions—directly impacting identity and access management within enterprise development platforms. |
| 4 | 2 | CVE-2026-55470 | Relevant to Healthcare and Digital Identity sectors due to its impact on FHIR-based healthcare systems processing patient data and identity-related components. | A ReDoS vulnerability in the HAPI FHIR DSTU2 module could disrupt critical healthcare IT infrastructure, affecting patient data handling and system availability. This highlights the importance of securing health information exchanges and digital identity management within public health ecosystems. |
| 3 | 2 | CVE-2026-15134 | Relevant to Digital Identity due to authentication and access control mechanisms in an HR/leave management system; potential Government sector relevance for public sector deployments. | A SQL injection vulnerability in a PHP-based employee leave management system could compromise user credentials and sensitive personnel data. This highlights the importance of securing internal HR applications that handle digital identity and access controls. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-10037.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-10698.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-10699.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-11903.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13126.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13127.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13128.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13129.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13320.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15053.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15167.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-22927.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-29008.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-29009.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-41042.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-41122.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47646.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-49145.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-49146.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-49147.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-49866.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53482.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54591.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54772.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55206.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55404.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55436.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55760.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55849.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55999.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56000.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56001.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56002.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56003.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56250.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56297.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56437.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56669.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57237.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57238.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57239.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57240.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57242.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57244.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57245.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57246.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57247.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57248.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57249.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57250.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57251.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57252.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57254.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57256.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57260.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58213.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58250.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58253.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59724.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59725.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59805.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59822.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59869.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59873.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59874.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59879.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59887.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59892.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59922.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59925.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59928.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59935.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59936.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59948.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60104.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-6230.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-6818.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-6820.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-6896.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-8307.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-9695.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-9700.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-9701.md` — heuristic TIER 3/4
