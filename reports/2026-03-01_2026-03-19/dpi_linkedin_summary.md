# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-03-21 07:56:12Z
- **Reports folder:** `/root/cyber-threat-observatory/reports`
- **Included count:** 15

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2025-30035 | This vulnerability affects CGM CLININET, a healthcare information system used in hospitals and outpatient clinics, directly impacting patient data security and medical record access within digital public infrastructure. | A critical authentication bypass in CGM CLININET could allow attackers to fully compromise any user account with just a username—putting sensitive patient data at risk. This highlights the importance of securing healthcare IT systems that form part of our digital public infrastructure. |
| 5 | 2 | CVE-2025-30042 | This vulnerability affects a healthcare information system managing sensitive patient data, placing it within the Digital Public Infrastructure domain under Healthcare. | A critical authentication bypass in CGM CLININET could expose sensitive patient records—highlighting the need for robust access controls in healthcare DPI systems. #HealthcareSecurity #DPI |
| 4 | 2 | CVE-2025-67038 | Affects industrial control systems and critical infrastructure devices used in enterprise edge networks managing serial equipment. | A TIER 2 vulnerability in Lantronix EDS5000 device servers could allow attackers to execute arbitrary OS commands with root privileges, impacting critical infrastructure. This highlights the importance of securing industrial IoT devices that connect legacy systems to modern networks. |
| 4 | 2 | CVE-2026-22552 | A missing authentication flaw in EV charging infrastructure can lead to unauthorized control of critical energy and transportation systems. | A critical auth bypass in EV charging platforms could disrupt public energy grids and mobility services. This TIER 2 vulnerability highlights the need for secure IoT deployments in digital public infrastructure. |
| 4 | 2 | CVE-2026-24898 | A token disclosure vulnerability in OpenEMR impacts healthcare DPI systems, potentially leading to PHI exposure and HIPAA violations. | A TIER 2 vulnerability in OpenEMR could expose sensitive patient data through unauthenticated API tokens. Healthcare organizations using this system should verify their MedEx integration settings and apply the patch immediately. |
| 4 | 2 | CVE-2026-25146 | Exposure of payment gateway API keys in OpenEMR impacts healthcare digital infrastructure and could enable financial fraud. | A TIER 2 vulnerability in OpenEMR could expose sensitive payment gateway secrets, affecting healthcare systems that are part of Digital Public Infrastructure. This highlights the importance of securing EHR platforms where financial data is processed. |
| 4 | 2 | CVE-2026-26266 | This XSS vulnerability in AliasVault's web client impacts identity management and email aliasing services that handle sensitive user data, relevant to DPI as it affects secure digital identity infrastructure. | A stored XSS flaw in AliasVault's web client could allow attackers to hijack user sessions by injecting malicious scripts into email content. This is particularly concerning for DPI environments relying on secure identity management and email aliasing services. |
| 4 | 2 | CVE-2026-27028 | A critical vulnerability in EV charging infrastructure management software could allow unauthorized control of public transportation systems, impacting digital public infrastructure. | A TIER 2 vulnerability in Mobility46's EV charging platform highlights a critical gap in transportation infrastructure security. If exploited, attackers could impersonate charging stations and manipulate backend data—posing risks to smart city initiatives and sustainable mobility services that rely on secure, public-facing systems. |
| 4 | 2 | CVE-2026-27647 | A session management flaw in EV charging infrastructure software could enable unauthorized access or DoS attacks on critical transportation systems. | A TIER 2 vulnerability in EV charging station software (Mobility46) highlights risks to smart city infrastructure. If exposed, attackers can hijack sessions and disrupt charging services—critical for public transportation and energy grid management. |
| 4 | 2 | CVE-2026-29191 | A critical XSS vulnerability in ZITADEL's SAML endpoint can lead to account takeover, impacting identity management systems foundational to DPI. | A critical XSS flaw in ZITADEL's login interface could allow attackers to hijack user accounts and access sensitive data. This highlights the importance of securing identity platforms that underpin digital public infrastructure. |
| 4 | 2 | CVE-2026-32118 | OpenEMR is a critical healthcare infrastructure component; this XSS flaw can lead to session hijacking and unauthorized access to PHI, affecting public health data systems. | A stored XSS vulnerability in OpenEMR could allow attackers to hijack clinician sessions and access protected health information. This highlights the importance of patching healthcare IT systems that manage critical citizen data. |
| 4 | 2 | CVE-2026-32169 | This SSRF vulnerability in Azure Cloud Shell could impact government and public sector cloud infrastructure used in digital public services. | A critical SSRF flaw in Microsoft's Azure Cloud Shell could allow privilege escalation within cloud environments. While requiring authentication, this highlights risks to DPI components that support government agencies and public services. |
| 4 | 2 | CVE-2026-3611 | Affects industrial control systems used in critical infrastructure sectors like healthcare, government services, and manufacturing, where unauthorized access can compromise building management and safety systems. | A TIER 2 vulnerability in Honeywell IQ4x controllers could allow attackers to gain full administrative control over building management systems—critical for facilities like hospitals or government buildings. This highlights the need for network segmentation and secure defaults in ICS environments. |
| 3 | 2 | CVE-2026-26125 | This vulnerability affects Microsoft's Payment Orchestrator Service, a critical component in financial transaction processing that could impact DPI-relevant payment infrastructures if deployed internally. | A TIER 2 vulnerability in Microsoft's Payment Orchestrator Service highlights potential privilege escalation risks in internal financial systems. While not internet-facing, it underscores the importance of securing backend payment infrastructure—especially relevant for DPI and regulated environments. |
| 3 | 2 | CVE-2026-29000 | Affects JWT-based authentication in backend services, potentially impacting government identity systems if used in public infrastructure. | A critical auth bypass in pac4j-jwt could allow attackers to impersonate admins by forging JWE-wrapped tokens. While not directly DPI-relevant, it's a key risk for internal services that may support public digital identity systems. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2006-10002.md` — heuristic TIER 3/4
- `TIER_3_CVE-2015-20120.md` — heuristic TIER 3/4
- `TIER_3_CVE-2016-20026.md` — heuristic TIER 3/4
- `TIER_3_CVE-2019-25513.md` — heuristic TIER 3/4
- `TIER_3_CVE-2019-25514.md` — heuristic TIER 3/4
- `TIER_3_CVE-2024-55024.md` — heuristic TIER 3/4
- `TIER_3_CVE-2024-57854.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-11252.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-12462.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-13476.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-14923.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-29165.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-30044.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-40943.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-41709.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-41764.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-41765.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-48609.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-48611.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-69614.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-69808.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-69809.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-69902.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-70042.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-70046.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-70219.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-70225.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-70229.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-70821.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-0006.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-0111.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-0114.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-0120.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-1525.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-1626.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-1678.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-21622.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-21628.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-21657.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-21658.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-21660.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-21708.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-21994.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-22193.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-22501.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-2251.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-22557.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-22891.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-2330.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-2331.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-23767.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-24101.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-24105.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-24108.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-24111.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-24112.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-24113.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-24114.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-24115.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-24352.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-24445.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-25072.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-25702.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-25823.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-2584.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-25873.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-26051.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-26105.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-26290.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-26305.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-26694.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-26701.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-26704.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-26705.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-26706.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-26708.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-26709.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-26710.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-26711.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-2743.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-27441.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-27442.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-27459.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-2751.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-27703.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-27755.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-27772.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-27947.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-28074.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-28114.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-28431.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-2844.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-28446.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-28448.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-28453.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-28466.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-28479.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-28680.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-28776.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-28785.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-28802.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-29045.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-29046.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-29103.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-29121.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-29122.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-29127.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-29515.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-2991.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-30704.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-30792.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-30797.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-30871.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-30884.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-30909.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-30968.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-30970.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-3130.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-3136.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-31800.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-31862.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-31877.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-31883.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-31885.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-31967.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-31972.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-3204.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-32137.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-32194.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-32242.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-32260.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-3257.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-3266.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-32865.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-3381.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-3843.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-4177.md` — heuristic TIER 3/4
