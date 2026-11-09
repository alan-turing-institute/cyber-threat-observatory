# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-11-09 12:11:28Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-11-08`
- **Included count:** 30

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-123543 | Tier 2 unauthenticated DoS in OpenAM blocks authentication and session validation, directly impacting Digital Identity infrastructure availability. | OpenAM operators: A Tier 2 unauthenticated DoS in OpenAM (<16.1.4) can exhaust server resources and halt authentication for all downstream apps. Patch to 16.1.4 or enforce reverse proxy limits immediately to protect your IdP availability. |
| 5 | 2 | CVE-2026-123545 | Core Digital Identity impact: CSRF in OpenAM's OAuth 2.0 device flow enables silent token theft and account takeover in public-facing IdAM deployments. | OpenAM operators: A CSRF flaw in the OAuth 2.0 device flow could let attackers silently steal access tokens if 'skip consent' is enabled. Patch to 16.1.4 or disable the setting to protect your identity infrastructure. |
| 5 | 2 | CVE-2026-123549 | Critical privilege escalation in OpenAM IdAM platform impacts authentication, authorization, and SSO/OIDC federation configurations, directly affecting Digital Identity infrastructure. | OpenAM deployments with self-registration enabled face critical privilege escalation risks, allowing attackers to hijack enterprise SSO and OAuth2 federation settings. Patching or disabling self-service registration is essential to protect digital identity infrastructure. |
| 5 | 2 | CVE-2026-123550 | Critical SAML authentication bypass in OpenAM IdAM platform enables session forgery and admin takeover, directly impacting Digital Identity and SSO infrastructure. | OpenAM deployments face a critical SAML bypass risk allowing attackers to forge sessions and hijack admin accounts. Patch immediately to protect your digital identity and SSO infrastructure. |
| 5 | 2 | CVE-2026-123551 | Compromises core IdAM session tokens and authentication controls in widely deployed government and enterprise digital identity platforms. | A critical flaw in OpenAM allows unauthenticated attackers to passively harvest live session tokens via a WebSocket bypass, threatening the authentication backbone of government and enterprise SSO deployments. Patching and network segmentation are essential to protect digital identity infrastructure. |
| 5 | 2 | CVE-2026-124444 | Healthcare sector: SQL injection in widely deployed open-source EHR (OpenEMR) patient portal exposes PHI and staff credentials, impacting clinical data confidentiality and HIPAA compliance. | Healthcare digital infrastructure alert: A Tier 2 SQL injection in OpenEMR's patient portal allows authenticated users to extract protected health information and staff password hashes. Clinics and hospitals should prioritize patching to 8.4.0 to safeguard PHI and maintain HIPAA compliance. |
| 5 | 2 | CVE-2026-124445 | Critical authentication flaw in OpenEMR patient portal enables token replay and PIN brute-forcing, exposing Protected Health Information (PHI) and impacting healthcare EHR deployments. | Healthcare EHR systems face a critical authentication flaw in OpenEMR patient portals, allowing token replay and PIN brute-forcing that could expose sensitive patient data. Organizations relying on OpenEMR should prioritize patching to version 8.4.0 to safeguard PHI and maintain HIPAA compliance. |
| 5 | 2 | CVE-2026-124450 | Healthcare sector: Critical RCE and PHI exposure in OpenEMR EHR platform via broken access control in fax module. | Healthcare DPI alert: OpenEMR vulnerability (CVE-2026-124450) allows low-privilege users to achieve RCE and steal database credentials, risking massive PHI breaches. Patch to 8.3.0+ immediately. |
| 5 | 2 | CVE-2026-124455 | Tier 2 IDOR in OpenEMR EHR allows authenticated patients to access other patients' PHI, impacting Healthcare sector compliance and data privacy. | Healthcare DPI Alert: CVE-2026-124455 exposes a critical IDOR flaw in OpenEMR patient portals, risking mass PHI leaks and HIPAA violations for clinics and hospitals. Upgrade to 8.3.0+ immediately to secure patient data. |
| 5 | 2 | CVE-2026-124458 | Authorization bypass in OpenEMR FHIR API exposes staff PII, directly impacting Healthcare DPI sector patient portals and clinical delivery infrastructure. | Healthcare DPI alert: A TIER 2 vulnerability in OpenEMR's FHIR API allows patient-scoped tokens to bypass compartment controls and harvest full staff demographics. Health systems should patch to v8.4.0 immediately to protect personnel privacy and block downstream phishing campaigns. |
| 5 | 2 | CVE-2026-124460 | Directly impacts the Healthcare sector by exposing Protected Health Information (PHI) in OpenEMR, a widely deployed EHR system used by clinics and hospitals. | Healthcare providers running OpenEMR face a critical HIPAA risk: an IDOR flaw in patient portals allows authenticated users to access other patients' SSNs and sensitive demographic data. Patch to 8.3.0 immediately to protect PHI and avoid regulatory fallout. |
| 5 | 2 | CVE-2026-124462 | Healthcare sector: Authenticated IDOR in OpenEMR patient portal allows cross-patient PHI exfiltration, impacting clinical data confidentiality and HIPAA compliance. | OpenEMR patient portals contain an authenticated IDOR vulnerability enabling cross-patient PHI access via a case-sensitivity bypass. Healthcare organizations should prioritize patching to v8.3.0 to safeguard patient records and ensure HIPAA compliance. |
| 5 | 2 | CVE-2026-124468 | Tier 2 SQL injection in OpenEMR EHR system exposes protected health information (PHI) and clinical data, directly impacting healthcare digital infrastructure. | Healthcare CISOs and IT teams: OpenEMR's REST API has a critical SQLi flaw (CVE-2026-124468) that can leak patient records and credentials. Ensure your EHR deployments are patched to 8.3.0+ or disable the API if unused. |
| 5 | 2 | CVE-2026-124470 | Healthcare sector: BOLA in OpenEMR patient portal allows authenticated users to extract sensitive clinical records and PHI across the database. | Open-source EMR systems power clinics worldwide, but a BOLA flaw in OpenEMR's patient portal lets authenticated users scrape sensitive medical records. Healthcare providers should patch to 8.3.0 immediately to protect patient privacy. |
| 5 | 2 | CVE-2026-124473 | Healthcare sector: IDOR in OpenEMR EHR allows authenticated users to overwrite clinical SOAP notes and reassign patient IDs, compromising patient record integrity. | OpenEMR users: A TIER 2 IDOR flaw lets authenticated staff hijack clinical SOAP notes and reassign patient IDs. Upgrade to 8.3.0 to protect patient record integrity and prevent clinical data manipulation. |
| 5 | 2 | CVE-2026-124480 | Healthcare sector: Authorization bypass in OpenEMR's FHIR API enables mass PHI exfiltration, impacting clinical data privacy and HIPAA/GDPR compliance. | OpenEMR users: A TIER 2 authorization bypass in the FHIR API could expose cross-patient PHI. Ensure the API is disabled if unused and patch to v8.4.0+ to protect clinical data. |
| 5 | 2 | CVE-2026-124484 | Healthcare sector: OpenEMR EHR missing authorization allows authenticated users to bypass patient isolation, risking massive PHI breaches and HIPAA violations. | OpenEMR users: A TIER 2 missing authorization flaw in versions < 8.4.0 lets authenticated staff bypass patient isolation, risking cross-patient PHI exfiltration and HIPAA breaches. Patch to 8.4.0 immediately. |
| 5 | 2 | CVE-2026-124485 | Tier 2 authorization bypass in OpenEMR patient portals enables cross-patient PHI exfiltration, directly impacting Healthcare sector data protection and regulatory compliance. | Healthcare DPI alert: A Tier 2 flaw in OpenEMR patient portals lets authenticated users bypass scoping filters and pull other patients' records. Clinics and health systems should prioritize patching to 8.3.0 to prevent cross-patient PHI breaches and regulatory fallout. |
| 5 | 2 | CVE-2026-124490 | Critical path traversal in OpenEMR EHR system enables arbitrary file read/write and potential RCE, directly threatening healthcare data confidentiality and clinical service availability. | Healthcare providers running OpenEMR must patch immediately: a critical path traversal flaw in the fax module allows authenticated attackers to exfiltrate patient records or deploy web shells. Prompt upgrades to v8.3.0+ are essential to protect clinical data infrastructure. |
| 4 | 2 | CVE-2026-123586 | Foundational DNS infrastructure vulnerability impacting availability across all DPI sectors via query amplification DoS. | DNS resolvers power every digital public service. This TIER 2 flaw in Hickory DNS shows how cyclic referrals can trigger amplification loops, stressing the foundational naming layer that government, finance, and healthcare rely on. Patch to 0.26.2+ to keep resolution stable. |
| 4 | 2 | CVE-2026-123607 | Foundational DNS infrastructure vulnerability; DoS in DNSSEC validation cascades across all public and regulated digital services relying on name resolution. | DNS is the backbone of digital public infrastructure. A DoS in Hickory DNS's DNSSEC validation could cascade across government, finance, and healthcare services. Patch or disable DNSSEC temporarily to maintain availability. |
| 4 | 2 | CVE-2026-123608 | Foundational DNS infrastructure underpinning public-facing digital services across government, finance, and healthcare sectors. | Unauthenticated DoS in Hickory DNS could disrupt public-facing resolvers, threatening availability for critical digital services. Patch to v0.26.1 recommended. |
| 4 | 2 | CVE-2026-124447 | TIER 2 IDOR in OpenEMR patient portal enables cross-patient data access/modification, directly impacting healthcare digital infrastructure and HIPAA compliance. | Healthcare systems running OpenEMR must patch to 8.3.0 immediately. This TIER 2 IDOR flaw lets authenticated patients hijack and alter other patients' medical records, posing severe privacy and integrity risks to clinical workflows. |
| 4 | 2 | CVE-2026-124464 | Healthcare sector: Authorization bypass in widely deployed open-source EHR (OpenEMR) enables cross-patient PHI exposure, impacting public health infrastructure and HIPAA/GDPR compliance. | A TIER 2 flaw in OpenEMR’s FHIR API allows compromised patient tokens to bypass compartment isolation and access other patients’ clinical data. Healthcare providers relying on open-source EHRs must patch to 8.4.0 to protect PHI and maintain regulatory compliance. |
| 4 | 2 | CVE-2026-124466 | Unauthenticated SSRF in widely deployed open-source EHR system OpenEMR, impacting healthcare clinical data infrastructure and patient management workflows. | Unauthenticated SSRF in OpenEMR (CVE-2026-124466) allows attackers to probe internal healthcare networks and steal cloud credentials via OAuth2 misconfiguration. Healthcare providers should patch to 8.4.0+ and restrict egress traffic immediately. |
| 4 | 2 | CVE-2026-124467 | Healthcare sector: RCE in widely deployed open-source EHR (OpenEMR) threatens patient data confidentiality and clinical service availability. | Healthcare providers running OpenEMR should patch immediately: a chained LFI and file upload flaw enables remote code execution and potential PHI exfiltration. While it requires authentication and a specific module, the public PoC makes it a priority for clinical infrastructure. |
| 4 | 2 | CVE-2026-124475 | Healthcare sector: IDOR in OpenEMR patient portal allows authenticated users to tamper with other patients' medical notifications and consent flags, impacting clinical safety and PHI. | Open-source EMR systems power many public clinics worldwide. This TIER 2 IDOR in OpenEMR's patient portal lets attackers hijack medical alerts and consent flags, posing direct clinical safety and HIPAA risks. Patch to 8.3.0 immediately. |
| 4 | 2 | CVE-2026-124476 | Impacts Healthcare and Finance sectors via IDOR in OpenEMR's patient portal, enabling authenticated users to manipulate billing records and payment audit logs in clinical environments. | Healthcare providers using OpenEMR should patch immediately: an IDOR in the patient payment portal lets authenticated users forge billing records and manipulate payment audits, directly threatening clinical financial integrity and compliance. |
| 4 | 2 | CVE-2026-124481 | Healthcare and Finance relevance: compromises patient billing integrity and payment processing in regulated OpenEMR clinical deployments. | Healthcare providers using OpenEMR must patch immediately to prevent authenticated patients from tampering with payment gateways and falsifying billing records. This TIER 2 flaw highlights the critical need for server-side validation in clinical financial workflows. |
| 3 | 2 | CVE-2026-123587 | Core DNSSEC validation bypass in Hickory DNS affects foundational internet naming infrastructure critical to secure public and regulated digital services. | DNSSEC integrity is the bedrock of secure public internet services. This Tier 2 flaw in Hickory DNS allows forged nonexistence proofs, reminding DPI operators to prioritize resolver hardening and upstream validation. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-101117.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105467.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107330.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107331.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110273.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114464.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-117545.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118904.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123528.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123534.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123538.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123542.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123562.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123563.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123564.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123566.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123569.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123570.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123573.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123574.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123575.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123576.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123584.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123588.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123591.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123592.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123595.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123596.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123601.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123602.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123604.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123606.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123615.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124328.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124428.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124432.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124433.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124436.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124440.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124441.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124446.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124448.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124449.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124453.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124456.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124457.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124459.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124461.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124463.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124465.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124469.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124471.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124472.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124477.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124478.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124479.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124482.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124483.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124486.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124487.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124488.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124489.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124501.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124553.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17466.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18893.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19133.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-6715.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-8639.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-9764.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97677.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-96146.md` — heuristic TIER 3/4
