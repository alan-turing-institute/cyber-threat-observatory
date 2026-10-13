# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-10-13 21:25:42Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-10-12`
- **Included count:** 15

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-109371 | Unauthenticated account lockout in ZITADEL IdAM platform impacts digital identity infrastructure and administrative access. | ZITADEL users face unauthenticated account lockout risks via a missing auth flaw in the Login V1 UI, threatening identity provider availability and integrity. |
| 5 | 2 | CVE-2026-109372 | Critical SAML authentication bypass in ZITADEL IdP enables cross-tenant account takeover, directly impacting digital identity federation and access management infrastructure. | A critical SAML callback flaw in ZITADEL (CVE-2026-109372) allows org-admins to impersonate users across different identity providers, highlighting the need for strict IdP configuration and prompt patching in digital identity ecosystems. Organizations relying on SAML federation should verify multi-provider setups and restrict administrative scopes immediately. |
| 5 | 2 | CVE-2026-109373 | Critical authentication bypass in ZITADEL IdAM platform enables unauthenticated session hijacking and MFA bypass, directly impacting Digital Identity infrastructure. | A critical flaw in the open-source ZITADEL identity platform allows attackers to bypass MFA and hijack admin sessions via forged cookies. For any organization relying on OIDC/SAML for digital public services, patching this TIER 2 vulnerability is urgent to protect citizen and enterprise access. |
| 4 | 2 | CVE-2026-103903 | General infrastructure flaw underpinning Government, Finance, and Healthcare network connectivity, enabling full administrative compromise via WinBox privilege escalation. | MikroTik RouterOS underpins connectivity across Government, Finance, and Healthcare networks, making this WinBox privilege escalation flaw a priority for infrastructure resilience. Though it requires valid low-privilege credentials, the path to full administrative control demands immediate patching in regulated environments. |
| 4 | 2 | CVE-2026-109609 | Authenticated SQLi in widely deployed ERPNext exposes core financial, payroll, and procurement data, directly impacting Finance and Government sector operations. | ERP systems like Frappe ERPNext are the backbone of public-sector and financial operations, making authenticated SQL injection risks a critical concern for data integrity. While valid credentials are required, organizations must prioritize patching and enforce MFA to protect sensitive payroll and procurement records from targeted extraction. |
| 4 | 2 | CVE-2026-109638 | SQLi in widely deployed ERPNext exposes financial, payroll, and transactional data critical to SME and public-sector operations. | ERP systems like Frappe ERPNext are the backbone of public-sector and SME financial workflows. This authenticated SQLi (CVE-2026-109638) highlights why strict input validation and MFA are non-negotiable for protecting transactional data and citizen-facing services. |
| 4 | 2 | CVE-2026-109648 | Authenticated SQLi in widely deployed ERPNext platform impacts core operational data across government, finance, and healthcare sectors. | ERP systems like ERPNext are the backbone of public and regulated sector operations. This authenticated SQLi highlights the critical need for strict access controls and prompt patching to protect sensitive citizen and financial data. |
| 4 | 2 | CVE-2026-109667 | TIER 2 privilege escalation in Frappe ERPNext enables full administrative takeover, directly threatening financial records, transaction integrity, and accounting operations critical to regulated finance and public-sector ERP deployments. | ERP systems are the backbone of financial and public-sector operations, but a single authenticated user can now bypass all permission checks in Frappe ERPNext to seize full admin control. Patching is critical to protect transaction integrity and sensitive financial data from internal or compromised account abuse. |
| 4 | 2 | CVE-2026-109674 | Authenticated SQLi in Frappe ERPNext threatens financial records and citizen service data in public-sector and financial deployments. | ERP systems power critical public finance and government procurement workflows. This authenticated SQLi in Frappe ERPNext underscores why credential hygiene and WAF tuning are essential for protecting sensitive operational data—patch to v15.98.0 or v16.6.0 now. |
| 3 | 2 | CVE-2026-109575 | Critical authentication bypass in HAProxy Data Plane API management plane, impacting foundational load-balancing infrastructure for regulated and public digital services. | A critical auth bypass in HAProxy's Data Plane API (CVE-2026-109575) allows unauthenticated takeover of load balancer management. While internal-facing, it poses a high lateral-movement risk for any enterprise or government network relying on HAProxy for traffic routing. |
| 3 | 2 | CVE-2026-109608 | General enterprise ERP infrastructure with explicit secondary relevance to Finance and Government deployments, impacting financial records and HR data in regulated/public-sector contexts. | A TIER 2 SQL injection in Frappe ERPNext highlights the persistent risk to public-sector and financial operations relying on general enterprise stacks. Agencies and regulated entities should prioritize patching and enforce strict authentication controls to protect sensitive financial and HR data. |
| 3 | 2 | CVE-2026-109631 | Tier 2 SQLi in Frappe ERPNext, a horizontal enterprise ERP frequently deployed across Finance, Government, and Healthcare sectors for core operational management. | Enterprise ERPs like Frappe ERPNext power critical workflows across regulated sectors. This Tier 2 SQLi underscores the importance of patching and enforcing least-privilege access to safeguard sensitive operational data. |
| 3 | 2 | CVE-2026-109633 | General infrastructure ERP platform with cross-sector relevance; stored XSS enables privileged account takeover impacting financial, healthcare, and government operational data. | ERP systems power critical public and regulated services. This TIER 2 stored XSS in Frappe ERPNext’s public booking module could lead to full admin account takeover, risking financial records and citizen data. Patch now to protect your operational backbone. |
| 3 | 2 | CVE-2026-41510 | Foundational WAF library bypass and memory exhaustion affecting public-facing gateways deployed across regulated and civic digital services. | A TIER 2 flaw in OWASP Coraza allows unauthenticated attackers to bypass WAF rules and exhaust proxy memory via default configurations. Critical for teams securing public-facing government, finance, and healthcare portals relying on standard reverse proxies. |
| 2 | 2 | CVE-2026-109391 | TIER 2 insecure deserialization in Square Squash crash reporting tool, explicitly tied to Finance sector as supporting infrastructure for payment/banking application reliability. | Even supporting developer toolchains can become critical attack surfaces: CVE-2026-109391 shows how an exposed crash-reporting API can lead to unauthenticated RCE. Finance and regulated sectors should audit third-party exception management systems and enforce strict API authentication. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2020-37280.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-71432.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102627.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103060.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103902.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104355.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105407.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105408.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105409.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105410.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105411.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105412.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105464.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105465.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108094.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108361.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108798.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108982.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108985.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109166.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109168.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109169.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109170.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109185.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109186.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109187.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109199.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109201.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109202.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109203.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109205.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109229.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109237.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109238.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109242.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109245.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109246.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109250.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109257.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109297.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109299.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109311.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109333.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109334.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109335.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109338.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109341.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109343.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109346.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109353.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109357.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109358.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109359.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109360.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109361.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109399.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109560.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109563.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109567.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109569.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109604.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109610.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109612.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109613.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109614.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109615.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109616.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109617.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109621.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109624.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109625.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109626.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109627.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109628.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109636.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109637.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109639.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109640.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109643.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109644.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109645.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109646.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109647.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109649.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109650.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109652.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109653.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109655.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109656.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109658.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109659.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109660.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109661.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109663.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109666.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109671.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109672.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109673.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12613.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17475.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18166.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18390.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18513.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18517.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18529.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18537.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-1907.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19620.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19622.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-52903.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59976.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59977.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65954.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75061.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75095.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75782.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75881.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75888.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78355.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78357.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78673.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82096.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82101.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82103.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82108.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82110.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83535.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84312.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84313.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84314.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84318.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84360.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84418.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85457.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85947.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85949.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85950.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85951.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85952.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85953.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85954.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85955.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85956.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85957.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85958.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85959.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85960.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85961.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85962.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85963.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85964.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85965.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85966.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85968.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85969.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85970.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85971.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85972.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85973.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85974.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85975.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90912.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90920.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-9191.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92876.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93695.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93886.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93891.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93892.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95837.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96012.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96119.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96261.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96262.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96263.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96264.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96265.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96266.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-90911.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-90921.md` — heuristic TIER 3/4
