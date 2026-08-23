# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-08-23 10:38:21Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-08-18`
- **Included count:** 39

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-15571 | Keycloak SSO account takeover via predictable CSRF hash impacts Digital Identity infrastructure and enterprise authentication gateways. | Keycloak users face account takeover risks via a legacy account-linking flaw that bypasses CSRF protections. Patching or disabling the endpoint is critical for protecting enterprise SSO and digital identity ecosystems. |
| 5 | 2 | CVE-2026-18963 | Critical unauthenticated account takeover in Keycloak, a foundational enterprise and public-sector Identity and Access Management (IdAM) platform. | Unauthenticated attackers can bypass email verification in Keycloak's password reset flow, enabling full account takeover. Public-sector and enterprise IdAM teams should disable the 'Forgot password' feature or patch immediately to protect digital identity infrastructure. |
| 5 | 2 | CVE-2026-21582 | Core enterprise IdAM platform (Atlassian Crowd) with unauthenticated user impersonation, directly compromising authentication and session management for digital identity services. | Unauthenticated user impersonation in Atlassian Crowd Data Center threatens the foundational trust layer of enterprise identity systems. Patch immediately to protect centralized IdAM deployments from lateral movement and credential access. |
| 5 | 2 | CVE-2026-57580 | Digital Identity: SAML federation flaw in authentik enables persistent account takeover via XML comment injection in NameID matching. | Identity providers relying on SAML federation must patch authentik immediately. A clever XML comment injection trick can hijack user accounts by truncating NameIDs, bypassing signature validation. |
| 5 | 2 | CVE-2026-60914 | Core enterprise LDAP directory service with unauthenticated remote access to identity data, directly impacting the Digital Identity sector and IdAM infrastructure. | Unauthenticated LDAP flaws in core directory services like Oracle Unified Directory pose a direct threat to Digital Identity infrastructure. Even when deployed internally, unpatched instances can expose entire credential stores and organizational structures, making immediate patching and network segmentation critical for DPI resilience. |
| 5 | 2 | CVE-2026-61574 | Digital Identity sector: Authorization bypass in authentik IdAM exposes stored RDP/SSH/VNC credentials and enables lateral movement from public-facing identity providers. | Public-facing identity providers face a critical risk: CVE-2026-61574 in authentik allows authenticated users to dump stored remote access credentials and bypass authorization boundaries. Organizations relying on open-source IdAM must patch immediately and rotate exposed RDP/SSH/VNC secrets to prevent lateral movement. |
| 5 | 2 | CVE-2026-70721 | Unauthenticated access to critical financial data in Oracle Hyperion, a core EPM suite with high relevance to Finance and Government sectors. | CVE-2026-70721 allows unauthenticated access to sensitive financial data in Oracle Hyperion. Though typically internal, this TIER 2 vulnerability poses significant lateral movement risks for Finance and Government digital infrastructure. |
| 5 | 2 | CVE-2026-70745 | Critical unauthenticated RCE in Oracle Hyperion Financial Reporting directly impacts enterprise financial consolidation, regulatory compliance, and fiscal data integrity. | Oracle Hyperion Financial Reporting faces a critical unauthenticated vulnerability (CVE-2026-70745) enabling full system takeover. Finance teams must prioritize patching and network segmentation to protect sensitive fiscal data and consolidation integrity. |
| 5 | 2 | CVE-2026-70905 | Directly compromises enterprise SAML-based identity gateways, threatening authentication and access control for federated digital services. | Unauthenticated RCE in Oracle Access Manager’s SAML agent exposes a critical gap in enterprise identity perimeters. Organizations relying on federated authentication should prioritize patching and restrict public-facing SAML endpoints immediately. |
| 4 | 2 | CVE-2026-60393 | Unauthenticated data exposure in Oracle Hyperion EPM's Lifecycle Management component risks sensitive financial planning and budgeting data in regulated finance and government sectors. | Financial institutions and government finance departments relying on Oracle Hyperion EPM should prioritize patching CVE-2026-60393. This unauthenticated vulnerability exposes critical budgeting and financial planning data to internal network attackers, highlighting the need for strict segmentation and prompt CSPU deployment. |
| 4 | 2 | CVE-2026-60977 | Critical unauthenticated RCE in Oracle WebLogic Server, a foundational middleware explicitly underpinning Finance, Government, and Healthcare digital public infrastructure. | Unauthenticated RCE (CVSS 9.8) in Oracle WebLogic Server demands immediate attention for public sector and regulated enterprises. While typically internal-facing, exposed or laterally reachable instances risk full server takeover—patch via August CSPU and lock down RMI ports now. |
| 4 | 2 | CVE-2026-62541 | Finance sector: Critical unauthenticated RCE in Oracle Hyperion EPM suite risks full compromise of financial planning, budgeting, and regulatory reporting data. | A critical unauthenticated vulnerability in Oracle Hyperion (CVE-2026-62541) allows full system takeover of enterprise financial planning platforms. Organizations relying on Hyperion for budgeting and regulatory reporting must prioritize patching to prevent lateral movement and data integrity breaches. |
| 4 | 2 | CVE-2026-70741 | Critical unauthenticated RMI flaw in Oracle Hyperion Financial Reporting enables direct manipulation of sensitive financial data and regulatory filings, posing high risk to enterprise and national economic infrastructure. | Unauthenticated access to core financial reporting systems can bypass internal controls and compromise regulatory data integrity. This TIER 2 flaw in Oracle Hyperion highlights the need for strict network segmentation and RMI hardening in regulated finance environments. |
| 4 | 2 | CVE-2026-70752 | Unauthenticated data access in Oracle Hyperion Financial Reporting exposes critical financial data, directly impacting the Finance DPI sector. | Financial institutions and regulated enterprises relying on Oracle Hyperion for reporting must patch CVE-2026-70752 immediately. This unauthenticated flaw allows internal network attackers to extract sensitive financial data without credentials, highlighting the need for strict segmentation and timely CSPU updates. |
| 4 | 2 | CVE-2026-70777 | Unauthenticated remote data breach in Oracle E-Business Suite's iSupplier Portal directly impacts Finance and Government procurement and financial workflows deployed in internet-facing DMZs. | Oracle E-Business Suite deployments face a critical unauthenticated data exposure risk in their internet-facing iSupplier Portal. Finance and government procurement teams should prioritize patching to protect vendor financial data and contract terms from direct external access. |
| 4 | 2 | CVE-2026-70779 | Core enterprise procurement portal handling financial and supplier data widely deployed across public and commercial sectors, posing unauthenticated data integrity risks to regulated supply chains. | Unauthenticated flaws in widely deployed procurement portals like Oracle iSupplier can expose critical financial and supply chain data. For public sector and enterprise finance teams, timely patching and strict network segmentation remain essential to prevent invoice manipulation and supplier data breaches. |
| 4 | 2 | CVE-2026-70832 | Unauthenticated remote access to Oracle Hyperion Financial Management exposes critical financial consolidation and reporting data, directly impacting the Finance DPI sector. | Financial institutions and regulated enterprises relying on Oracle Hyperion for consolidation and reporting should prioritize patching CVE-2026-70832. This unauthenticated vulnerability allows attackers with internal network access to exfiltrate sensitive financial data without credentials. |
| 4 | 2 | CVE-2026-70880 | Critical unauthenticated RCE in Oracle Hyperion DRM, a core financial master data management platform widely deployed by financial institutions and public sector finance departments for regulatory reporting and data governance. | Unauthenticated RCE in Oracle Hyperion DRM (CVE-2026-70880) poses a severe risk to financial data governance and regulatory reporting infrastructure. While typically deployed internally, its CVSS 10.0 score and strategic value make it a high-priority patch target for financial institutions and public sector finance teams. |
| 4 | 2 | CVE-2026-70889 | Unauthenticated data disclosure in Oracle Hyperion DRM exposes critical financial and master data, directly impacting banking and corporate finance infrastructure. | Financial institutions relying on Oracle Hyperion DRM for master data management face unauthenticated data exposure risks. Patching and internal network segmentation are critical to protect sensitive financial records from lateral movement attacks. |
| 4 | 2 | CVE-2026-70898 | Unauthenticated master data manipulation in Oracle Hyperion DRM directly threatens financial reporting integrity and public-sector fiscal management systems. | Financial and government institutions relying on Oracle Hyperion DRM for master data management face a critical unauthenticated data integrity risk. Patching and strict network segmentation are essential to protect budget models and fiscal reporting from internal or lateral-movement attacks. |
| 4 | 2 | CVE-2026-70947 | Unauthenticated data exposure in Oracle E-Business Suite Purchasing directly impacts Finance sector operations and public-sector procurement integrity. | Unauthenticated access to core procurement data in Oracle E-Business Suite highlights why internal network segmentation and timely patching are critical for financial and public-sector ERP environments. #DPI #CyberSecurity #FinanceTech |
| 4 | 2 | CVE-2026-70952 | Unauthenticated access to critical financial planning and reporting data in Oracle Hyperion, directly impacting enterprise financial infrastructure and regulatory compliance. | Financial institutions and regulated enterprises relying on Oracle Hyperion for budgeting and reporting should prioritize patching this unauthenticated data exposure. While internal-facing by design, it offers a high-value lateral movement path for attackers targeting sensitive financial records. |
| 4 | 2 | CVE-2026-70953 | Critical unauthenticated RCE in Oracle Commerce Platform directly impacts the Finance sector by compromising payment processing, customer accounts, and PCI-DSS compliance. | Unauthenticated remote takeovers in enterprise commerce backends threaten financial operations and regulatory compliance. Organizations handling customer accounts and transactions must prioritize patching Oracle Commerce Platform to secure critical financial infrastructure. |
| 4 | 2 | CVE-2026-70954 | Unauthenticated RCE in Oracle Commerce Platform directly threatens financial transaction processing, payment gateways, and PCI-DSS compliance in enterprise e-commerce environments. | A critical unauthenticated flaw in Oracle Commerce Platform exposes internet-facing storefronts to full takeover, putting payment processing and customer financial data at immediate risk. Regulated commerce operators should prioritize the August CSPU patch and enforce strict network segmentation. |
| 4 | 2 | CVE-2026-70979 | TIER 2 unauthenticated flaw in Oracle Commerce CAS impacts financial services and regulated e-commerce platforms by threatening transactional data integrity and pricing operations. | Financial services and regulated e-commerce platforms running Oracle Commerce should prioritize patching CVE-2026-70979. This unauthenticated backend flaw can corrupt pricing data and disrupt transaction flows, making network segmentation and immediate CSPU application critical for compliance and operational resilience. |
| 4 | 2 | CVE-2026-70980 | TIER 2 unauthenticated RCE in Oracle Commerce platforms directly impacts Finance/DPI by compromising public-facing e-commerce infrastructure handling transactions, customer accounts, and payment integrations. | Critical unauthenticated RCE in Oracle Commerce (CVE-2026-70980) exposes public-facing e-commerce storefronts to full takeover. For Finance and retail DPI, this underscores the urgency of patching internet-facing transactional platforms before attackers exploit high-complexity but unauthenticated attack paths. |
| 4 | 2 | CVE-2026-70981 | TIER 2 unauthenticated flaw in Oracle Commerce backend directly impacts financial transaction integrity and digital commerce availability. | Oracle Commerce backends face a critical unauthenticated flaw (CVSS 9.1) that can corrupt transactional data or crash services. Finance and retail operators should prioritize patching and enforce strict internal network segmentation to protect digital commerce infrastructure. |
| 4 | 2 | CVE-2026-70988 | Tier 2 vulnerability in Oracle Commerce impacts Finance sector; authenticated low-privilege users can access critical financial and customer data. | Finance sector alert: Oracle Commerce platforms face a Tier 2 vulnerability (CVE-2026-70988) allowing data access via low-privilege accounts. Ensure August 2026 CSPU patching and enforce least-privilege controls to safeguard financial data. |
| 4 | 2 | CVE-2026-70997 | Enterprise e-commerce search layer handling high-volume transactions and customer accounts, directly impacting financial infrastructure and regulated digital commerce ecosystems. | Unauthenticated remote flaws in enterprise e-commerce search platforms pose immediate risks to financial infrastructure and customer data. Patching Oracle Commerce components is critical for maintaining trust in national digital commerce ecosystems. |
| 4 | 2 | CVE-2026-70998 | TIER 2 unauthenticated remote vulnerability in Oracle Commerce directly impacts the Finance sector by exposing payment processing, transaction management, and customer financial data. | An unauthenticated remote flaw in Oracle Commerce’s Endeca controller could allow attackers to read or alter critical financial and customer data in enterprise e-commerce platforms. Finance and retail operators should prioritize patching and restrict network access to protect transaction integrity. |
| 3 | 2 | CVE-2026-60971 | Unauthenticated RCE in Oracle WebLogic/WebCenter middleware, critical for regulated enterprise and government IT infrastructure. | Oracle WebLogic Server's internal T3/IIOP protocols face an unauthenticated RCE vulnerability. While typically internal-facing, this TIER 2 flaw demands immediate patching for enterprises and public sector deployments relying on Oracle Fusion Middleware. |
| 3 | 2 | CVE-2026-62633 | Critical unauthenticated bypass in widely deployed enterprise reporting middleware that accelerates lateral movement in Finance, Government, and Healthcare internal networks. | Oracle’s Reports Developer faces a critical, unauthenticated takeover flaw (CVSS 9.8) that bypasses internal authentication controls. While typically network-isolated, this TIER 2 vulnerability poses a severe lateral-movement risk for regulated sectors like Finance, Government, and Healthcare relying on internal BI reporting. |
| 3 | 2 | CVE-2026-70910 | Unauthenticated data exposure in Oracle Siebel CRM integration endpoints, widely deployed across finance, healthcare, and government enterprise environments. | Unauthenticated REST API flaws in enterprise CRM platforms pose immediate data breach risks for regulated sectors. Organizations deploying Siebel for finance, healthcare, or government services should prioritize the August CSPU and enforce strict API gateway controls. |
| 3 | 2 | CVE-2026-70977 | TIER 2 unauthenticated remote flaw in Oracle Commerce backend impacts transactional integrity and service availability in enterprise e-commerce and retail payment ecosystems (Finance sector). | Enterprise e-commerce platforms rely on robust backend search and content pipelines to maintain transactional integrity. This unauthenticated remote flaw in Oracle Commerce highlights the need for strict network segmentation and timely patching in regulated retail and finance digital infrastructure. |
| 3 | 2 | CVE-2026-70993 | Unauthenticated DoS and data modification in Oracle Commerce backend infrastructure explicitly deployed by government e-procurement portals and financial institutions. | Enterprise commerce backends like Oracle Commerce underpin critical government e-procurement and financial services. This unauthenticated TIER 2 flaw underscores the importance of network segmentation and rapid patching to safeguard public digital commerce infrastructure. |
| 2 | 2 | CVE-2026-71167 | General infrastructure Java microservices framework deployed across enterprise and government stacks, exposing public-facing APIs to unauthenticated data manipulation and partial DoS. | A critical, unauthenticated flaw in Oracle Helidon’s web server leaves internet-facing microservices vulnerable to data tampering and service degradation. Organizations running Java-based public or government-facing APIs should patch immediately to secure their digital infrastructure. |
| 2 | 2 | CVE-2026-73903 | General infrastructure microservices framework explicitly noted for deployment in government and enterprise stacks, risking unauthenticated data integrity compromise. | Unauthenticated data manipulation in Oracle Helidon microservices underscores the critical need for API gateway hardening and timely patching across government and enterprise backend deployments. |
| 2 | 2 | CVE-2026-73905 | TIER 2 critical unauthenticated RCE in Oracle Helidon, a widely deployed Java microservices framework underpinning enterprise and DPI backend web services. | Critical TIER 2 vulnerability in Oracle Helidon exposes unauthenticated remote code execution in default web server deployments. While sector-agnostic, this framework flaw demands immediate patching for any DPI or regulated enterprise relying on Java microservices for public-facing APIs. |
| 2 | 2 | CVE-2026-73928 | General infrastructure framework widely deployed in government and enterprise cloud backends; unauthenticated HTTP data manipulation risks public service integrity. | Foundational microservice frameworks like Oracle Helidon quietly power government and enterprise digital services. This unauthenticated data flaw underscores why ingress controls and rapid patching are non-negotiable for public infrastructure resilience. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-12564.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15371.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15585.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19671.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-21584.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-23933.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-24183.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-24184.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-24185.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-32657.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-45532.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48508.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48798.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50143.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50577.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50578.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-52723.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-52817.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53958.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54552.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54730.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55426.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55839.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56684.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60707.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60715.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60716.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60722.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60748.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60751.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60752.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60754.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60759.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60765.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60769.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60779.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60798.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60967.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60969.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60970.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60975.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60976.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60980.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60981.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60983.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60990.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60992.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60993.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60994.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60996.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60998.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61034.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61219.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61268.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61276.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61281.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61284.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61286.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61293.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61339.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61341.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62292.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62449.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62586.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62591.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62615.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62618.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62619.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62623.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62627.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62628.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62629.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62630.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62631.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62635.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62637.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63337.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66046.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66780.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66782.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66783.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67262.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69219.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69220.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70666.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70685.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70690.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70705.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70706.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70713.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70733.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70735.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70736.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70737.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70738.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70739.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70740.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70742.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70749.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70750.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70760.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70761.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70762.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70763.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70770.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70771.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70773.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70774.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70782.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70790.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70822.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70823.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70827.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70828.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70829.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70833.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70834.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70837.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70839.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70840.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70842.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70844.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70845.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70854.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70855.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70856.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70857.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70858.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70859.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70861.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70863.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70864.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70865.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70866.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70867.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70868.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70870.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70872.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70874.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70875.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70876.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70877.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70878.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70879.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70881.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70882.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70883.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70884.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70885.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70886.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70887.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70890.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70891.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70892.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70893.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70894.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70896.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70897.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70899.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70900.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70901.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70903.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70906.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70914.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70918.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70920.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70922.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70924.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70925.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70926.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70927.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70928.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70929.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70932.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70933.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70934.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70935.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70936.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70937.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70939.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70940.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70941.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70942.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70943.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70944.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70945.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70946.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70948.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70949.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70950.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70955.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70956.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70958.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70959.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70960.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70964.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70965.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70966.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70967.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70971.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70973.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70978.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70984.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70985.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70987.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70992.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70995.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70996.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70999.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71000.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71002.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71003.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71009.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71010.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71018.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71020.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71021.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71022.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71026.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71027.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71028.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71030.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71037.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71039.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71040.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71041.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71042.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71043.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71044.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71045.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71046.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71048.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71049.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71050.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71051.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71052.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71055.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71056.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71057.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71058.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71062.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71063.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71064.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71067.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71068.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71069.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71092.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71094.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71095.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71096.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71097.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71098.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71099.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71101.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71104.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71107.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71111.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71112.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71113.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71116.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71117.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71122.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71126.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71129.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71130.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71131.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71136.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71141.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71143.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71150.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71153.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71160.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71303.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71307.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71308.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71365.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71417.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71539.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73890.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73891.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73902.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73915.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73927.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73931.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-74038.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-74039.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-74935.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-74939.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-74941.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-74942.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-74946.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-74949.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-74953.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-74965.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-74977.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-74978.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-74979.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75625.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75778.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75840.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75842.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75843.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75844.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75846.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75851.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75852.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75853.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75855.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75874.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75897.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75898.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75914.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75915.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75924.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75935.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75936.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-70734.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-71138.md` — heuristic TIER 3/4
