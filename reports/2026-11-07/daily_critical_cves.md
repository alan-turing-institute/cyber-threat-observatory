# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-11-08 14:36:34Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-11-07`
- **Included count:** 41

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-120984 | Critical RCE in Keycloak, a foundational IdAM/SSO platform, directly threatens authentication and session management for government, finance, and healthcare digital identity services. | A critical RCE in Keycloak (CVE-2026-120984) underscores the cascading risks of compromised IdAM credentials, threatening the authentication backbone of public and regulated digital services. While exploitation requires high-privilege access, the impact on SSO-dependent applications makes immediate patching vital for DPI resilience. |
| 5 | 2 | CVE-2026-16712 | Cross-tenant authorization bypass in IBM API Connect threatens data isolation guarantees critical to digital identity, government, and financial API ecosystems. | Multi-tenant API gateways underpin modern digital public services. This TIER 2 flaw in IBM API Connect shows how insufficient tenant-boundary validation can breach isolation controls, risking compliance across government and finance sectors. |
| 5 | 2 | CVE-2026-16717 | TIER 2 broken object-level authorization in IBM API Connect directly impacts Government, Finance, and Healthcare sectors by risking unauthorized access to citizen-facing APIs, payment gateways, and health data exchanges. | API gateways are the front door for digital public services. This TIER 2 flaw in IBM API Connect could let authenticated users bypass authorization controls, exposing sensitive citizen, financial, and health data. Patching and strict RBAC are critical for regulated environments. |
| 5 | 2 | CVE-2026-17291 | Tier 2 open redirect in IBM API Connect OAuth 2.0 flow enables account takeover, directly impacting Digital Identity authentication and session security. | IBM API Connect users face account takeover risks via OAuth 2.0 open redirects. Patching is critical to protect digital identity flows and prevent credential theft in enterprise API gateways. |
| 5 | 2 | CVE-2026-17295 | Foundational API gateway infrastructure explicitly tied to Finance, Government, Healthcare, and Digital Identity sectors for managing public-facing and internal digital services. | IBM API Connect's authenticated path traversal (CVE-2026-17295) underscores the critical need for strict credential hygiene and WAF rules in enterprise API gateways. As foundational infrastructure for banking, civic tech, and health data exchange, timely patching and monitoring are essential for DPI resilience. |
| 4 | 2 | CVE-2026-123218 | Privilege escalation in IBM Aspera Faspex, a critical secure file-transfer platform explicitly deployed across Healthcare, Finance, and Government data exchange networks. | Secure file transfer underpins regulated data exchange, but a compromised account in IBM Aspera Faspex can now escalate to full admin control. Healthcare, finance, and government agencies must patch immediately and enforce MFA to safeguard sensitive cross-sector data flows. |
| 4 | 2 | CVE-2026-16716 | Impacts Digital Identity sector via token assignment bypass in IBM API Connect, a core platform for OAuth/OIDC and identity-aware API gateways in public and regulated environments. | Digital public infrastructure relies on secure API gateways to federate identity and exchange data. This TIER 2 token manipulation flaw in IBM API Connect underscores the critical need for rigorous IAM controls and timely patching across government and finance deployments. |
| 4 | 2 | CVE-2026-16720 | Critical authentication bypass in enterprise API management enables token theft and identity assumption, directly impacting Digital Identity infrastructure in government, finance, and healthcare sectors. | Enterprise API gateways are the backbone of secure digital services, but a critical authentication flaw in IBM API Connect could let attackers steal valid tokens and impersonate users. For DPI operators in government and finance, patching and hardening directory integrations is now a priority. |
| 4 | 2 | CVE-2026-16920 | Foundational API gateway middleware explicitly deployed across Finance, Government, and Healthcare to secure public-facing digital services. | IBM API Connect’s confused deputy flaw (CVE-2026-16920) threatens the API gateways securing public-facing services across finance, government, and healthcare. While it requires valid credentials, the CVSS 9.9 impact underscores the need for rapid patching and strict credential hygiene in regulated API ecosystems. |
| 4 | 2 | CVE-2026-17049 | Critical authorization bypass in IBM API Connect, a foundational middleware explicitly deployed across Finance, Government, and Healthcare to secure citizen, banking, and clinical data exchanges. | API gateways are the front doors for modern digital public services. This critical authorization bypass in IBM API Connect highlights why strict credential hygiene and rapid patching are non-negotiable for protecting citizen, financial, and healthcare data flows. |
| 4 | 2 | CVE-2026-17131 | Critical unauthenticated SSRF in IBM API Connect, a foundational enterprise API gateway widely deployed at the edge of regulated public and financial digital services. | Unauthenticated SSRF in IBM API Connect (CVSS 9.3) exposes a critical edge risk for DPI and regulated enterprises. As API gateways increasingly power citizen and financial services, securing outbound traffic and applying patches is essential to prevent internal network pivoting. |
| 4 | 2 | CVE-2026-17132 | Critical SQLi in IBM API Connect, a foundational enterprise API gateway explicitly supporting regulated Finance, Government, and Healthcare digital services. | IBM API Connect gateways face a critical authenticated SQL injection risk (CVE-2026-17132). For public sector and regulated enterprises relying on API-first architectures, patching to v12.1.1.3 and enforcing strict credential controls is essential to protect citizen and financial data pipelines. |
| 4 | 2 | CVE-2026-17187 | Enterprise API gateway SSRF impacting Finance, Government, and Healthcare digital service exposure; requires patching to protect citizen-facing and regulated API endpoints. | IBM API Connect SSRF (CVE-2026-17187) highlights the need for strict egress filtering and credential hygiene in enterprise API gateways. Critical for Finance, Government, and Healthcare deployments exposing digital services to the public. |
| 4 | 2 | CVE-2026-17278 | Critical authentication bypass in IBM API Connect, a foundational API management layer explicitly tied to Finance, Healthcare, Government, and Digital Identity sectors for secure data exchange. | IBM API Connect’s critical auth bypass (CVE-2026-17278) exposes API catalogs and runtime configs without credentials, threatening the control plane of cross-sector digital public infrastructure. Patch to v12.1.1.3 and enforce strict network segmentation on management portals. |
| 4 | 2 | CVE-2026-17280 | Targets unauthenticated brute-force on IBM API Connect login endpoints, directly impacting Digital Identity and enterprise API gateway authentication flows. | IBM API Connect’s lack of default rate-limiting on login endpoints exposes enterprise API gateways to credential stuffing, underscoring the need for MFA and WAF controls in digital identity infrastructure. |
| 4 | 2 | CVE-2026-17290 | Directly impacts Digital Identity infrastructure by allowing forged identity tokens and unauthorized account creation in enterprise API gateways. | Enterprise API gateways managing public digital services must patch IBM API Connect to prevent attackers from forging identity tokens and creating unauthorized accounts. A critical reminder to enforce strict token validation and MFA in your IdAM stack. |
| 4 | 2 | CVE-2026-17301 | Critical unauthenticated bypass in IBM API Connect undermines cryptographic signature validation, directly impacting Digital Identity and access controls for public-facing enterprise APIs. | Enterprise API gateways are the front door for digital public services. This critical, unauthenticated bypass in IBM API Connect highlights why cryptographic signature validation must be rigorously enforced to protect citizen and financial data. |
| 4 | 2 | CVE-2026-17313 | Critical unauthenticated bypass in IBM API Connect, a foundational gateway heavily deployed across Finance, Government, and Healthcare for public-facing citizen and payment APIs. | IBM API Connect’s internet-facing gateway now faces a critical unauthenticated bypass (CVE-2026-17313), threatening the API infrastructure that powers public citizen services, financial transactions, and health data exchange. Patching and network segmentation are urgent for any regulated organization relying on this middleware. |
| 4 | 2 | CVE-2026-17316 | Unauthenticated SSRF in IBM API Connect, a foundational API gateway explicitly deployed across Finance, Government, and Healthcare sectors for managing public-facing digital services. | API gateways are the front door for modern digital public services. This unauthenticated SSRF in IBM API Connect highlights why egress filtering and strict network segmentation remain critical for Finance, Government, and Healthcare deployments. Patch to 12.1.1.3+ and review outbound traffic rules. |
| 4 | 2 | CVE-2026-17338 | Core API gateway infrastructure widely deployed in Finance, Government, and Healthcare to route sensitive citizen, patient, and financial data; broken authorization risks unauthorized data disclosure. | IBM API Connect’s broken object-level authorization (CVE-2026-17338) highlights a critical risk for regulated sectors relying on API gateways to expose citizen, patient, and financial services. While authentication limits mass exploitation, organizations in Finance, Government, and Healthcare must patch immediately and enforce strict token rotation to protect sensitive data exchanges. |
| 4 | 2 | CVE-2026-17340 | Critical unauthenticated RCE in IBM API Connect Gateway, a foundational infrastructure component widely deployed for Finance, Government, and Healthcare digital public services and API gateways. | Unauthenticated RCE in IBM API Connect (CVE-2026-17340) threatens the edge layer of digital public infrastructure. With API gateways powering citizen services, banking APIs, and health data exchange, this TIER 2 flaw demands immediate patching and WAF hardening across regulated sectors. |
| 4 | 2 | CVE-2026-17342 | Critical authenticated RCE in IBM API Connect, a foundational gateway widely deployed for Finance, Government, and Healthcare digital services. | IBM API Connect faces a critical authenticated RCE (CVE-2026-17342) that could compromise edge gateways routing sensitive Finance, Government, and Healthcare APIs. Patch immediately and enforce strict access controls to protect public-facing digital infrastructure. |
| 4 | 2 | CVE-2026-17343 | Authorization bypass in IBM API Connect directly impacts Finance and Government sectors by compromising secure API gateways used for digital banking, payment routing, and citizen-facing public services. | Enterprise API gateways are the backbone of modern digital banking and government services. This TIER 2 authorization bypass in IBM API Connect highlights why strict RBAC and timely patching are non-negotiable for protecting citizen and financial data. |
| 4 | 2 | CVE-2026-17356 | Enterprise API management platform explicitly tied to government and finance digital services; hard-coded crypto key risks sensitive data exposure in regulated API gateways. | IBM API Connect’s hard-coded cryptographic key (CVE-2026-17356) poses a Tier 2 risk to government and finance API gateways. While requiring local access, the flaw underscores the need for strict access controls and timely patching in regulated digital service deployments. |
| 4 | 2 | CVE-2026-17359 | Foundational API gateway infrastructure widely deployed across Finance, Government, and Healthcare digital services; compromise enables edge takeover and downstream service disruption. | IBM API Connect RCE (CVE-2026-17359) highlights the critical need for strict IAM and network segmentation at the API edge. While authentication is required, compromised credentials in this widely deployed enterprise gateway can lead to full infrastructure takeover across regulated sectors. Patch and enforce MFA/RBAC now. |
| 4 | 2 | CVE-2026-17360 | Critical hard-coded credentials in IBM API Connect, foundational middleware explicitly deployed across Finance, Government, and Healthcare API ecosystems. | Enterprise API gateways are the backbone of modern digital public services, but hard-coded admin credentials in IBM API Connect (CVE-2026-17360) expose Finance, Government, and Healthcare deployments to trivial takeover. Patch to v12.1.1.3 and enforce strict network segmentation on management planes immediately. |
| 4 | 2 | CVE-2026-17392 | Breaks multi-tenant isolation in IBM API Connect, a foundational gateway widely deployed across Finance, Government, and Healthcare for secure API exposure. | Multi-tenant API gateways are the backbone of modern digital public services. This LDAP injection flaw in IBM API Connect could let attackers bypass tenant boundaries and seize admin control across Finance, Government, and Healthcare deployments. Patching and strict network segmentation are critical. |
| 4 | 2 | CVE-2026-17397 | SSRF in IBM API Connect, a foundational API gateway widely deployed across Finance, Government, and Healthcare to expose regulated digital services, enabling internal pivoting and metadata harvesting. | API gateways are the front door for modern digital public services. This authenticated SSRF in IBM API Connect highlights how a single gateway flaw can become a pivot point into internal Finance, Government, or Healthcare networks—prompt patching and strict egress controls are essential. |
| 4 | 2 | CVE-2026-18838 | Critical authentication bypass in IBM API Connect, a foundational edge gateway explicitly deployed across Finance, Government, and Healthcare to expose regulated digital services. | Unauthenticated attackers can bypass identity controls and hijack API configurations in IBM API Connect. For Finance, Government, and Healthcare sectors relying on this gateway for public-facing digital services, patching to v12.1.1.3 is urgent to prevent service disruption and data exposure. |
| 3 | 2 | CVE-2026-123990 | SQLi in self-hosted BI platform widely deployed in government and public-sector infrastructure for internal reporting and citizen service dashboards. | A public exploit for a SQL injection in DataEase underscores the need for strict patching and network segmentation in government BI deployments. Public agencies should upgrade to v3.2.0 to protect internal reporting and citizen-facing analytics. |
| 3 | 2 | CVE-2026-17066 | Critical multi-tenant authorization bypass in IBM API Connect, a foundational gateway widely deployed across regulated finance, healthcare, and government API ecosystems. | Multi-tenant isolation failures in enterprise API gateways can cascade into cross-sector data breaches. IBM API Connect’s CVE-2026-17066 highlights why strict tenant boundaries and high-privilege credential controls are non-negotiable for public and regulated digital services. |
| 3 | 2 | CVE-2026-17117 | Critical RCE in IBM API Connect, a foundational middleware platform widely deployed to secure and manage APIs for government, finance, and healthcare digital services. | API gateways are the front door for modern digital public services. This critical RCE in IBM API Connect highlights why strict access controls and rapid patching are non-negotiable for any regulated API infrastructure. |
| 3 | 2 | CVE-2026-17158 | Critical privilege escalation in enterprise API gateways that serve as foundational infrastructure for regulated and public digital service integrations. | API gateways are the backbone of modern digital public infrastructure. This Tier 2 flaw in IBM API Connect underscores why strict access controls and rapid patching are non-negotiable for any organization exposing citizen or financial services online. |
| 3 | 2 | CVE-2026-17329 | Critical unauthenticated SSRF in a public-facing API gateway, foundational infrastructure widely deployed across government, finance, and healthcare for regulated API orchestration. | Unauthenticated SSRF in IBM API Connect exposes a critical pivot point for attackers targeting public-facing digital services. Organizations running citizen or financial APIs should prioritize patching to v12.1.1.3 and enforce strict egress filtering. |
| 3 | 2 | CVE-2026-17358 | TIER 2 tenant isolation bypass in IBM API Connect impacts foundational enterprise API gateways deployed across regulated and public digital service environments. | API gateways form the critical middleware layer for modern digital public infrastructure. This TIER 2 vulnerability in IBM API Connect highlights how tenant isolation failures can enable cross-tenant data breaches, reinforcing the need for rigorous API security and segmentation in multi-tenant government and enterprise deployments. |
| 3 | 2 | CVE-2026-17384 | Tier 2 SSRF in IBM API Connect, foundational enterprise middleware critical for secure API delivery in regulated and public-sector environments. | API gateways power the backbone of digital public services. This Tier 2 SSRF in IBM API Connect underscores the importance of egress filtering and strict credential management in enterprise API layers. |
| 3 | 2 | CVE-2026-17406 | TIER 2 SSRF in IBM API Connect, a foundational enterprise API gateway critical for securing public-facing and regulated sector digital services. | API gateways sit at the edge of every major digital service. This TIER 2 SSRF in IBM API Connect underscores the need for strict egress controls and credential management to prevent internal network exposure in regulated environments. |
| 3 | 2 | CVE-2026-17408 | Foundational API gateway middleware widely deployed in Finance and Government digital services, where unauthenticated RCE could disrupt regulated public-facing APIs. | IBM API Connect’s critical OS command injection flaw (CVE-2026-17408) highlights the risk to foundational API gateways underpinning Finance and Government digital services. Patching and WAF hardening are essential to protect regulated public-facing endpoints from unauthenticated RCE. |
| 2 | 2 | CVE-2026-17336 | TIER 2 SQL injection in IBM API Connect, general infrastructure widely deployed across regulated sectors for backend integration and data exchange. | Critical SQL injection in IBM API Connect (TIER 2) requires authentication but poses high data exfiltration risks for regulated organizations relying on enterprise API gateways. Prioritize patching to v12.1.1.3 and enforce least-privilege database controls. |
| 2 | 2 | CVE-2026-17352 | TIER 2 SSRF in enterprise API gateway; impacts foundational infrastructure used to expose regulated/public digital services. | API gateways power the front door of modern digital public infrastructure. This TIER 2 SSRF in IBM API Connect underscores why egress filtering and strict authentication are non-negotiable for protecting backend services and citizen data flows. |
| 2 | 2 | CVE-2026-17411 | General infrastructure API gateway vulnerability; relevant for regulated sectors deploying IBM API Connect for citizen or financial services. | TIER 2 SQLi in IBM API Connect highlights the need for strict management plane segmentation and MFA in regulated API deployments. While not actively exploited, post-compromise database access underscores the importance of hardening enterprise API gateways supporting public and financial services. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-123991.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124314.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124315.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124318.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16709.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16714.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16715.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16718.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16880.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17108.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17112.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17129.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17134.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17146.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17150.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17172.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17190.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17228.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17239.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17244.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17279.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17281.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17282.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17283.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17284.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17285.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17288.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17292.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17293.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17294.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17297.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17298.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17299.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17309.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17311.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17318.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17319.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17320.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17321.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17322.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17324.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17326.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17327.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17328.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17330.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17332.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17333.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17334.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17335.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17337.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17344.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17345.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17353.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17354.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17357.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17361.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17362.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17363.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17373.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17374.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17375.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17376.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17378.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17379.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17380.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17381.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17382.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17383.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17387.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17388.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17394.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17396.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17398.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17399.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17400.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17401.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17402.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17404.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17405.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17410.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18535.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19121.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19128.md` — heuristic TIER 3/4
