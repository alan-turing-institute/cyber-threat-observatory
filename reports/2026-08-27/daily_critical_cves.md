# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-08-28 13:14:58Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-08-27`
- **Included count:** 11

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-59316 | Digital Identity: Stored XSS in Spring Authorization Server's default consent page compromises OAuth2/OIDC identity flows and session trust boundaries. | A TIER 2 flaw in Spring Authorization Server exposes public-facing OAuth2/OIDC deployments to stored XSS, risking session hijacking and consent manipulation in critical Digital Identity infrastructure. |
| 5 | 2 | CVE-2026-59354 | Critical flaw in Spring Security OAuth2 Authorization Server impacts foundational Digital Identity infrastructure, enabling stored XSS, SSRF, and privilege escalation in enterprise IdP deployments. | Spring Security's OAuth2 Authorization Server faces a critical vulnerability (CVE-2026-59354) that could compromise enterprise identity providers via stored XSS and SSRF. While exploitation requires explicit DCR configuration, organizations relying on this foundational IdAM stack should patch to v7.0.5 immediately to secure authentication pipelines. |
| 4 | 2 | CVE-2026-18965 | Finance sector relevance: unauthenticated API flaw in a cloud payment processing platform exposes IoT transaction terminals and disrupts cashless payment infrastructure. | A missing authorization flaw in a widely deployed IoT payment API leaves cashless transaction terminals exposed to unauthenticated remote control. For finance and retail infrastructure, this underscores the critical need for strict API segmentation and zero-trust access controls in payment ecosystems. |
| 4 | 2 | CVE-2026-54718 | Authenticated RCE via SSTI in Silverstripe CMS workflow module, widely deployed across government and public-sector websites. | A server-side template injection flaw in Silverstripe's Advanced Workflow module enables RCE for privileged users, underscoring the need for strict permission controls and timely patching in government CMS deployments. |
| 4 | 2 | CVE-2026-54721 | Authenticated RCE in Silverstripe CMS UserForms module, widely deployed across government and public-sector digital infrastructure. | Public-sector agencies and government websites running Silverstripe CMS must patch immediately to prevent authenticated remote code execution via the UserForms module. |
| 4 | 2 | CVE-2026-81679 | Cross-tenant data leakage in OpenRemote IoT broker impacts smart city and municipal infrastructure deployments, breaking civic data isolation and compliance boundaries. | Smart city platforms rely on strict multi-tenant isolation to protect civic data. This TIER 2 flaw in OpenRemote allows authenticated admins to bypass realm boundaries, exposing cross-tenant notifications and operational alerts. Municipal IT teams should verify upgrades to v1.28.0 and audit read:admin access. |
| 3 | 2 | CVE-2026-18885 | TIER 2 unauthenticated RCE in ServiceNow AI platform; classified as general infrastructure that indirectly supports DPI operations across regulated enterprise environments. | Critical unauthenticated RCE (CVSS 10.0) in ServiceNow’s AI platform underscores the risk to foundational enterprise ITSM stacks. While exploitation requires specific configurations, its widespread adoption in government and regulated workflows makes immediate patching essential for DPI resilience. |
| 3 | 2 | CVE-2026-18886 | Critical unauthenticated privilege escalation in ServiceNow AI Platform, a core enterprise workflow system widely deployed across government, healthcare, and finance sectors. | Unauthenticated privilege escalation in ServiceNow’s AI Platform (CVE-2026-18886) poses a strategic risk to regulated enterprises and public-sector deployments. While configuration-dependent, the CVSS 10.0 rating and broad SaaS footprint warrant immediate patching for DPI-relevant instances. |
| 3 | 2 | CVE-2026-6876 | Unauthenticated RCE in ServiceNow Now Platform, a core enterprise ITSM/portal stack widely deployed across government, finance, and healthcare for public-facing service delivery. | TIER 2 alert: Unauthenticated sandbox escape in ServiceNow Now Platform enables remote code execution on public-facing service portals. Critical for government and enterprise ITSM deployments relying on internet-exposed customer and employee access points. |
| 3 | 2 | CVE-2026-74820 | General infrastructure vulnerability in ServiceNow AI Platform affecting widely deployed enterprise ITSM/HR workflows across regulated and public-sector environments. | Self-hosted ServiceNow deployments face critical unauthenticated SQL injection risk in the AI Platform, requiring immediate patching to protect sensitive ITSM and HR data across government, finance, and healthcare sectors. |
| 3 | 2 | CVE-2026-74848 | General infrastructure API gateway flaw enabling cross-user response poisoning and data leakage, impacting edge deployments across regulated sectors. | Public-facing API gateways running Apache APISIX face a critical HTTP smuggling risk (CVE-2026-74848) that can leak sensitive data and poison responses. Regulated organizations using edge routing infrastructure should prioritize patching to version 3.18.0. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2025-30156.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-10036.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16279.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-30046.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-30056.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-30057.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-30062.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-40526.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-44629.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47849.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47877.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47885.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47886.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47888.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47889.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47890.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47891.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50152.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54083.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54085.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54330.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57499.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59270.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59284.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59307.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61783.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75005.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75159.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75418.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75871.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75889.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77358.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78002.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-80210.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-80211.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-80212.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81521.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81522.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81525.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81526.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81529.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81573.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81574.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81575.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81576.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81579.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81581.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81625.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81659.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81662.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81706.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81707.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81714.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81715.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81716.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81717.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81718.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81719.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81721.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81726.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81727.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81729.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81730.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81743.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81817.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81818.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81826.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81838.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-30047.md` — heuristic TIER 3/4
