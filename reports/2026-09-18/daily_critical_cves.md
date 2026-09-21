# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-09-21 08:41:30Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-09-18`
- **Included count:** 18

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-87743 | Direct authorization bypass in Keycloak and Quarkus-based IAM services enables unauthenticated access to identity data and admin interfaces, impacting Digital Identity and cloud-native infrastructure. | A critical authorization bypass in Red Hat’s Keycloak and Quarkus framework allows unauthenticated attackers to bypass access controls and expose identity data. With no workarounds available, public-facing IAM deployments need immediate patching to protect citizen and enterprise identity services. |
| 5 | 2 | CVE-2026-93568 | Directly impacts Red Hat Keycloak and SSO (Digital Identity sector) by enabling authorization/routing bypass in public-facing IdAM gateways. | Identity providers like Keycloak and SSO are exposed to authorization bypass via HTTP/2/3 Extended CONNECT flaws in Netty. Patching public-facing IdAM gateways is critical to prevent session hijacking and policy evasion. |
| 5 | 2 | CVE-2026-93569 | Directly impacts core IdAM platforms (Keycloak, Red Hat SSO) by enabling authentication/authorization bypass and tenant isolation breaks via HTTP/1-to-HTTP/2 authority confusion. | A new TIER 2 flaw in Netty’s HTTP conversion utility threatens enterprise identity gateways, allowing unauthenticated attackers to bypass auth boundaries and poison caches in Keycloak and SSO deployments. Organizations relying on HTTP/1-to-HTTP/2 translation should prioritize patching to protect tenant isolation and access controls. |
| 4 | 2 | CVE-2026-75031 | Unauthenticated RCE in a payment-adjacent e-commerce framework directly threatens financial transaction infrastructure and digital commerce services. | Unauthenticated remote code execution in the Interchange e-commerce framework poses a direct threat to financial transaction infrastructure. While default configurations offer sandboxing, misconfigured deployments face full system compromise—highlighting the need for strict configuration management in payment-adjacent digital services. |
| 4 | 2 | CVE-2026-75878 | Critical SSO authentication bypass on internet-facing B2B file transfer gateways widely deployed in Finance, Healthcare, and Government for secure data exchange. | Unauthenticated attackers can hijack sessions on IBM Sterling File Gateway by spoofing SSO headers, posing a direct risk to regulated B2B data exchanges in finance, healthcare, and government. Patching is the only fix until IBM releases updates. |
| 4 | 2 | CVE-2026-81626 | Unauthenticated SQLi in IBM Guardium, a foundational data protection and compliance appliance critical to regulated Finance, Healthcare, and Government environments. | An unauthenticated SQL injection in IBM Guardium threatens the backbone of regulated data compliance. While internal by default, compromising this monitoring appliance could blind audit trails and expose sensitive records across Finance, Healthcare, and Government sectors. |
| 4 | 2 | CVE-2026-81657 | Critical unauthenticated RCE in IBM Guardium, a foundational database security appliance explicitly deployed across Finance, Healthcare, and Government sectors for regulatory compliance. | Unauthenticated RCE in IBM Guardium poses a severe lateral movement risk for regulated enterprises. With zero workarounds, Finance, Healthcare, and Government sectors must prioritize patching to protect critical database monitoring infrastructure. |
| 4 | 2 | CVE-2026-82967 | Critical database security and compliance monitoring appliance widely deployed across Finance, Healthcare, and Government sectors to enforce PCI-DSS, HIPAA, and GDPR audit controls. | Unauthenticated bypass in IBM Guardium exposes the management interface of a cornerstone compliance appliance, threatening audit integrity and data protection controls across regulated Finance, Healthcare, and Government environments. Patching and strict network segmentation are essential to maintain regulatory posture. |
| 4 | 2 | CVE-2026-84108 | High-impact RCE in IBM Guardium, a foundational compliance and data protection appliance widely deployed across Finance, Healthcare, and Government sectors to secure regulated databases and citizen/patient records. | Compromise of database security appliances like IBM Guardium can bypass critical compliance controls in regulated sectors. This TIER 2 RCE highlights the need for strict internal segmentation and rapid patching to protect financial, healthcare, and government data pipelines. |
| 4 | 2 | CVE-2026-89058 | Directly impacts core Digital Identity stacks (Keycloak, SSO) and enterprise backend infrastructure, risking authenticated session and token leakage via CORS misconfiguration. | A TIER 2 CORS flaw in RESTEasy threatens Red Hat Keycloak and SSO deployments, highlighting how a single wildcard origin misconfiguration can bypass authentication controls and leak sensitive identity tokens. |
| 4 | 2 | CVE-2026-93558 | Impacts core Digital Identity providers (Keycloak/SSO) and foundational Java frameworks widely deployed in regulated government, finance, and healthcare backend services. | A remote, unauthenticated DoS in Netty’s WebSocket handler threatens the availability of critical identity providers like Keycloak and enterprise Java platforms. Organizations relying on these foundational stacks for public-facing services should prioritize patching or disabling compression to prevent heap exhaustion outages. |
| 4 | 2 | CVE-2026-93564 | DoS vulnerability in Netty HAProxy decoder impacts core Digital Identity platforms (Keycloak, Red Hat SSO), risking disruption to authentication, SSO, and token issuance services. | A TIER 2 DoS flaw in Netty's HAProxy decoder threatens Red Hat Keycloak and SSO deployments. This memory leak can exhaust identity providers behind load balancers, disrupting critical authentication and federation flows. |
| 4 | 2 | CVE-2026-93567 | Digital Identity: Impacts Red Hat Keycloak and Single Sign-On IdAM gateways, enabling HTTP/2 CONNECT tunneling that bypasses egress policies and undermines identity federation controls. | A new TIER 2 flaw in Netty's HTTP/2 codec could allow attackers to bypass egress filters on Red Hat Keycloak and SSO gateways. Identity teams should verify proxy configurations and patch immediately to protect federation infrastructure. |
| 3 | 2 | CVE-2026-13673 | TIER 2 LDAP API permission flaw in widely deployed Synology NAS infrastructure, impacting directory services and data integrity in regulated/public sector storage environments. | Synology NAS administrators should prioritize patching CVE-2026-13673, a TIER 2 LDAP API flaw that allows authenticated attackers to read/write arbitrary files. While requiring valid credentials, the vulnerability poses a significant risk to directory-backed storage systems in enterprise and public sector deployments. |
| 3 | 2 | CVE-2026-80441 | General infrastructure critical to regulated sector compliance (Finance, Healthcare, Government); unauthenticated SQLi compromises audit integrity and data confidentiality. | CVE-2026-80441 exposes an unauthenticated SQLi in IBM Guardium, a cornerstone for regulated sector compliance. Organizations in Finance, Healthcare, and Government must patch immediately to safeguard audit trails and sensitive data. |
| 3 | 2 | CVE-2026-84075 | General infrastructure (database security appliance) explicitly tied to regulated Finance, Healthcare, and Government deployments; unauthenticated bypass enables lateral movement and policy tampering. | IBM Guardium's internal database security appliance contains a critical unauthenticated bypass (CVE-2026-84075), creating a lateral movement risk for regulated sectors relying on it for compliance and data protection. Immediate patching and strict network segmentation are recommended. |
| 3 | 2 | CVE-2026-92701 | Affects foundational confidential computing/TEE attestation infrastructure explicitly noted to underpin regulated Healthcare, Finance, and Government data-sharing initiatives. | A critical attestation flaw in confidential computing platforms (CVE-2026-92701) could undermine trust in secure AI and cross-sector data sharing. Regulated organizations relying on TEEs should prioritize patching to prevent session misbinding and trust bypass. |
| 3 | 2 | CVE-2026-93468 | TIER 2 unauthenticated file read in HGiga OAKlouds collaboration portal widely deployed across Taiwanese government and public-sector organizations for internal policy dissemination. | Internal collaboration platforms are often overlooked in threat models, but unauthenticated path traversals in widely used government portals can expose sensitive administrative data. Ensuring internal enterprise stacks are patched is vital for public-sector resilience. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2023-5778.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-14753.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-14754.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-15399.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-61682.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-10027.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-10030.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-10575.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-10744.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-10751.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-10853.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-10858.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-11375.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-11378.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-11381.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-11716.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-11725.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-11726.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-11727.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12384.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12954.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15579.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17086.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18911.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18912.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-28197.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-28198.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-40530.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-40539.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46655.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54148.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55556.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58197.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59163.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61548.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61551.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61552.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61672.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61682.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61817.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61818.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61819.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61833.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-6205.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62279.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62943.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63199.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63349.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63419.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63422.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63445.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63458.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67101.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67102.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67103.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67549.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69184.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-7006.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77239.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77301.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-80442.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81179.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81305.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81321.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81656.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81669.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81933.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81937.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81942.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81943.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81944.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81945.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82340.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82832.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82885.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82893.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82896.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83561.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84031.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84034.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84036.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84064.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84070.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84071.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84106.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84738.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84975.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85058.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85410.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85497.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87915.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88097.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89413.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90978.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91127.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91149.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93331.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93455.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93494.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93559.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93560.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93563.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93565.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93572.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93575.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93576.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93593.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93594.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93595.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93597.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93598.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93599.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93652.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93657.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93658.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93660.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93687.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93737.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93738.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93740.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93750.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93753.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93758.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93759.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93760.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93762.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93763.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93764.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93765.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93838.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93852.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-32641.md` — heuristic TIER 3/4
