# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-11-21 11:03:15Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-11-19`
- **Included count:** 19

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-123890 | Foundational virtualization management platform underpinning Government, Finance, and Healthcare infrastructure, with active in-wild exploitation and no workaround. | Actively exploited vCenter directory bypass threatens the virtualization backbone of government, finance, and healthcare systems. With no workaround available, immediate patching is critical to protect national digital infrastructure. |
| 5 | 2 | CVE-2026-130235 | Digital Identity: SSRF in Okta .NET SDK leaks SSWS API tokens, compromising foundational identity infrastructure. | Okta SDK flaw exposes admin tokens via SSRF, threatening identity platforms across regulated sectors. Patch .NET integrations immediately to protect critical IdAM infrastructure. |
| 5 | 2 | CVE-2026-130236 | TIER 2 flaw in Auth0 Authorization Extension allows authenticated users to bypass access controls and inject malicious logic into tenant login rules, directly compromising Digital Identity infrastructure and authentication integrity. | Auth0 tenants face a critical Digital Identity risk: CVE-2026-130236 allows authenticated users to hijack login rules and bypass authentication. Patch to v2.13+ and verify access control rules immediately to protect your identity infrastructure. |
| 5 | 2 | CVE-2026-84236 | Critical unauthenticated RCE in IBM Guardium compliance appliances directly impacts regulated Finance, Government, and Healthcare database monitoring and audit integrity. | A critical unauthenticated RCE in IBM Guardium (CVE-2026-84236) threatens the compliance backbone of regulated sectors. Finance, government, and healthcare organizations must patch immediately to protect audit trails and sensitive citizen/patient data from lateral movement. |
| 4 | 2 | CVE-2026-103026 | Finance sector relevance: unauthenticated authorization bypass in a public-facing hosting billing platform allows arbitrary state modification of payment and account records. | Public-facing billing platforms face critical risks when framework flaws bypass authorization controls. This TIER 2 vulnerability in Paymenter highlights how unauthenticated state manipulation can compromise financial transactions and customer trust in regulated hosting environments. |
| 4 | 1 | CVE-2026-131914 | Actively exploited unauthenticated RCE in a legacy ASP.NET CSRF library widely deployed across government, financial, and healthcare web portals. | Critical, actively exploited RCE in legacy ASP.NET web apps demands immediate action. Government and financial portals relying on outdated .NET stacks must audit and replace defunct CSRF modules before widespread compromise. |
| 4 | 2 | CVE-2026-132286 | Impacts identity and account provisioning in RuoYi, a framework widely deployed in Chinese government and enterprise internal management portals. | A mass-assignment flaw in the widely-used RuoYi framework allows attackers to escalate privileges and spoof audit logs during user registration. While disabled by default, enabling this feature in government or enterprise portals exposes critical identity provisioning workflows to manipulation. |
| 4 | 2 | CVE-2026-133172 | Cross-tenant authorization bypass in Cozy Cloud threatens sensitive municipal and healthcare data hosted on shared European public-sector infrastructure. | A TIER 2 authorization flaw in Cozy Cloud could allow authenticated users to exfiltrate or delete files across tenants, posing a direct risk to European municipal clouds and healthcare data platforms. Patching to v1.6.69+ is critical for public-sector deployments relying on shared infrastructure. |
| 4 | 2 | CVE-2026-133323 | Unauthenticated remote code execution in an internet-facing enterprise UC platform widely deployed across government, finance, and healthcare sectors, posing a direct pivot risk to regulated networks. | Critical unauthenticated RCE in Mitel MiCollab’s internet-facing conferencing module exposes government and financial networks to full system compromise. Patch immediately and restrict external access to protect regulated communications infrastructure. |
| 4 | 2 | CVE-2026-19609 | XSS in Unblu co-browsing bridges public-facing customer portals to internal agent sessions, directly impacting regulated Finance, Government, and Healthcare digital service desks. | A public-facing co-browsing widget in enterprise support platforms can now be weaponized to hijack internal agent sessions. With Unblu widely deployed across banking, government, and healthcare portals, this TIER 2 XSS flaw highlights the hidden risk of bridging customer interfaces to internal workstations—patch on-prem deployments now. |
| 4 | 2 | CVE-2026-76535 | Critical authentication bypass in Splunk Enterprise SIEM, a foundational security platform widely deployed across Government, Finance, and Healthcare for compliance logging and threat detection. | Unauthenticated access to Splunk Enterprise’s diagnostic API could let attackers run arbitrary queries and tamper with security logs. Regulated sectors relying on Splunk for compliance and threat detection should verify internal network segmentation and apply the vendor’s configuration fix immediately. |
| 4 | 2 | CVE-2026-87977 | Critical SQLi in IBM Guardium Data Protection, a core compliance and data security platform widely deployed across Finance, Healthcare, and Government sectors for regulatory adherence. | A critical unauthenticated SQL injection in IBM Guardium Data Protection threatens the integrity of compliance logs and audit trails across Finance, Healthcare, and Government environments. Even internal-only vulnerabilities can derail regulatory adherence and incident response when security monitoring platforms are compromised. |
| 3 | 2 | CVE-2026-116439 | Unauthenticated path traversal in foundational enterprise storage (Dell PowerStore) risks data integrity and availability across regulated Finance, Healthcare, and Government deployments. | Critical unauthenticated path traversal in Dell PowerStore storage arrays (CVE-2026-116439) poses severe lateral movement risks for internal networks. While general infrastructure, its widespread use in regulated sectors makes patching urgent for DPI resilience. |
| 3 | 2 | CVE-2026-123058 | Unauthenticated installer RCE in a widely deployed e-commerce platform directly impacts digital commerce infrastructure and financial transaction processing (Finance sector). | A forgotten web installer in a popular e-commerce platform is leaving merchant storefronts wide open to unauthenticated RCE and full takeover. For digital commerce and finance infrastructure, this TIER 2 flaw underscores why post-deployment hardening and automated installer cleanup are non-negotiable. |
| 3 | 2 | CVE-2026-125060 | TIER 2 IDOR in JTL-Shop checkout exposes customer PII and payment/transaction data, impacting digital commerce and Finance sector compliance. | Unauthenticated IDOR in JTL-Shop checkout lets attackers hijack delivery addresses and steal customer PII. A critical reminder for e-commerce and digital payment platforms to enforce strict session-bound object validation and patch promptly. |
| 3 | 2 | CVE-2026-131192 | Foundational SIEM/log management infrastructure supporting compliance and security monitoring across regulated sectors (Finance, Healthcare, Government, Digital Identity). | Unauthenticated REST API bypass in Splunk Enterprise exposes live log streams, highlighting the need for strict network segmentation and API hardening in regulated environments relying on SIEM for compliance and threat detection. |
| 3 | 2 | CVE-2026-132131 | General infrastructure (Node.js web framework) explicitly noted as used in government and public services; allows auth bypass. | Fastify middleware flaw lets attackers bypass auth controls in public-facing APIs. Critical for government and enterprise web services relying on Node.js stacks. |
| 3 | 2 | CVE-2026-133303 | Enterprise unified communications platform widely deployed across government, finance, and healthcare; unauthenticated RCE in internet-facing web conferencing poses systemic risk to regulated operations. | Unauthenticated RCE in Mitel MiCollab's web conferencing module underscores the exposure risk of internet-facing enterprise communications infrastructure. Regulated sectors should audit DMZ placements and patch promptly. |
| 2 | 2 | CVE-2026-82342 | Tier 2 RCE in IBM Guardium compliance monitoring appliance risks audit log integrity, directly impacting regulated Finance, Healthcare, and Government environments reliant on PCI-DSS/HIPAA/GDPR monitoring. | Internal compliance infrastructure is critical for regulated digital services. This Tier 2 RCE in IBM Guardium shows how unpatched monitoring appliances can jeopardize audit trails and regulatory compliance across finance, healthcare, and government sectors. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-103035.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103579.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103580.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104199.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105802.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110461.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110462.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111509.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115463.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115578.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118977.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123891.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123892.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-125288.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126086.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-128064.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-129223.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-129699.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-129700.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-129938.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130151.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130157.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130158.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130160.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130179.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130234.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131175.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131177.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131178.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131179.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131181.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131182.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131188.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131190.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131196.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131198.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131199.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131200.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131202.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131203.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131209.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131210.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131211.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131215.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131218.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131236.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131239.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131243.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131245.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131246.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131248.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131252.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131253.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131255.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131256.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131258.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131260.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131261.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131262.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131263.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131266.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131268.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131269.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131270.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131271.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131272.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131282.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131286.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131287.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131293.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131295.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131297.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131303.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131304.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131305.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132039.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132798.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132802.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132803.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132804.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132806.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132807.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132808.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132825.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132892.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132893.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132894.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132895.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132896.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132897.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132898.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132899.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132900.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132901.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132902.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132903.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132904.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132905.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132906.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132907.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132908.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132910.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132912.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132913.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132914.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132915.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132916.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132917.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132918.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133014.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133015.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133016.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133017.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133018.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133019.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133021.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133022.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133023.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133024.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133025.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133026.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133027.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133076.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133077.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133078.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133079.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133080.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133081.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133082.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133083.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133084.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133085.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133086.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133087.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133088.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133089.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133090.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133091.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133092.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133093.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133094.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133095.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133096.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133113.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133161.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133168.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133173.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133185.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133189.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133245.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133476.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18883.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61798.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61827.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62256.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62258.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69260.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69261.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76536.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76538.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76540.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76544.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77313.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77315.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77316.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77359.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81430.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82339.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84273.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84322.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85018.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86094.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86126.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93911.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93912.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93914.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93915.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93916.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93917.md` — heuristic TIER 3/4
