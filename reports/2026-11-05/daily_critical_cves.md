# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-11-07 21:54:32Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-11-05`
- **Included count:** 36

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-103112 | Core IdAM platform (Keycloak/SSO) vulnerability enabling account takeover via race condition, directly impacting digital identity infrastructure. | A race condition in Keycloak's authentication flow could allow attackers to hijack sessions and take over accounts. For digital identity providers, patching this TIER 2 vulnerability is critical to maintaining trust in public and enterprise SSO deployments. |
| 5 | 2 | CVE-2026-107123 | Unauthenticated DoS in Keycloak's SAML processing disrupts default internet-facing SSO endpoints, directly threatening public-sector and enterprise Digital Identity infrastructure. | A single malformed SAML request can now exhaust CPU on internet-facing Keycloak instances, taking down SSO for all downstream services. With no viable workarounds, public and enterprise identity providers must prioritize patching to prevent unauthenticated denial-of-service attacks on critical authentication flows. |
| 5 | 2 | CVE-2026-107602 | Unauthenticated DoS in Keycloak's SAML parser paralyzes public-facing identity providers, directly impacting Digital Identity infrastructure and downstream regulated services. | Keycloak admins: a trivial unauthenticated DoS in the SAML parser can take down your entire IdP with zero mitigations. Patch immediately to protect your digital identity infrastructure. |
| 5 | 2 | CVE-2026-110931 | Critical unauthenticated DoS in Keycloak's SAML 1.1 parser crashes public-facing IdPs, directly impacting Digital Identity and enterprise SSO availability. | A single crafted request can crash Keycloak identity providers via a SAML parsing flaw, exposing the fragility of public-facing IdAM infrastructure. Immediate patching is essential to prevent widespread authentication outages across regulated sectors. |
| 5 | 2 | CVE-2026-110932 | Digital Identity sector: Unauthenticated DoS in Keycloak IdAM platform threatens availability of authentication and SSO services. | Keycloak deployments face a severe availability threat: an unauthenticated DoS flaw allows attackers to exhaust disk space and crash authentication services with no official workaround. |
| 5 | 2 | CVE-2026-112208 | Direct authentication bypass in Keycloak's SSO/IdAM flow enables full account takeover, critically impacting Digital Identity infrastructure and downstream regulated services. | A high-severity auth bypass in Keycloak’s Organization login flow allows attackers to hijack sessions and take over accounts via stale SSO flags. As a foundational IdP for government, finance, and healthcare, this TIER 2 vulnerability demands immediate patching to protect critical identity ecosystems. |
| 5 | 2 | CVE-2026-114232 | Core IdAM/SSO platform (Keycloak) with authorization bypass impacting identity boundaries and token isolation, directly relevant to the Digital Identity sector. | A TIER 2 flaw in Keycloak’s UMA Protection API lets authenticated users bypass resource ownership checks, risking horizontal privilege escalation across SSO-connected services. For DPI operators relying on centralized identity brokers, patching this authorization gap is critical to protect citizen and enterprise data boundaries. |
| 5 | 2 | CVE-2026-115573 | TIER 2 missing authorization in OpenEMR EHR enables authenticated users to dump patient PHI and hijack X12 EDI insurance billing credentials, directly impacting Healthcare and Finance sectors. | A TIER 2 flaw in OpenEMR lets low-privilege clinic staff bypass access controls to exfiltrate patient records and redirect insurance claims. Healthcare IT teams must patch to 8.3.0 immediately to protect PHI and financial routing. |
| 5 | 2 | CVE-2026-117691 | Critical SAML signature bypass in Keycloak enables federated account takeover, directly impacting Digital Identity and SSO infrastructure. | A critical SAML signature bypass in Keycloak allows attackers to hijack federated user accounts via crafted HTTP-Redirect requests. Organizations relying on Keycloak for SSO must patch immediately to protect digital identity flows. |
| 5 | 1 | CVE-2026-119757 | Directly compromises cryptocurrency payment processing infrastructure and merchant fund security, with confirmed in-the-wild exploitation and no runtime mitigations. | A critical, actively exploited flaw in BTCPay Server allows unauthenticated attackers to steal Lightning Network credentials and drain merchant funds. With no runtime mitigations available, payment processors must patch immediately to protect financial infrastructure. |
| 5 | 2 | CVE-2026-123196 | Digital Identity sector: compromises public-facing IdAM systems via password-reset poisoning, enabling account takeover in OAuth2/OIDC and SSO deployments. | A TIER 2 flaw in the open-source Authorizer IdAM server lets attackers hijack password-reset emails and steal session tokens. For any organization relying on self-hosted OAuth2/OIDC or SSO, patching to v2.4.2 is critical to prevent mass account takeovers. |
| 5 | 2 | CVE-2026-49272 | High-severity authentication bypass in OAuthLib, a foundational IdAM library critical for public-sector and enterprise SSO and API access controls. | A critical flaw in OAuthLib allows attackers to bypass device authorization and steal bearer tokens, threatening the integrity of government and enterprise identity providers. Patch to 4.0.1 immediately to secure your SSO and API gateways. |
| 5 | 2 | CVE-2026-65983 | Healthcare sector: Unauthenticated exposure of decrypted patient documents (PHI) in OpenEMR EHR systems directly impacts clinical data confidentiality and regulatory compliance. | Healthcare DPI alert: A TIER 2 vulnerability in OpenEMR allows unauthenticated access to decrypted patient records via its fax module. EHR deployments must patch to 8.2.0 or restrict web access to protect PHI. |
| 5 | 2 | CVE-2026-73856 | Foundational WAF engine bypass enabling unauthenticated data leakage across public-facing Digital Identity, Finance, Healthcare, and Government web services. | A case-sensitivity flaw in ModSecurity WAF lets attackers bypass response inspection and leak sensitive data from public-facing apps. Critical patch needed for all regulated digital services relying on this foundational security layer. |
| 5 | 2 | CVE-2026-82965 | Unauthenticated DoS in Keycloak's SAML endpoints disrupts core Digital Identity and SSO services for enterprise and public-sector deployments. | A single oversized XML payload can crash Keycloak's SAML endpoints, locking out all users. With no vendor mitigations available, identity providers must rely on network-level controls to protect critical authentication infrastructure. |
| 5 | 2 | CVE-2026-92857 | Directly compromises Digital Identity infrastructure by enabling token forgery and user impersonation in Keycloak, a core IdAM platform for regulated and public services. | A TIER 2 vulnerability in Keycloak’s Dynamic Client Registration allows authenticated attackers to forge identity tokens and bypass relying-party validation. DPI operators using Keycloak for public-facing authentication should patch immediately or restrict DCR endpoints to protect downstream identity ecosystems. |
| 5 | 2 | CVE-2026-93998 | Directly impacts foundational SSO/IdAM infrastructure (Keycloak/SAML), enabling full authentication bypass and admin impersonation in public-facing digital identity deployments. | A critical SAML authentication bypass in Red Hat Keycloak (CVE-2026-93998) allows attackers to forge assertions and impersonate admins in federated SSO environments. While requiring a shared signing key configuration, this TIER 2 flaw underscores the need to audit multi-issuer trust setups in national and enterprise identity platforms. |
| 5 | 2 | CVE-2026-97175 | Critical account takeover flaw in Keycloak SSO/IdAM infrastructure enabling identity linking bypass; core Digital Identity sector impact. | Keycloak users face account takeover risks via improper email verification in identity federation. This TIER 2 flaw highlights the fragility of automated identity linking in enterprise SSO deployments. |
| 4 | 2 | CVE-2026-103938 | TIER 2 CSRF in OpenEMR EHR enables financial ledger manipulation and audit trail degradation, directly impacting Healthcare and Finance sectors. | Healthcare providers relying on OpenEMR should patch immediately: a TIER 2 CSRF flaw allows attackers to silently void billing transactions and corrupt financial audit trails. Protecting clinical revenue cycles and ledger integrity is critical for regulated health systems. |
| 4 | 2 | CVE-2026-111489 | Finance sector relevance due to management of banking details, virtual balances, and account transfers in a public-facing sports facility platform. | Hardcoded credentials in a sports management app expose user banking details and enable unauthorized balance transfers, highlighting the critical need for secure API authentication in finance-adjacent digital services. |
| 4 | 2 | CVE-2026-113663 | Foundational AI agent framework with sandbox escape RCE, posing systemic risk to government service bots, healthcare assistants, and financial automation built on AG2. | AI-driven public services are growing fast, but a sandbox escape in the AG2 framework could hand attackers full host control. Patch your agent backends before newline injection turns your civic bot into a backdoor. |
| 4 | 2 | CVE-2026-116790 | Critical VoIP/WebRTC infrastructure (FreeSWITCH) with direct impact on government contact centers, financial call routing, and healthcare telemedicine communications. | A TIER 2 flaw in FreeSWITCH allows unauthenticated attackers to hijack or drop VoIP calls by spoofing ICE checks. Organizations running government contact centers, telemedicine platforms, or financial routing systems should verify media port security and apply the v1.11.2 patch immediately. |
| 4 | 2 | CVE-2026-122304 | TIER 2 authorization bypass in Kyverno, a Kubernetes policy engine explicitly deployed in government, healthcare, and finance for compliance and cluster security. | Kyverno users in regulated sectors should patch immediately: a TIER 2 flaw lets namespace admins bypass confinement and steal cluster-wide secrets or disable security webhooks. Critical for any DPI stack relying on Kubernetes policy enforcement. |
| 4 | 2 | CVE-2026-123010 | Direct authentication bypass in an Okta/JWT integration package undermines Digital Identity workflows and role-based access controls critical to public and regulated enterprise services. | A flawed JWT issuer check in a popular Okta integration package lets attackers forge session tokens and bypass authentication entirely. For teams relying on cloud-native identity bridges, this TIER 2 flaw highlights why strict token validation remains non-negotiable in digital public infrastructure. |
| 4 | 2 | CVE-2026-123158 | TIER 2 OpenSSH authentication bypass directly compromises remote access controls, impacting Digital Identity, government, and finance infrastructure reliant on secure SSH administration. | A ready-to-use PoC exists for a critical OpenSSH password bypass that grants unauthenticated remote access to Alpine Linux systems. For DPI operators, this underscores the urgent need to enforce key-only authentication and patch bastion hosts securing government and financial infrastructure. |
| 4 | 2 | CVE-2026-46350 | Critical input validation bypass in the foundational dcmjs DICOM library corrupts medical imaging data integrity and availability in Healthcare PACS and radiology systems. | Healthcare IT teams should prioritize patching dcmjs to v0.52.0 to prevent crafted DICOM files from crashing PACS viewers and corrupting critical radiology measurements. |
| 4 | 2 | CVE-2026-48705 | Healthcare DPI: Unauthenticated DICOM upload flaw in MONAI clinical AI toolkit risks inference pipeline crashes and silent diagnostic data corruption in hospital/research networks. | Clinical AI pipelines face silent data corruption risks: CVE-2026-48705 in MONAI allows unauthenticated DICOM uploads to crash inference servers and poison diagnostic outputs. Healthcare IT teams should patch to 1.6.1 and enforce strict network segmentation. |
| 4 | 2 | CVE-2026-71548 | Digital Identity: Authenticated SQLi in SuiteCRM exposes OAuth2 tokens and user hashes, risking credential theft in enterprise IdAM-integrated deployments. | CVE-2026-71548 in SuiteCRM allows authenticated users to extract OAuth2 tokens and password hashes via SQL injection. Organizations using CRM systems for customer or employee data should patch immediately to protect identity credentials and prevent account takeover. |
| 4 | 2 | CVE-2026-76077 | Impacts ASN1SCC runtime used in government space telemetry and telecom infrastructure, enabling RCE/DoS in critical embedded systems. | A TIER 2 vulnerability in the ASN1SCC compiler/runtime threatens critical space and telecom infrastructure. Embedded systems processing XER messages face RCE and DoS risks, highlighting the need for strict supply-chain patching in national infrastructure. |
| 4 | 2 | CVE-2026-84183 | Authenticated RCE in Apache OFBiz ERP platform directly impacts Finance and Government sectors managing transactions, procurement, and citizen services. | Enterprise ERP systems like Apache OFBiz form the backbone of public sector and financial operations. This authenticated RCE highlights the critical need for strict role-based access controls and timely patching in regulated digital infrastructure. |
| 3 | 2 | CVE-2026-111490 | Finance sector relevance due to direct exposure of banking data and unauthorized virtual balance transfers in a public-facing SaaS API. | A TIER 2 IDOR flaw in a sports management SaaS API exposes banking data and enables virtual balance transfers, highlighting how authorization bypasses in public-facing apps can directly impact financial integrity. #CyberSecurity #DPI #FinanceTech |
| 3 | 2 | CVE-2026-115928 | Tier 2 unauthenticated DoS in FreeSWITCH, a foundational telecom stack explicitly noted to underpin healthcare, finance, and government voice communications. | A Tier 2 stack overflow in FreeSWITCH allows unauthenticated remote DoS via malformed SIP INVITEs. Organizations relying on this open-source telecom stack for critical voice services should apply the patch or disable inbound SDES parsing immediately. |
| 3 | 2 | CVE-2026-116784 | General infrastructure VoIP stack underpinning emergency services and public telecom networks; unauthenticated DoS impacts critical communications availability. | A trivially exploitable DoS in FreeSWITCH (CVE-2026-116784) can crash entire VoIP instances, threatening emergency call routing and public telecom infrastructure. Upgrade to 1.11.2+ to secure media ports. |
| 3 | 2 | CVE-2026-122310 | Critical Kubernetes policy engine privilege escalation impacting cloud-native infrastructure explicitly noted as relevant to government cloud and regulated DPI deployments. | A TIER 2 flaw in Kyverno enables namespace-to-cluster-admin escalation via URL path manipulation. Government and regulated cloud operators should prioritize patching this foundational policy engine to secure multi-tenant workloads and prevent lateral movement. |
| 3 | 2 | CVE-2026-33944 | SQLi in Dolibarr ERP/CRM compromises financial records and accounting data, impacting SMEs and foundations relying on it for regulated business operations. | Dolibarr ERP/CRM users face a critical SQL injection risk that exposes financial records and password hashes. Patch immediately to protect your organization's accounting and invoicing data from full database compromise. |
| 3 | 2 | CVE-2026-92693 | Foundational network telemetry and DDoS mitigation sensor used across ISPs and critical infrastructure; unauthenticated OOB read threatens monitoring stack availability. | A TIER 2 flaw in FastNetMon’s sFlow parser shows how unauthenticated network telemetry can become an attack vector. For DPI and critical infrastructure, securing internal monitoring VLANs isn’t optional—it’s a frontline defense against DDoS and lateral movement. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-100360.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100361.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102523.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102940.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103935.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104133.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104136.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104137.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104720.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105321.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107891.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107912.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109408.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112109.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115738.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116569.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116570.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116782.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116785.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116786.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116787.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116788.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116789.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119083.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119344.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119345.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120499.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121139.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-122302.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-122303.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-122305.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-122306.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-122307.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-122308.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-122309.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-122311.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-122313.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-122314.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-122315.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-122316.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-122318.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-122319.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-122320.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-122321.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-122322.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-122323.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123025.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123032.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123033.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123047.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123059.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123184.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123202.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123271.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123272.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123273.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19134.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-49393.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54142.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54146.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58273.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61649.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61651.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61653.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63111.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63213.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63215.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69135.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69142.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71550.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71901.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73099.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73100.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73101.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73116.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75614.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77596.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82413.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82904.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82910.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82912.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82916.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85076.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85627.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88981.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88984.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92855.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93424.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94395.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96453.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96677.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97847.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-49407.md` — heuristic TIER 3/4
