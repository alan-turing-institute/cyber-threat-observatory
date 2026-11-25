# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-11-25 18:58:54Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-11-24`
- **Included count:** 16

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-136132 | Critical authentication bypass in a zero-trust identity gateway (Pangolin) that handles SSO, MFA, and OIDC, directly compromising digital identity and access management infrastructure. | A trivial URL-encoding trick now bypasses authentication in Pangolin, a popular zero-trust identity gateway. With public-facing deployments defaulting to vulnerable path-matching rules, organizations relying on SSO and MFA at the edge need to patch immediately to prevent unauthenticated access to protected services. |
| 4 | 2 | CVE-2026-112732 | Critical unauthenticated RCE in Microsoft Exchange/Visio indexing service poses direct risk to government email infrastructure and public sector communications. | A critical, no-interaction RCE in Microsoft Exchange’s attachment indexer (CVE-2026-112732) highlights the hidden risks in default enterprise configurations. Government and public sector IT teams should prioritize patching to protect critical email infrastructure from unauthenticated network attacks. |
| 4 | 2 | CVE-2026-123266 | Critical code injection in Adobe Experience Manager, a widely deployed CMS for government and financial public-facing portals, requiring patching to prevent server compromise. | Public-facing digital portals in government and finance rely heavily on Adobe Experience Manager, making this critical code injection vulnerability a priority for infrastructure teams. While authentication is required, the widespread deployment and high CVSS score demand immediate patching and credential hygiene to protect citizen and customer-facing services. |
| 4 | 2 | CVE-2026-124284 | Critical authentication bypass in enterprise SSO/federation flows (OIDC, SAML, AD FS) impacting Digital Identity infrastructure. | Enterprise security platforms relying on federated SSO face a critical auth bypass risk. Patching OIDC/SAML integrations is essential to protect digital identity access controls. |
| 4 | 2 | CVE-2026-132697 | Bypasses 2FA in MediaWiki's EmailAuth extension, directly impacting Digital Identity and Government/public-sector wiki deployments reliant on secondary authentication. | Public-facing wikis used by governments and NGOs face a critical 2FA bypass in MediaWiki’s EmailAuth extension. Attackers can exhaust rate limits and submit a single space to skip secondary authentication—patching is essential for any public documentation platform. |
| 4 | 2 | CVE-2026-132734 | TIER 2 flaw in widely deployed MediaWiki platforms enables unauthenticated file reads, exposing LDAP directories and database credentials critical to Digital Identity and public-sector infrastructure. | Unauthenticated file reads in MediaWiki’s ExternalData extension could expose LDAP directories and database credentials on public-facing wikis. Patch or harden your knowledge bases now to protect government and enterprise identity infrastructure. |
| 4 | 2 | CVE-2026-132735 | Directly compromises 2FA/TOTP and session management in MediaWiki, enabling account takeover and aligning with Digital Identity sector criteria for authentication bypass. | A TIER 2 flaw in MediaWiki’s OATHAuth extension allows attackers to bypass 2FA and hijack accounts by manipulating recovery code flows. Organizations relying on wiki platforms for internal documentation or public knowledge bases should prioritize patching to protect privileged access and identity controls. |
| 4 | 2 | CVE-2026-135796 | Critical root RCE in Volans NGFW management UI, a foundational perimeter security component explicitly tied to Government, Finance, and Healthcare infrastructure protection. | Perimeter firewalls are the first line of defense for digital public infrastructure. This critical, unpatched root RCE in Volans NGFW management interfaces highlights the urgent need for network segmentation and MFA in government and healthcare networks. |
| 4 | 2 | CVE-2026-136190 | Directly compromises SSO/OIDC identity infrastructure by exposing client secrets and allowing provider manipulation, impacting Digital Identity services. | A TIER 2 flaw in gitea-mirror lets authenticated users steal OIDC client secrets and hijack SSO providers. For any org relying on self-hosted identity mirroring, patching to v3.38.1 and rotating secrets is critical to prevent credential theft and auth bypass. |
| 3 | 2 | CVE-2026-109484 | Tier 2 critical flaw in Azure App Service for Linux, a foundational cloud PaaS explicitly noted to support public-sector and enterprise workloads. | A CVSS 10.0 unauthenticated privilege escalation in Azure App Service for Linux underscores the risks of default-public cloud hosting platforms. While Microsoft applied a server-side patch, it highlights the critical need for continuous monitoring of foundational infrastructure underpinning citizen-facing and regulated digital services. |
| 3 | 2 | CVE-2026-116382 | Foundational runtime for telecom, finance, and government backends; node-wide crash impacts regulated enterprise infrastructure. | A TIER 2 DoS in Erlang/OTP's inets server can crash entire backend nodes, posing a silent availability risk for telecom, finance, and government systems relying on this foundational runtime. Patch or restrict ESI configurations now. |
| 3 | 2 | CVE-2026-123256 | Enterprise CMS flaw impacting public-facing portals across Government, Finance, and Healthcare sectors; enables unauthorized content/configuration writes via low-privilege accounts. | Public digital services in government, finance, and healthcare rely on enterprise CMS platforms like Adobe Experience Manager. This Tier 2 authorization flaw highlights how compromised low-privilege accounts can lead to content defacement or configuration changes, underscoring the need for strict IAM controls and write-operation monitoring on internet-facing publish instances. |
| 3 | 2 | CVE-2026-132726 | MediaWiki powers internal knowledge management and documentation across government, healthcare, and finance sectors, making this RCE vulnerability relevant to regulated enterprise infrastructure. | MediaWiki is a cornerstone for internal knowledge management in government and regulated sectors. This Tier 2 deserialization flaw (CVE-2026-132726) enables RCE, reminding infrastructure teams to patch wiki platforms even when exploitation requires prior database access. |
| 3 | 2 | CVE-2026-135792 | Unauthenticated root RCE in Panabit network gateways widely deployed in government and telecom infrastructure for bandwidth management and authentication. | Critical unauthenticated RCE in Panabit Smart Application Gateways poses a direct risk to government and telecom networks relying on these appliances for traffic management and user authentication. With no patch available, strict network segmentation is the only defense. |
| 3 | 2 | CVE-2026-135794 | General infrastructure vulnerability in enterprise/government network gateways enabling persistent root RCE and traffic policy manipulation. | Panabit Smart Application Gateways face a critical post-auth RCE (CVE-2026-135794) that could compromise traffic routing and compliance in government and enterprise networks. Network segmentation and admin access controls are critical until patched. |
| 3 | 2 | CVE-2026-136183 | Exposes payment and tax details in a multi-tenant e-commerce framework, impacting merchant financial operations and aligning with Finance sector criteria. | A TIER 2 IDOR flaw in a popular e-commerce framework allows compromised vendor accounts to hijack competitor stores and access sensitive payment data. Merchants and fintech platforms relying on headless commerce backends should prioritize patching to protect financial operations and tenant isolation. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-100969.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100985.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103333.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111546.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116225.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119579.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120933.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120935.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120941.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120944.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120945.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120946.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120948.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120949.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121357.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121375.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123166.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123167.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123168.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123172.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123253.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123342.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123626.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123721.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123722.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123986.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123987.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124286.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-125675.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-125716.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-125717.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-125718.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-125723.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127181.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127182.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-129833.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130822.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132157.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132694.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132887.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133002.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133448.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133453.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133780.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134068.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134894.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134895.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134896.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134897.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-135388.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-135691.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-135692.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-135693.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-135694.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-135695.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-135696.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-135706.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-135709.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-135722.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-135723.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-135734.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-135736.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-135737.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-135738.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-135739.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-135740.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-135790.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-135791.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-136155.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-136156.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-136157.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-136158.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-136181.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-136184.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-136185.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-136187.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-136188.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-136455.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-136613.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18530.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19881.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65155.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65156.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65157.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65158.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65159.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82169.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82170.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82313.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82315.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82316.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82319.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82320.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82321.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82322.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97893.md` — heuristic TIER 3/4
