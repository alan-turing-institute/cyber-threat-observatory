# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-10-02 03:38:04Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-09-30`
- **Included count:** 24

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-102091 | Unauthenticated SSRF in Kiteworks Secure Data Forms, a platform widely deployed across government, healthcare, and finance for regulated, internet-facing data collection. | Unauthenticated SSRF in Kiteworks Secure Data Forms exposes internet-facing data collection endpoints used by federal agencies and regulated industries. Patching and egress filtering are critical to protect sensitive public and healthcare data from internal network reconnaissance. |
| 5 | 2 | CVE-2026-102101 | RCE in Kiteworks Core PDN appliance, widely deployed across Government, Healthcare, and Finance for secure MFT and cross-organizational data exchange. | Kiteworks Core RCE (CVE-2026-102101) poses a high-impact risk to regulated sectors. While exploitation requires a data-influence precondition, the platform's critical role in government, healthcare, and finance MFT workflows demands immediate patching to 9.5.0+. |
| 5 | 2 | CVE-2026-102106 | Critical admin auth bypass in Kiteworks EPG, widely deployed in government and regulated sectors for CUI/PHI email protection. | Kiteworks EPG admin bypass (CVE-2026-102106) threatens government and regulated email security. Patch to v9.5.0+ and lock down admin access to protect CUI/PHI workflows. |
| 5 | 2 | CVE-2026-102149 | Strong Digital Identity and Government relevance due to certificate-based authentication bypass impacting secure email gateways widely deployed in defense and public sector. | Critical authentication bypass in Kiteworks EPG allows attackers to hijack certificate-based logins, threatening secure communications across government and regulated enterprise environments. Immediate patching is essential for digital identity integrity. |
| 5 | 2 | CVE-2026-88920 | Critical authentication bypass in Apache WSS4J undermines SAML-based federated identity trust chains, directly impacting Digital Identity, Finance, and Government B2B/API integrations. | A critical flaw in Apache WSS4J allows attackers to forge SAML sender-vouches assertions, bypassing authentication in enterprise IdAM and B2B SOAP services. Organizations relying on federated identity for finance or government APIs should prioritize patching to protect trust chains. |
| 4 | 2 | CVE-2026-102104 | Government / General Infrastructure: Unauthenticated SSRF in Kiteworks Email Protection Gateway, widely deployed across government agencies and defense contractors for secure communications. | Unauthenticated SSRF in perimeter email gateways poses a direct risk to government and defense communications. Kiteworks EPG users should patch immediately to prevent internal network mapping and potential pivoting. |
| 4 | 2 | CVE-2026-102105 | Unauthenticated SSRF in a perimeter email gateway widely deployed by Government and Healthcare sectors to protect CUI/PHI, enabling internal network pivoting and cloud credential theft. | Perimeter email gateways are critical choke points for public sector and healthcare communications. This unauthenticated SSRF in Kiteworks EPG could let attackers bypass network segmentation and harvest cloud credentials—patching to 9.5.0 is essential for regulated environments. |
| 4 | 2 | CVE-2026-102115 | Unauthenticated password reset bypass in Kiteworks Core enables account takeover, directly impacting Digital Identity and Government/regulated enterprise file-sharing infrastructure. | Kiteworks Core faces a critical unauthenticated password reset bypass (CVE-2026-102115) that allows full account takeover. While SSO users are safe, government and regulated enterprises relying on local credentials must patch immediately to protect sensitive digital identity and collaboration workflows. |
| 4 | 2 | CVE-2026-102127 | Government sector relevance: Kiteworks Email Protection Gateway is widely deployed by US federal agencies and defense contractors; XXE flaw risks exfiltration of credentials and cryptographic keys. | Kiteworks Email Protection Gateway faces a TIER 2 XXE risk (CVE-2026-102127) that could leak credentials and crypto keys. While requiring a non-default config, this matters for government and defense sectors relying on Kiteworks for secure email infrastructure. |
| 4 | 2 | CVE-2026-102128 | Unauthenticated identity-verification bypass in Kiteworks EPG enables remote account takeover, directly impacting secure Government communications infrastructure. | Remote, unauthenticated account takeover in Kiteworks Email Protection Gateway threatens secure government communications. Organizations relying on Kiteworks for defense and public-sector file sharing should patch to v9.5.1+ immediately. |
| 4 | 2 | CVE-2026-102143 | Unauthenticated arbitrary file write on Kiteworks Email Protection Gateway, widely deployed in US government and defense for secure email infrastructure. | Government and regulated sectors relying on Kiteworks Email Protection Gateway must patch CVE-2026-102143 immediately. This unauthenticated file write flaw on perimeter-facing appliances provides attackers a critical foothold for chaining to full system compromise. |
| 4 | 2 | CVE-2026-102458 | Plaintext credential exposure in Digiwin EasyFlow BPM platform, widely deployed by Taiwanese government agencies and regional financial institutions for public service and compliance workflows. | Unauthenticated API flaw in Digiwin EasyFlow exposes plaintext passwords, posing a direct threat to government service delivery and financial compliance workflows. Patch immediately and enforce strict network segmentation. |
| 4 | 2 | CVE-2026-103099 | Unauthenticated remote DoS on internet-facing enterprise video conferencing nodes widely deployed across government, healthcare, and finance for critical remote operations. | Enterprise video platforms like Pexip Infinity are critical infrastructure for government and healthcare remote operations. This unauthenticated remote DoS vulnerability requires immediate patching to prevent disruption of secure, cross-sector communications. |
| 4 | 2 | CVE-2026-103547 | Core LDAP directory service (ldapd) race condition enables remote authentication bypass and identity hijacking, directly impacting Digital Identity infrastructure. | A race condition in OpenBSD's ldapd daemon allows attackers to hijack authentication results and bind as another identity. While disabled by default, any organization relying on this LDAP service for identity management must patch immediately to prevent critical auth bypass. |
| 4 | 2 | CVE-2026-76504 | Foundational SD-WAN control plane vulnerability explicitly tied to Government and regulated sector networks, with active wild exploitation and CISA KEV listing. | An actively exploited authentication bypass in Cisco SD-WAN Manager grants full admin API access to enterprise control planes. Listed in CISA KEV and critical for Government and regulated sector networks, immediate patching and strict network segmentation are essential. |
| 4 | 2 | CVE-2026-86134 | Unauthenticated remote DoS on WatchGuard Fireware OS management interface poses systemic availability risk to Government, Finance, and Healthcare network perimeters. | Unpatched WatchGuard firewalls face unauthenticated remote DoS via the login interface, threatening the availability of government, financial, and healthcare network perimeters. Patching is critical to maintain edge security and administrative access. |
| 4 | 2 | CVE-2026-94052 | Critical authentication bypass in Apache MINA SSHD's LDAP module impacts Digital Identity and enterprise access control for bastion/CI-CD infrastructure. | A critical auth bypass in Apache MINA SSHD’s optional LDAP module could grant unauthorized SSH access to bastion hosts and CI/CD pipelines. Organizations relying on LDAP-backed identity for server access should verify configurations and patch immediately. |
| 4 | 2 | CVE-2026-95616 | Foundational Java WS-Security library extensively deployed across government, healthcare, and finance for secure SOAP integrations; unauthenticated DoS directly threatens regulated API availability. | An unauthenticated DoS in Apache WSS4J threatens the availability of secure SOAP endpoints widely used across government, healthcare, and finance integrations. Patch immediately to prevent trivial memory-exhaustion attacks on regulated enterprise APIs. |
| 3 | 2 | CVE-2024-58387 | Unauthenticated file read in Inspur HCM Cloud, widely deployed in Chinese government and state-owned enterprises, enabling credential theft and lateral movement. | Confirmed in-the-wild exploitation of an unauthenticated file read in Inspur's HCM Cloud highlights risks to government and enterprise digital infrastructure. While typically internal, misconfigurations expose sensitive credentials and system files, underscoring the need for strict network segmentation and patching in public-sector deployments. |
| 3 | 2 | CVE-2026-102102 | TIER 2 unauthenticated SSRF in a widely deployed enterprise email security gateway, explicitly noted as impacting Government, Healthcare, and Finance perimeter defenses. | A critical, unauthenticated SSRF in Kiteworks Email Protection Gateways exposes a common perimeter blind spot for regulated sectors. With no authentication required and default internet exposure, Government, Healthcare, and Finance deployments face immediate internal reconnaissance risks until patched to v9.5.0. |
| 3 | 2 | CVE-2026-103441 | Government sector: unauthenticated RCE in MediaWiki/Wikibase impacts public-facing civic knowledge bases and structured data platforms deployed by government entities. | Public-facing wiki platforms powering government and civic knowledge bases face a critical unauthenticated RCE risk via a deserialization flaw in Wikibase. While requiring a non-default extension, the high impact on public-sector data infrastructure warrants immediate patching and configuration review. |
| 3 | 2 | CVE-2026-103442 | Affects centralized authentication and session management in MediaWiki deployments used by public-sector and educational knowledge bases, impacting General Infrastructure and Digital Identity sectors. | Centralized authentication extends beyond traditional IdP stacks—MediaWiki’s CentralAuth extension contains a high-impact PHP object injection that could compromise cross-wiki identity synchronization. Government and educational knowledge bases should patch or restrict merge permissions to prevent session forgery and potential RCE. |
| 3 | 2 | CVE-2026-89238 | Foundational WS-Security library for enterprise SOAP APIs, explicitly noted for impact on government and finance B2B integrations relying on compliance-grade security policies. | A critical bypass in Apache WSS4J threatens the confidentiality and authentication guarantees of enterprise SOAP APIs. While no wild exploitation is confirmed, government and finance integrations relying on WS-Security for compliance should prioritize patching to prevent policy bypass and unauthorized access. |
| 2 | 2 | CVE-2023-54403 | Tier 2 enterprise CRM flaw with active exploitation; report explicitly ties deployment to government and finance sectors, highlighting credential theft risks in regulated environments. | CVE-2023-54403 in Yonyou U8 CRM allows unauthenticated file reads and is actively exploited in the wild. Though typically internal, exposed instances in government and finance sectors risk immediate credential theft—patch and restrict external access now. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-100253.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100254.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100255.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100256.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100262.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100266.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100268.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100273.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100277.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101276.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101283.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101295.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101879.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101880.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101881.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101882.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101884.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102089.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102092.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102093.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102094.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102096.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102097.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102098.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102099.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102100.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102108.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102109.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102112.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102113.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102114.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102116.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102117.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102118.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102119.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102120.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102121.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102123.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102125.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102126.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102129.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102130.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102131.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102132.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102142.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102147.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102454.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102455.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102456.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102457.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102490.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102509.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102510.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102511.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102874.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102984.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102990.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102992.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102993.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102994.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102996.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102997.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102998.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102999.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103000.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103054.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103056.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103087.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103101.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103102.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103104.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103105.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103106.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103235.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103237.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103239.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103242.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103321.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103470.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103472.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-10739.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-10764.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18782.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18783.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19553.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47489.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47491.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47493.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47494.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47495.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47496.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47498.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47499.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47500.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47501.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47502.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47503.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47504.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47505.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47507.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47508.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47510.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47519.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47521.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47535.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47536.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47541.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47548.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47550.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47551.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47552.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47553.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47554.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47556.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47558.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47559.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47560.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47561.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47563.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47569.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47570.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47571.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47572.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47573.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47574.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47575.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47576.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47577.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47578.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47579.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47580.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47582.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47583.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47585.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47587.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47588.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47589.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47590.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47591.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47592.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47593.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47594.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47595.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47596.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47597.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47598.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47599.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47600.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47601.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47602.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-51570.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55107.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55177.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55181.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55224.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62146.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77185.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85532.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87004.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87830.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92121.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92867.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92871.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92873.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93994.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94002.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-92870.md` — heuristic TIER 3/4
