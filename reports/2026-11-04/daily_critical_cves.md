# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-11-05 12:35:37Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-11-04`
- **Included count:** 17

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-111036 | SSRF in Coupa Supplier Portal SaaS impacts Finance and Government sectors via procurement and spend management workflows. | Coupa's Supplier Portal faces a high-impact SSRF risk in document conversion, threatening procurement integrity for Finance and Government clients relying on the SaaS platform. |
| 5 | 2 | CVE-2026-114425 | Unauthenticated root file manipulation on public-facing secure email gateways widely deployed in government, healthcare, and finance sectors for compliant communications. | Critical unauthenticated flaw in SEPPmail Secure Email Gateway allows remote attackers to manipulate files with root privileges. Widely used in regulated sectors, this TIER 2 vulnerability demands immediate patching to protect sensitive citizen and patient communications. |
| 5 | 2 | CVE-2026-115770 | Core OIDC/OAuth identity provider flaw enabling email verification forgery and cross-application account takeover, directly impacting Digital Identity infrastructure. | A logic flaw in the self-hosted Pocket ID provider lets authenticated users forge email verification claims, risking account takeovers across relying applications. For DPI and enterprise identity teams, this underscores the critical need to validate token binding and avoid email-based account matching in OIDC deployments. |
| 5 | 2 | CVE-2026-11749 | Directly impacts SAML-based identity federation and session integrity, a core component of enterprise and government Digital Identity infrastructure. | SAML replay flaws in widely used Java libraries can undermine trust in enterprise and government identity federations. Patching assertion replay protections is critical for maintaining secure digital public infrastructure access. |
| 5 | 2 | CVE-2026-121639 | Directly impacts enterprise and public-sector identity infrastructure by allowing unauthenticated disruption of SSO/VPN authentication and LDAP/Active Directory synchronization. | Unauthenticated remote flaws in identity gateways can instantly lock out users and break directory sync. Organizations relying on WatchGuard AuthPoint for SSO or VPN should prioritize patching to protect critical access infrastructure. |
| 5 | 2 | CVE-2026-121802 | Critical origin validation flaw in a widely used authentication framework enabling unauthenticated account takeover and session hijacking, directly impacting Digital Identity infrastructure. | Unauthenticated account takeover in the Better Auth Expo plugin highlights the risks of flawed origin validation in modern identity stacks. Organizations relying on internet-facing auth backends should patch immediately to prevent mass credential compromise. |
| 5 | 2 | CVE-2026-62662 | Directly impacts the Digital Identity sector by enabling authorization bypass and JWT token forgery in self-hosted OIDC providers used for regulated service-to-service access. | A TIER 2 flaw in Pocket ID allows forged OIDC access tokens targeting arbitrary backend services when client credentials are compromised. DPI operators and regulated enterprises using self-hosted identity providers should patch to v2.10.0 immediately to secure service-to-service authorization boundaries. |
| 4 | 2 | CVE-2026-114421 | Government sector: Dominant secure email gateway for German public administration; unauthenticated account takeover risks inter-agency communications and citizen services. | SEPPmail's GINA webmail faces an unauthenticated account takeover flaw (CVE-2026-114421) that could compromise secure email infrastructure across German municipalities and public agencies. Patching to v15.1.1 is critical to protect government communications and citizen data. |
| 4 | 2 | CVE-2026-118513 | High-severity X509/mTLS authentication bypass in Symfony enables full identity spoofing, directly impacting digital identity verification in enterprise and public-sector portals. | A new TIER 2 vulnerability in Symfony’s X509Authenticator allows attackers to spoof identities via certificate CN manipulation. For DPI and enterprise identity teams relying on mTLS, patching or switching to per-attribute user keys is critical to prevent full account takeover. |
| 4 | 2 | CVE-2026-121956 | Impacts Kerberos-based authentication in FreeRDP remote access gateways, directly affecting Digital Identity infrastructure across government, healthcare, and finance sectors. | Unauthenticated remote DoS/RCE in FreeRDP’s Kerberos implementation highlights the critical need to harden identity-aware remote access gateways. Organizations relying on Kerberos for enterprise or public-sector VDI should prioritize patching or disable u2u mechanisms immediately. |
| 4 | 2 | CVE-2026-121966 | TIER 2 authentication bypass in Traefik reverse proxy enables identity hijacking via NTLM/Negotiate ForwardAuth, directly impacting Digital Identity and foundational routing infrastructure. | Edge proxies are the gatekeepers of digital public services, but a shared connection pool flaw in Traefik could let attackers hijack user identities. If your infrastructure relies on NTLM or Negotiate for ForwardAuth, patching to v2.11.60/v3.7.16 is critical to protect citizen and enterprise access controls. |
| 4 | 2 | CVE-2026-121971 | Core PHP framework flaw risking credential leakage in authenticated outbound calls across Digital Identity, Healthcare, Finance, and Government web services. | Foundational PHP framework Symfony patched a credential-leak flaw in its HTTP client that could expose API tokens and auth headers to attacker-controlled endpoints. Regulated sector teams using scoped clients should prioritize upgrades to protect outbound service integrations. |
| 4 | 2 | CVE-2026-54381 | Healthcare sector impact: unauthenticated cloud bucket exposure leaks ~129k user health profiles and clinical-adjacent metrics, threatening digital health infrastructure privacy and compliance. | A misconfigured cloud bucket just exposed over 129,000 health profiles and sensitive biometric data without a single authentication check. For digital health platforms, this underscores why zero-trust storage policies and automated IAM audits are non-negotiable in regulated environments. |
| 4 | 2 | CVE-2026-82029 | Finance sector: Broken access control in Invoice Ninja allows authenticated vendor contacts to exfiltrate sensitive financial documents (invoices, contracts, receipts), impacting financial data confidentiality. | Financial infrastructure alert: A broken access control flaw in Invoice Ninja lets authenticated vendor contacts download invoices and contracts belonging to other clients. Organizations should patch to v5.13.28 and enforce a custom HASH_SALT to protect financial records. |
| 3 | 2 | CVE-2026-122019 | Unauthenticated social login bypass enables full account takeover and wallet drainage on a widely deployed e-commerce platform, impacting digital payment processing and consumer financial data. | A trivial, unauthenticated API flaw in a popular multi-vendor e-commerce platform allows attackers to hijack accounts and drain digital wallets with just an email address. As commercial platforms increasingly handle direct payments, securing social login flows is critical for protecting digital financial infrastructure. |
| 3 | 2 | CVE-2026-54378 | Broken access control in a public-facing health tracking API enables cross-user leakage of personal health records, impacting healthcare data privacy and compliance. | A TIER 2 flaw in a popular health-tracking API exposes users to cross-account data breaches, highlighting the critical need for strict IAM scoping in consumer healthcare apps. Organizations handling health data must prioritize credential isolation to meet privacy compliance standards. |
| 3 | 2 | CVE-2026-54383 | TIER 2 Healthcare relevance: internet-facing API flaw exposes PII and sensitive health metrics, highlighting data privacy risks in consumer wellness and digital public health ecosystems. | As consumer wellness platforms integrate into broader digital health ecosystems, data privacy becomes a critical infrastructure concern. This TIER 2 API flaw demonstrates how missing authorization checks can enable mass harvesting of health metrics and PII, reinforcing the need for strict access controls in health-adjacent services. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2025-11229.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100252.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100302.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102339.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102664.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103002.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104203.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-10859.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109518.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110022.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111038.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-113370.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-113371.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-113372.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-113373.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-113374.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-11376.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-11724.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121637.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121638.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121640.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121939.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121946.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121950.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121951.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121953.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121954.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121955.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121957.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121958.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121959.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121961.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121962.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121963.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-122007.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-122009.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-122118.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-122120.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-122126.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-122130.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-122133.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-122134.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-122135.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-122192.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-122224.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-122266.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-122299.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12356.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13271.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13284.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13289.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13292.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16511.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17493.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18142.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47678.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-52848.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54372.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54375.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54376.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54382.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55367.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57152.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57853.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59267.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59268.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62126.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76506.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76826.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77372.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77690.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77779.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79405.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-80335.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87038.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87039.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87041.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90624.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90626.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90629.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90634.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94459.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94460.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-121960.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-76892.md` — heuristic TIER 3/4
