# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-09-03 09:26:35Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-09-02`
- **Included count:** 9

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-49249 | TIER 2 DoS in Boruta OAuth/OIDC identity provider crashes the BEAM VM, blocking all downstream authentication flows for digital identity services. | A single authenticated request can crash an entire OAuth 2.0 identity provider. CVE-2026-49249 exposes how default open registration in Boruta allows trivial atom exhaustion, taking down critical authentication infrastructure in under 30 seconds. |
| 5 | 2 | CVE-2026-73475 | Finance sector relevance; bypasses payment validation in Drupal Commerce PayPal module, impacting transaction integrity and merchant revenue. | E-commerce merchants using Drupal Commerce PayPal must patch immediately to prevent payment bypass fraud. CVE-2026-73475 allows attackers to mark transactions as paid without transferring funds, directly threatening financial integrity. |
| 5 | 2 | CVE-2026-78689 | Digital Identity: Directly compromises SAML-based SSO endpoints via the nginx-saml reference implementation, disrupting authentication flows for enterprise and government digital services. | A heap overflow in NGINX’s njs XML module could crash public-facing SAML SSO endpoints before signature verification, posing a direct DoS risk to government and enterprise identity federation. Patching or disabling unused njs/SAML modules is critical for DPI resilience. |
| 5 | 2 | CVE-2026-84699 | Critical authentication bypass in self-hosted enterprise password manager enabling unauthenticated local account takeover, directly impacting organizational Digital Identity and credential infrastructure. | A critical auth bypass in Team Password Manager lets attackers reset local admin passwords without credentials. While typically deployed behind firewalls, this flaw underscores the need to migrate from local accounts to centralized LDAP/SAML identity providers in regulated environments. |
| 4 | 2 | CVE-2026-14957 | Core IPsec VPN infrastructure for government and regulated enterprises, with FIPS compliance mandates making it a critical availability target for public-sector remote access. | FIPS-compliant government and enterprise VPN gateways face a new unauthenticated DoS risk in Libreswan. While configuration barriers limit immediate impact, public-sector remote access infrastructure should prioritize patching to maintain service availability. |
| 4 | 2 | CVE-2026-84668 | Directly impacts Digital Identity and General Infrastructure by enabling SAML authentication bypass and full admin takeover in enterprise CI/CD pipelines. | A TIER 2 flaw in the Jenkins SAML Plugin lets authenticated users overwrite IdP metadata, bypassing authentication and compromising CI/CD pipelines. Patching is critical for organizations using SAML to secure developer access and software supply chains. |
| 3 | 2 | CVE-2026-20212 | TIER 2 unauthenticated root RCE on Cisco Nexus 9000 data center switches; critical general infrastructure underpinning regulated and public-sector networks. | Unauthenticated root RCE on Cisco Nexus 9000 switches highlights the persistent risk to foundational data center infrastructure. Even without in-wild exploitation, TIER 2 severity demands immediate iACL hardening and patching to protect lateral movement paths in regulated environments. |
| 3 | 2 | CVE-2026-84394 | SSRF bypass in a widely adopted Node.js URI library risks internal network and cloud metadata access across enterprise and public-sector web platforms. | A subtle bracket-handling flaw in a popular Node.js library is enabling SSRF bypasses in public-facing APIs. DPI teams should audit URL validation logic to prevent policy/use desyncs that expose internal infrastructure. |
| 3 | 2 | CVE-2026-84645 | Foundational CI/CD infrastructure flaw enabling RCE on Jenkins controllers, directly impacting software supply chains for government, finance, and healthcare digital services. | A high-severity RCE vulnerability in Jenkins (CVE-2026-84645) threatens CI/CD pipelines across regulated sectors. Organizations deploying public or enterprise digital services must patch immediately and restrict configuration permissions to safeguard their software supply chains. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-14199.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14828.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19117.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19219.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20274.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20275.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20276.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20277.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20278.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20279.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20280.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-45730.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-49832.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53670.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53671.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53706.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66362.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66786.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66842.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77124.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77125.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77180.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78222.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78408.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78409.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78410.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78590.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78604.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79991.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82404.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82955.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82958.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84381.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84484.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84485.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84648.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84649.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84650.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84665.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84669.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84670.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84672.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84673.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84675.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84695.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84800.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84801.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84837.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84838.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-20281.md` — heuristic TIER 3/4
