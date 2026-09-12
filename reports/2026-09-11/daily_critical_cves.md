# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-09-12 09:57:54Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-09-11`
- **Included count:** 6

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-47839 | Core IdAM/OIDC federation component in enterprise cloud platforms; bypass grants full admin control over user identities and session tokens. | A critical authorization bypass in Cloud Foundry UAA allows federated OIDC users to escalate to full admin privileges, compromising the identity trust boundary for enterprise and government cloud platforms. Organizations relying on OIDC federation should verify group-mapping configurations and prioritize patching to protect their IdAM infrastructure. |
| 5 | 2 | CVE-2026-49464 | Government sector: IDOR in Dutch citizen portal backend allows authenticated users to access/modify other citizens' civic task submissions and PII. | A Tier 2 flaw in Dutch government citizen portals exposes an IDOR vulnerability that lets authenticated users hijack and complete others' civic tasks. Highlights the critical need for strict ownership validation in public-sector GraphQL APIs handling citizen data. |
| 5 | 2 | CVE-2026-54072 | Directly compromises OAuth 2.0/OIDC identity providers, enabling full account takeover via token exfiltration in public-facing authentication infrastructure. | A critical open redirect in a popular open-source OAuth/OIDC server is leaking access and refresh tokens via phishing links. For any organization relying on self-hosted identity providers, this underscores the urgent need to harden redirect allowlists and disable deprecated implicit flows. |
| 5 | 2 | CVE-2026-73784 | TIER 2 SAML signature bypass in HPE IceWall IAM/SSO gateway enables direct identity takeover, directly impacting Digital Identity infrastructure. | Identity gateways are the front door to digital public services. A TIER 2 flaw in HPE IceWall's SAML processing allows attackers to forge assertions and impersonate users, highlighting the critical need for strict cryptographic validation in enterprise IAM deployments. |
| 4 | 2 | CVE-2026-78133 | Foundational VPN gateway (strongSwan) underpins secure remote access and site-to-site connectivity for government, enterprise, and regulated sectors. | A TIER 2 use-after-free in strongSwan's IKEv2 daemon could crash or compromise widely deployed government and enterprise VPN gateways. Patch to 6.1.0 or disable Multi-KE to protect critical remote access infrastructure. |
| 3 | 2 | CVE-2026-80462 | Critical unauthenticated API bypass in Chef Automate, a general infrastructure platform widely deployed to manage CI/CD and automation pipelines for government, finance, and healthcare sectors. | Unauthenticated access to infrastructure automation platforms like Chef Automate can cascade across entire public-sector and enterprise environments. Patching and strict network segmentation are essential to protect the underlying pipelines that power regulated digital services. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2025-15679.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-38056.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-38058.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-44715.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50013.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54166.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54174.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57842.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70341.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73785.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78132.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-7863.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78807.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-80469.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82583.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-8303.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84390.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85979.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87020.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87776.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88260.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89060.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89065.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89066.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89090.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89099.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89161.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89176.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89177.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90444.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90445.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90447.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90448.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90451.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90456.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90460.md` — heuristic TIER 3/4
