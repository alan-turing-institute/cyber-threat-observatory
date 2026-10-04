# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-10-04 11:17:53Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-10-03`
- **Included count:** 6

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-105115 | Compromises default-deployed, unauthenticated endpoints on OpenAM, a core IdAM/SSO platform critical to government, healthcare, and finance digital identity infrastructure. | A default-enabled, unauthenticated SOAP endpoint in OpenAM exposes public-facing identity providers to reliable DoS and potential RCE. DPI operators should immediately block /jaxrpc/* at the proxy or patch to 16.1.3 to protect citizen and enterprise authentication services. |
| 5 | 2 | CVE-2026-105119 | Directly impacts core Identity Provider (IdP) infrastructure by bypassing PKCE in OAuth/OIDC hybrid flows, enabling session hijacking and token theft in digital identity systems. | A critical PKCE bypass in OpenAM’s OAuth/OIDC hybrid flows could allow attackers to hijack sessions and steal tokens in enterprise and government identity platforms. Ensure public clients are restricted and hybrid flows are hardened to protect your digital identity infrastructure. |
| 4 | 2 | CVE-2026-105105 | Critical unauthenticated command injection in NASA's AIT-Core ground data system, directly impacting government space infrastructure and mission control operations. | A default-exposed ZeroMQ broker in NASA’s AIT-Core toolkit allows unauthenticated spacecraft command injection and telemetry theft. For government and space agencies, this underscores the critical need to harden internal ground-segment infrastructure against lateral movement and data exfiltration. |
| 4 | 2 | CVE-2026-71886 | Impacts Digital Identity by enabling OpenPGP trust chain manipulation and identity spoofing in cryptographic libraries used for citizen/service authentication and document signing. | A logic flaw in the widely deployed Bouncy Castle Java library allows attackers to spoof OpenPGP identities and bypass trust delegations. For DPI systems relying on cryptographic verification for citizen authentication or secure document signing, patching to v1.86 is critical to preserve trust chain integrity. |
| 4 | 2 | CVE-2026-71887 | Impacts OpenPGP signature verification and identity attribution, a foundational trust mechanism for digital identity and secure communications. | Bouncy Castle's OpenPGP flaw lets attackers hijack legitimate signatures and misattribute them to fake identities. A critical integrity risk for digital identity and secure document workflows. |
| 3 | 2 | CVE-2026-71889 | Foundational cryptographic library underpinning PKI/TLS trust for regulated sectors; bypasses X.509 NameConstraints impacting mTLS and API authentication in enterprise/government deployments. | A TIER 2 flaw in Bouncy Castle’s Java crypto library could undermine PKI trust boundaries for regulated services. While requiring specific API usage, it highlights the critical need to audit cryptographic validation paths in digital identity and government infrastructure. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-71883.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71885.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71888.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71890.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71891.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85515.md` — heuristic TIER 3/4
