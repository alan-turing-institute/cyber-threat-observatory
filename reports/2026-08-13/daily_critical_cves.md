# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-08-15 01:57:47Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-08-13`
- **Included count:** 19

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-17206 | TIER 2 RCE in IBM i host servers directly impacts Finance and Government sectors, where the OS underpins core banking systems, payment processing, and public sector transaction infrastructure. | IBM i remains the backbone of many banking cores and government transaction systems. This unmitigated TIER 2 RCE (CVE-2026-17206) highlights the critical need to patch legacy enterprise platforms before attackers turn internal exposure into systemic financial or civic disruption. |
| 5 | 2 | CVE-2026-49478 | Core Digital Identity infrastructure vulnerability compromising OIDC discovery, JWKS verification, and Kubernetes token handling in the Sigstore/Fulcio code-signing CA. | A TIER 2 flaw in Fulcio (Sigstore) exposes how OIDC redirect mishandling can leak Kubernetes tokens and poison JWKS caches, directly threatening software supply chain trust and digital identity verification. Organizations relying on OIDC-based code signing should patch to v1.8.6 and harden issuer configurations immediately. |
| 5 | 2 | CVE-2026-73302 | Critical OIDC SSO authentication bypass enabling full admin account takeover, directly impacting Digital Identity infrastructure and low-code platforms deployed across government, healthcare, and finance. | A critical flaw in Budibase’s OIDC SSO flow ignores email verification, allowing attackers to hijack admin accounts via trusted identity providers. Organizations relying on low-code platforms for citizen or clinical services should patch immediately and enforce strict IdP verification policies. |
| 5 | 2 | CVE-2026-73420 | Critical authentication bypass in NextAuth.js enables full account takeover via magic-link misrouting, directly impacting Digital Identity and passwordless access systems. | A Unicode flaw in NextAuth.js lets attackers hijack passwordless sign-in links by default. For any public-facing identity system relying on magic links, this is a critical account takeover risk that demands immediate patching. |
| 4 | 2 | CVE-2026-17101 | TIER 2 remote code execution via authentication bypass in IBM i Navigator, a foundational OS console explicitly underpinning Finance, Government, and Healthcare workloads. | Critical IBM i infrastructure underpins regulated sectors worldwide. This TIER 2 authentication flaw in Navigator for i enables unauthenticated RCE with no workarounds, requiring immediate patching to protect finance, government, and healthcare backends. |
| 4 | 2 | CVE-2026-17197 | Remote authentication bypass in IBM i OS directly threatens core banking, hospital records, and government civic databases hosted on this foundational enterprise infrastructure. | IBM i systems underpin critical finance, healthcare, and government workloads worldwide. This TIER 2 remote auth bypass demands immediate patching to protect core public and regulated infrastructure from unauthorized access. |
| 4 | 2 | CVE-2026-17220 | Core enterprise OS (IBM i) widely deployed in Finance, Government, and Healthcare for legacy transaction processing; remote buffer overflow impacts authentication metadata and critical network services. | IBM i remains the backbone for many regulated sectors, making this remote buffer overflow a priority for Finance, Government, and Healthcare IT teams. With no temporary workarounds available, patching and network segmentation are critical to protect legacy transaction systems and authentication metadata. |
| 4 | 2 | CVE-2026-18164 | Healthcare sector: hard-coded credentials in an FDA-cleared brain stimulation device allow unauthenticated manipulation of therapy parameters, posing direct patient safety and clinical data integrity risks. | Medical IoT security remains critical: a hard-coded credential in an FDA-cleared brain stimulation device could let attackers override therapy limits via Bluetooth. Healthcare providers and patients should apply the latest firmware immediately to protect patient safety and clinical data. |
| 4 | 2 | CVE-2026-59109 | Finance sector: SQL injection in enterprise accounting software via PEPPOL e-invoices threatens financial integrity and B2B transaction security. | Supply-chain style attacks via standard e-invoicing networks (PEPPOL) are a growing threat to financial infrastructure. This TIER 2 SQLi in a popular accounting app shows how B2B document exchange can bypass traditional perimeter defenses. |
| 4 | 2 | CVE-2026-61967 | Unauthenticated privilege escalation in a widely deployed OTP/MFA WordPress plugin directly impacts Digital Identity infrastructure and public-facing access controls. | A critical, unauthenticated flaw in a popular WordPress OTP/MFA plugin could let attackers bypass multi-factor authentication and seize full site admin control. Public sector and regulated organizations relying on WordPress for citizen or customer portals should patch immediately to protect identity verification workflows. |
| 4 | 2 | CVE-2026-61979 | Unauthenticated privilege escalation in a widely deployed SAML SSO plugin directly compromises federated identity and access management workflows. | A critical flaw in a popular SAML SSO WordPress plugin allows unauthenticated attackers to seize full admin control, threatening federated identity systems across public and enterprise deployments. Patch immediately to protect your digital identity infrastructure. |
| 4 | 2 | CVE-2026-73188 | Unauthenticated exposure of protected health information (PHI) in a public-facing clinic management plugin, directly impacting healthcare data infrastructure and regulatory compliance. | Healthcare providers using WordPress for patient portals face a critical data exposure risk. CVE-2026-73188 allows unauthenticated access to patient records and billing data, underscoring the need for rigorous plugin vetting in digital health infrastructure. |
| 4 | 2 | CVE-2026-73421 | Critical authentication bypass in NextAuth.js directly impacts Digital Identity by failing open on misconfigurations, exposing protected routes and user sessions. | NextAuth.js v5 beta users: a silent fail-open bug turns misconfigured auth checks into open doors. Patch to beta.32 or switch to property checks to protect your digital identity layer. |
| 4 | 2 | CVE-2026-73570 | Unauthenticated RCE in Zimbra Collaboration Suite impacts government and enterprise digital identity infrastructure, compromising authentication, account management, and sovereign email services. | Zimbra’s widely deployed email and collaboration platform faces an unauthenticated RCE flaw that could compromise government and enterprise identity management. While requiring optional SNMP configuration, the impact on sovereign email and access control infrastructure warrants immediate patching for public sector and regulated deployments. |
| 3 | 2 | CVE-2026-14456 | Foundational cryptographic library underpinning secure communications across all DPI sectors; unauthenticated QUIC DoS risks availability of public-facing identity, finance, and government services. | OpenSSL’s foundational role in secure communications means this unauthenticated QUIC DoS could disrupt public-facing services across identity, finance, and government sectors. Patching or implementing connection limits is critical to maintain availability for regulated digital infrastructure. |
| 3 | 2 | CVE-2026-48702 | Core software supply chain transparency log (Sigstore/Rekor) disruption halts artifact signing and verification, degrading digital trust infrastructure for regulated and public-sector CI/CD pipelines. | An unauthenticated DoS in Rekor can crash software transparency logs, halting artifact signing and verification across enterprise and public-sector supply chains. With zero effective workarounds, immediate patching is essential to protect digital trust infrastructure. |
| 3 | 2 | CVE-2026-53793 | General infrastructure utility (rsync) critical for backup and data synchronization in government and financial systems; chroot escape breaks data integrity boundaries. | A critical chroot escape in rsync (CVE-2026-53793) threatens backup and data sync workflows across government and financial infrastructure. Ensure your rsync daemons are patched to 3.5.0+ to maintain data integrity boundaries. |
| 3 | 2 | CVE-2026-73645 | Finance sector relevance due to smart contract token wrapping and transaction integrity risks in DeFi infrastructure, though mitigated by extreme volume thresholds. | A Tier 2 vulnerability in OpenZeppelin’s confidential contracts library highlights the critical need for robust overflow checks in DeFi token wrappers. While practical exploitation faces a massive volume barrier, it underscores the importance of rigorous financial smart contract auditing for public-facing blockchain infrastructure. |
| 3 | 2 | CVE-2026-73665 | TIER 2 unauthenticated RCE in FreePBX UCP, a VoIP/PBX platform explicitly tied to enterprise and public-sector communications infrastructure. | Unauthenticated RCE in FreePBX UCP (CVE-2026-73665) exposes internet-facing VoIP systems to full compromise. Public-sector and enterprise telecom deployments should patch to v17.0.9 and restrict UCP port access immediately. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-0293.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-0294.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-0295.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-0296.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-0297.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-0298.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-0299.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-11840.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12263.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13365.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13460.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14662.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14664.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14668.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14669.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14670.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14671.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14676.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14677.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14679.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14680.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14875.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15741.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15742.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16238.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16239.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16674.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16722.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16867.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16868.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16887.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16896.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16898.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16908.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16961.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16967.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16975.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16982.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17004.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17045.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17069.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17099.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17199.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17223.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17229.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17272.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18071.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18077.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18101.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18193.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18249.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18408.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18428.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18509.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18511.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18846.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19297.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19385.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19483.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19753.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-45725.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48099.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-49864.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53783.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53785.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53795.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53799.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53802.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53803.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55402.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59714.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-6464.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-6471.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68451.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68452.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68453.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68454.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70452.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70453.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70454.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70457.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70458.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70462.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70463.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72629.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72630.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72632.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72642.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72643.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72658.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72665.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72669.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72670.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72672.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72675.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72677.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72741.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72853.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72856.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73266.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73305.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73408.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73417.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73483.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73484.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73515.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73530.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73566.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73601.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73604.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73613.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73616.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73622.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73623.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73644.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73652.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73653.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73659.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73660.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73661.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73662.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73664.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73667.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73841.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-8715.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-70464.md` — heuristic TIER 3/4
