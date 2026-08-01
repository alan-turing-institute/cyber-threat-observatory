# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-08-01 13:15:00Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-07-30`
- **Included count:** 15

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-65635 | Digital Identity: Boruta OAuth/OIDC library allows unauthenticated creation of over-privileged clients if dynamic registration is exposed, impacting custom IdP infrastructure. | Custom Identity Providers using the Boruta Elixir library face a critical configuration risk: exposing dynamic client registration can allow attackers to spawn over-privileged OAuth clients without authentication. Organizations relying on custom IdP stacks must audit their endpoint exposure immediately. |
| 5 | 2 | CVE-2026-67345 | Directly impacts Digital Identity infrastructure via an OAuth 2.0 redirect URI bypass in a widely deployed IAM/SSO platform, enabling account takeover across regulated sectors. | A TIER 2 flaw in MaxKey’s OAuth 2.0 flow lets attackers hijack authorization codes through a simple hostname suffix trick. For any organization relying on open-source IAM/SSO for citizen or enterprise access, strict redirect validation and prompt patching are critical to prevent cascading identity compromises. |
| 4 | 2 | CVE-2026-12943 | Critical unauthenticated RCE in IBM HMC data center management infrastructure, explicitly impacting government, finance, and healthcare deployments running critical DPI workloads. | Unauthenticated remote code execution in IBM Hardware Management Console poses a silent but severe risk to regulated data centers. While internal-only by default, compromised HMC appliances can disrupt critical government, financial, and healthcare infrastructure—making patching and strict network segmentation essential for DPI operators. |
| 4 | 2 | CVE-2026-17543 | Critical SQL injection in PHP's ext-pgsql extension impacts foundational web stacks explicitly powering regulated sectors (Finance, Healthcare, Government, Digital Identity). | A trivially exploitable SQL injection in PHP’s core PostgreSQL extension threatens the web infrastructure underpinning public services and regulated sectors. Organizations running PHP 8.2–8.5 should prioritize patching or refactoring to prepared statements immediately. |
| 4 | 2 | CVE-2026-18140 | General-purpose AWS API infrastructure underpinning Finance, Healthcare, and Government digital services; unauthenticated DoS risks cascading failures in regulated cloud deployments. | A trivially exploitable DoS in AWS’s core JSON parsing library could take down public-facing APIs across finance, healthcare, and government sectors. Patching aws-smithy-json to 0.62.7 is critical for any regulated cloud service relying on unauthenticated endpoints. |
| 4 | 2 | CVE-2026-54363 | Critical unauthenticated RCE in perimeter-facing enterprise file-sharing platform with AD integration, posing direct risk to regulated sector deployments managing sensitive documents. | Unauthenticated RCE in Gladinet CentreStack (CVE-2026-54363) exploits a hardcoded crypto key to forge admin tokens. With default public-facing deployment and AD integration, regulated organizations must patch immediately to prevent full domain compromise. |
| 4 | 2 | CVE-2026-68500 | Directly impacts Finance DPI by enabling unauthenticated payment fraud and compromising transaction integrity in public-facing e-commerce payment gateways. | Unauthenticated attackers can mark arbitrary orders as paid without transferring funds, exposing merchants to scalable financial fraud. Critical for Finance DPI: payment gateway integrity is non-negotiable—patch or implement webhook validation immediately. |
| 3 | 2 | CVE-2026-15435 | Critical unauthenticated path traversal in enterprise integration middleware explicitly noted for government, healthcare, and financial data exchange pipelines. | IBM App Connect Enterprise faces a critical path traversal flaw (CVSS 9.8) enabling arbitrary file writes in integration layers. Teams using ACE for cross-sector data exchange should prioritize patching and network segmentation to safeguard DPI pipelines. |
| 3 | 2 | CVE-2026-17651 | General infrastructure flaw in Chrome for Android that impacts mobile access to finance, government, and enterprise services, requiring immediate patching. | A TIER 2 sandbox escape in Chrome for Android poses a direct risk to mobile devices used for banking and public sector access. Ensure all enterprise and field devices are updated to v151.0.7922.72+ to prevent full device compromise. |
| 3 | 2 | CVE-2026-17670 | General infrastructure browser vulnerability affecting endpoints used to access government, healthcare, and financial DPI portals. | Chrome sandbox escape (CVE-2026-17670) poses a Tier 2 risk to DPI access endpoints. While requiring prior renderer compromise, patching is critical for staff and citizens interacting with public sector and regulated service portals. |
| 3 | 2 | CVE-2026-58066 | SAML authentication vulnerability in Rocket.Chat impacts enterprise identity federation and secure collaboration infrastructure. | SAML flaws in collaboration tools like Rocket.Chat underscore the importance of securing optional identity integrations. Even with low EPSS, misconfigured SAML can compromise enterprise access controls. |
| 3 | 2 | CVE-2026-66066 | Critical unauthenticated RCE and file-read flaw in Ruby on Rails Active Storage impacts public-facing web services across all DPI sectors relying on this framework. | Public-facing Rails applications face critical exposure to unauthenticated RCE via crafted image uploads. DPI teams using Rails for citizen or regulated services should prioritize patching or enable libvips untrusted blocking immediately. |
| 2 | 2 | CVE-2026-14522 | TIER 2 enterprise integration middleware that may underpin government, healthcare, or financial data exchanges, requiring urgent patching to prevent RCE in backend routing systems. | IBM App Connect Enterprise faces a high-severity RCE flaw (CVE-2026-14522) with no vendor workarounds. While typically internal, integration middleware often bridges critical public and financial services—patching is essential to protect backend data flows. |
| 2 | 2 | CVE-2026-17701 | General infrastructure risk: Chrome sandbox escape impacts endpoint security across regulated sectors (Finance, Healthcare, Government) relying on standard web access. | A TIER 2 Chrome sandbox escape on macOS underscores the ongoing endpoint hygiene challenge for regulated sectors. While exploitation requires chaining, timely patching is essential to protect government, healthcare, and financial service endpoints from lateral movement. |
| 2 | 2 | CVE-2026-17705 | Foundational browser vulnerability impacting cross-sector DPI service access; requires enterprise patching to secure endpoints used for government, finance, and healthcare portals. | A high-severity Chrome sandbox escape risk demands immediate patching across enterprise and public-sector fleets. While user interaction is required, the ubiquitous deployment makes it a critical baseline defense for protecting access to digital identity, finance, and government services. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-10535.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-11536.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-11707.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-11771.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-11885.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-11897.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-11980.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12932.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12945.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12946.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12947.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13435.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13444.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13584.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14519.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14980.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15240.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15929.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16524.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16526.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16527.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16529.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16727.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16969.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17653.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17654.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17656.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17657.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17658.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17660.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17661.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17663.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17665.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17666.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17669.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17671.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17672.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17675.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17676.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17677.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17678.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17680.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17681.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17682.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17684.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17685.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17686.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17687.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17688.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17692.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17694.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17695.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17697.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17698.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17699.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17704.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17708.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17709.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17710.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17711.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17712.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17713.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17716.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17718.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17719.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17721.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17722.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17723.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17725.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17727.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17741.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17744.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17750.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17751.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17752.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17758.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17774.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17778.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17786.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17807.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17816.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17836.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17861.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17862.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17863.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17864.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17867.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17868.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17875.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17877.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17881.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17884.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17886.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17887.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17888.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17894.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17896.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17898.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17899.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17916.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17918.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17920.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17922.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17924.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17930.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17935.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17940.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17947.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17948.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17950.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17951.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17952.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17956.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17967.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17969.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17971.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17979.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17987.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17989.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17990.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17991.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17993.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17995.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18002.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18012.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18015.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18017.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18064.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18186.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18187.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18188.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18360.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18361.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18378.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18381.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-22620.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-22621.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-22622.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-28323.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-41703.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-44090.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-44091.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-44092.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-44093.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-44094.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-44095.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-44096.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-44097.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-44098.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-44099.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-44100.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-44101.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-44104.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-44106.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-44107.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-44108.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47858.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47873.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47876.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48499.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-4978.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-51290.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-5219.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56428.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57859.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57862.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58043.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58222.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-5846.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62246.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62663.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63035.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63362.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63550.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63559.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64816.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-6540.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65421.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66360.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66364.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66369.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66416.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66418.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66720.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67244.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67245.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67247.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67248.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67348.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67527.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68502.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68503.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-7260.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-9322.md` — heuristic TIER 3/4
- `TIER_4_CVE-2024-25039.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-51291.md` — heuristic TIER 3/4
