# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-09-02 23:13:13Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-09-01`
- **Included count:** 10

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-18765 | Government sector: Critical SQL injection in a public-facing Turkish municipal portal handling citizen permits and administrative services. | A critical SQL injection vulnerability in a Turkish government portal exposes sensitive citizen and business permit data to unauthenticated attackers. Public-facing civic services must prioritize immediate patching and input validation to safeguard national administrative infrastructure. |
| 5 | 2 | CVE-2026-84423 | Directly impacts Digital Identity infrastructure by allowing unauthenticated file uploads and identity spoofing in Casdoor, an open-source IdAM/SSO platform handling OAuth/OIDC/SAML flows. | Unauthenticated file uploads in public-facing IdAM gateways can poison audit trails and bypass authentication boundaries. Organizations relying on open-source SSO platforms like Casdoor should verify storage provider configurations and patch immediately to protect identity trust chains. |
| 4 | 2 | CVE-2026-4813 | Critical RCE in Lutece Core, a CMS framework widely deployed by European municipalities for citizen-facing government portals and smart city platforms. | Municipal governments relying on Lutece Core for public service portals face a critical RCE risk. While admin credentials are required, the public-facing nature of these civic platforms makes patching to v7.1.9 a top priority for local authorities. |
| 3 | 2 | CVE-2026-66357 | General infrastructure vulnerability in Erlang/OTP backend HTTP server, explicitly tied to fintech and telecommunications deployments behind reverse proxies. | HTTP request smuggling in Erlang/OTP’s backend server could bypass security controls in fintech and telecom architectures. Patch or harden reverse proxies to prevent desync attacks. |
| 3 | 2 | CVE-2026-73270 | Foundational Erlang/OTP runtime deployed across telecom, finance, and government; auth bypass in embedded HTTP server impacts management interfaces and internal APIs. | A case-sensitivity flaw in Erlang/OTP's embedded HTTP server allows unauthenticated access to protected directories on Windows/macOS. While Linux deployments are safe, regulated sectors relying on this foundational runtime should patch management interfaces and APIs. |
| 3 | 2 | CVE-2026-73276 | HTTP request smuggling in Erlang/OTP's inets library impacts proxied web services in fintech and enterprise backends, posing desync risks to regulated infrastructure. | Foundational runtimes like Erlang/OTP power critical fintech and telecom backends. This TIER 2 HTTP request smuggling flaw highlights how niche reverse-proxy configurations can still create desync vulnerabilities in regulated infrastructure—patch or harden your proxy headers. |
| 3 | 2 | CVE-2026-79687 | General enterprise storage infrastructure underpinning Healthcare, Finance, and Government workloads; unauthenticated filesystem access enables lateral movement and data exfiltration in regulated datacenters. | Unauthenticated filesystem access in Dell PowerStore storage arrays poses a silent lateral movement risk for regulated sectors. While deployed internally, compromised storage can expose critical healthcare, financial, and government data—highlighting the need for strict network segmentation and prompt patching. |
| 2 | 2 | CVE-2026-73812 | Tier 2 HTTP request smuggling in Erlang/OTP httpd, a foundational backend runtime explicitly noted for deployment across finance and government infrastructure. | HTTP request smuggling in Erlang/OTP’s httpd server (CVE-2026-73812) underscores a persistent desync risk for backend services behind reverse proxies. Though generic, its widespread use in finance and government stacks makes proxy hardening and header normalization a priority for regulated environments. |
| 2 | 2 | CVE-2026-75538 | Tier 2 DoS in Erlang/OTP runtime, a foundational backend platform for telecom and financial messaging systems. | A Tier 2 heap overflow in Erlang/OTP’s inet driver can crash BEAM VMs handling network traffic, posing a DoS risk to telecom and financial messaging backends that rely on this concurrency runtime. Patch or adjust packet framing to maintain service availability. |
| 2 | 2 | CVE-2026-84119 | Critical sandbox escape in foundational browser/email clients widely deployed across regulated enterprise and public sector environments. | A Tier 2 critical sandbox escape in Firefox and Thunderbird underscores the ongoing risk of client-side RCE in foundational enterprise tools. Immediate patching is vital to secure cross-sector digital workflows against drive-by compromises. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2023-54356.md` — heuristic TIER 3/4
- `TIER_3_CVE-2024-10085.md` — heuristic TIER 3/4
- `TIER_3_CVE-2024-14047.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-12768.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13336.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16675.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18630.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18771.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18780.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18931.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19118.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19472.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19766.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-25706.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-45221.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55951.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58566.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58567.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58569.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58571.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58572.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58575.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59680.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59681.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61750.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61751.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61752.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61753.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61754.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61755.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61756.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61757.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61758.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61759.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61760.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61761.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61762.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61763.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61764.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61765.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61766.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61767.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61768.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61769.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61770.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61771.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61772.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61773.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61774.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61775.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61776.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61777.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61778.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61779.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63137.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67394.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72649.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73700.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73701.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73702.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73703.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73704.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73706.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73707.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73708.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73709.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73710.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73712.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73713.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73714.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73716.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73717.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73718.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73719.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73720.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73721.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73722.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73723.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73724.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73725.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73749.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73750.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73751.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73752.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73753.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73763.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73764.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73765.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73766.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73767.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73768.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73770.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73771.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73774.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73775.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73776.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73778.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73779.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73780.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73781.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73782.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76111.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76851.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78592.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79682.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79683.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79684.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79686.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83549.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83551.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83607.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83612.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83616.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84149.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84165.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84189.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84190.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84192.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84194.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84195.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84196.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84199.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84200.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84203.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84204.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84205.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84218.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84233.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84235.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84361.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84366.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84370.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-8712.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-9634.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-9637.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-73715.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-73773.md` — heuristic TIER 3/4
