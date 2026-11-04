# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-11-04 15:15:04Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-11-03`
- **Included count:** 7

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-121543 | Direct Digital Identity sector impact: default authorization bypass in an open-source SSO/IdP enables full identity provider takeover and downstream service compromise. | A default authorization flaw in the smart-sso identity provider allows any authenticated user to escalate to admin, risking full takeover of SSO infrastructure. Critical for Digital Identity deployments managing citizen or enterprise access. |
| 5 | 2 | CVE-2026-4052 | Core IdAM/SSO token issuance flaw in WSO2 Identity Server allows privilege escalation to admin APIs, directly impacting digital identity boundaries and credential scoping. | A critical authorization bypass in WSO2 Identity Server could allow low-privilege users to escalate to admin-level API access, threatening the integrity of enterprise SSO and token-based identity boundaries. Organizations relying on WSO2 for digital identity infrastructure should prioritize patching and audit key manager configurations. |
| 5 | 2 | CVE-2026-46487 | Foundational software for government Spatial Data Infrastructures (SDI); unauthenticated bypass exposes restricted civic geospatial metadata. | GeoNetwork, the backbone of many national Spatial Data Infrastructures, faces a trivial unauthenticated flaw that bypasses access controls on public-facing portals. Governments and public institutions must patch immediately to protect sensitive geospatial metadata. |
| 4 | 2 | CVE-2026-119215 | Digital Identity: Authorization bypass in an Elixir/Phoenix auth library allows MFA/TOTP secret hijacking and account takeover, impacting enterprise and public-sector identity platforms. | A TIER 2 flaw in a popular Elixir authentication library lets attackers hijack MFA secrets and lock out users. While it requires custom API exposure, any public-sector or enterprise identity platform using ash_authentication should audit their GraphQL/JSON API routes immediately. |
| 4 | 2 | CVE-2026-95731 | Foundational data center orchestration tool with hardcoded admin credentials, posing high lateral-movement risk to internal networks underpinning Finance, Healthcare, and Government digital services. | Hardcoded credentials in HPE’s Fabric Composer give attackers instant admin control over internal data center networks. While not internet-facing by default, this TIER 2 flaw is a critical lateral-movement vector for any organization relying on enterprise networking to run regulated digital public services. |
| 3 | 2 | CVE-2026-114550 | Unauthenticated RCE in a foundational MQTT library used across IoT telemetry stacks in healthcare, government, and finance deployments. | A TIER 2 unauthenticated RCE in libwebsockets exposes internet-facing MQTT brokers and IoT gateways to full compromise. Critical for any DPI architecture relying on device telemetry across healthcare, government, or financial infrastructure. |
| 3 | 2 | CVE-2026-92188 | Unauthenticated SYSTEM RCE in enterprise database monitoring software widely deployed across Finance, Government, and Healthcare to secure critical backend assets. | Internal database monitoring tools are critical to regulated sectors, but unauthenticated RCE flaws like CVE-2026-92188 turn them into high-value lateral movement targets. Patching and strict network segmentation are essential to protect Finance, Government, and Healthcare infrastructure. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2022-30267.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103653.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103916.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104608.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105979.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105980.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105982.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109593.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112354.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112917.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-113421.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115231.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115290.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115294.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115714.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115732.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115878.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116650.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116651.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118487.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118489.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118623.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118627.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118628.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119084.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119675.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119741.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119742.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119922.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120330.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120572.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120678.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120757.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120775.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120830.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120833.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120952.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120955.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120956.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121382.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121386.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121388.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121392.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121393.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121394.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121395.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121398.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121400.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121402.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121404.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121407.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121409.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121412.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121416.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121417.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121419.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121423.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121437.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121444.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121448.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121449.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121506.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121554.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121559.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121561.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121565.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121614.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121621.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13594.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16900.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-22058.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-28335.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-28336.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-39379.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54161.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57154.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63469.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63470.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63471.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63482.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63489.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63500.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63502.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65168.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77691.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77777.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77778.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77799.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77800.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82158.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82159.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82976.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85035.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89293.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92187.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93325.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95722.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95723.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95724.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95725.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95726.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95727.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95728.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95732.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95733.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95734.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95735.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95736.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95737.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95738.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95739.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95740.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95741.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95742.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95743.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95744.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95745.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95746.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95747.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95748.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95749.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95750.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95751.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95752.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95753.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-99246.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-99264.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-99269.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-99270.md` — heuristic TIER 3/4
