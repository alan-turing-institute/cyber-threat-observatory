# Daily identity and access threats

- **Report date:** 2026-10-25
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-116163

**PIR:** 1.b · **CVSS:** 9.1

Parse Server before 8.6.102 and 9.0.0 before 9.10.5-alpha.2 contains an authentication bypass because the validateSetUp, validateLogin, and validateUpdate methods of custom adapters subclassing AuthAdapter are never called, and an inherited default that accepts any authData is used instead. Attackers can supply arbitrary authData to sign up, link identities, log in as existing users, or skip custom additional authentication factors.

## CVE-2026-116006

**PIR:** 1.b · **CVSS:** 7.3

A vulnerability was detected in YunaiV/zhijiantianya ruoyi-vue-pro up to 2026.09. The affected element is an unknown function of the file AuthController.java of the component SMS Code Verification. The manipulation of the argument mobile/code results in improper authentication. The attack can be launched remotely. The exploit is now public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

