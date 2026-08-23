# Daily identity and access threats

- **Report date:** 2026-08-22
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-54789

**PIR:** 1.b · **CVSS:** 7.5

mod_auth_openidc is an OpenID Certified authentication and authorization module for the Apache 2.x HTTP server that implements the OpenID Connect Relying Party functionality. Prior to 2.4.19.4, an out-of-bounds read and a one-byte out-of-bounds write exist in the state-cookie parser of `mod_auth_openidc`. The issue is fixed in version 2.4.19.4 by stopping the scan at the string terminator so a value-less token is rejected. No in-product workarounds are available. As a stop-gap, an upstream rever

