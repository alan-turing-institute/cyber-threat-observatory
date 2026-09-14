# Daily identity and access threats

- **Report date:** 2026-09-13
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-90474

**PIR:** 1.b · **CVSS:** 7.6

MCPHub before 1.0.32 contains an authentication bypass vulnerability in its embedded OAuth 2.0 authorization server where client authentication is disabled by default and PKCE enforcement is optional. Attackers who obtain an authorization code through interception can redeem it for access tokens without providing a client secret or PKCE verifier, gaining access to victim accounts and their privileges.

