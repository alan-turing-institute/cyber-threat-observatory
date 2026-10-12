# Daily identity and access threats

- **Report date:** 2026-10-11
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-108865

**PIR:** 1.b · **CVSS:** 8.8

AmoyLab Unla through 0.10.0 contains an authentication bypass vulnerability that allows unauthenticated attackers to obtain valid access tokens because the OAuth2 server never authenticates a resource owner. Attackers can register a client, request a code from /authorize, and exchange it at /token to access OAuth2-protected MCP prefixes, proxied upstream APIs and injected credentials.

