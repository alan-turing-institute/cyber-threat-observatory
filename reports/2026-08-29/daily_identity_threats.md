# Daily identity and access threats

- **Report date:** 2026-08-29
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-82466

**PIR:** 1.b · **CVSS:** 9.4

Rodauth before 2.46.0 contains an authentication bypass vulnerability in the webauthn_login route that allows logged-in users to authenticate as any other account. Attackers can exploit improper account resolution logic that falls back to session account identifiers instead of validating the credential binding to complete authentication as arbitrary users.

## CVE-2026-73208

**PIR:** 1.b · **CVSS:** 7.4

An attacker that holds a token intended for a different purpose can authenticate, because when an OAuth2 token response does not contain a scope claim, the audience claim is used in its place and checked against the configured required scopes. These are different concepts, and the audience claim does not describe what a token is allowed to do. A token that grants no relevant permissions can be accepted because its intended recipient value happens to match a configured scope name, granting access

