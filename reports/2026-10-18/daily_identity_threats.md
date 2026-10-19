# Daily identity and access threats

- **Report date:** 2026-10-18
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-104627

**PIR:** 1.b · **CVSS:** 0.0

The Gitea OpenID association callback in the security settings accepted a positive OpenID 2.0 assertion without checking that the signed-in user had started the linking. Because OpenID 2.0 allows unsolicited assertions, an attacker-controlled OpenID provider could attach the attacker's identity to the account of a signed-in victim who opened a crafted link, and the attacker could then sign in as the victim through OpenID login, which does not apply the local TOTP or WebAuthn checks. The callback

