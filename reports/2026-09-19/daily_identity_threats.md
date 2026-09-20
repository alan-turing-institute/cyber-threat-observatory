# Daily identity and access threats

- **Report date:** 2026-09-19
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-75878

**PIR:** 1.b · **CVSS:** 9.1

IBM Sterling File Gateway could allow a remote attacker to bypass authentication and obtain a fully authenticated session due to improper authentication via an unvalidated SSO header.

## CVE-2026-94000

**PIR:** 1.b · **CVSS:** 6.6

A flaw was found in the Admin REST API of Keycloak, an open-source identity and access management solution. The issue occurs in the group-membership endpoints where the system fails to check if a group grants administrative privileges before allowing a user to be added. This allows a delegated administrator with limited permissions to add themselves to a high-privilege group, potentially gaining full control over the entire realm.

