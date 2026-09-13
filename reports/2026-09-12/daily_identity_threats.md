# Daily identity and access threats

- **Report date:** 2026-09-12
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-90474

**PIR:** 1.b · **CVSS:** 7.6

MCPHub before 1.0.32 contains an authentication bypass vulnerability in its embedded OAuth 2.0 authorization server where client authentication is disabled by default and PKCE enforcement is optional. Attackers who obtain an authorization code through interception can redeem it for access tokens without providing a client secret or PKCE verifier, gaining access to victim accounts and their privileges.

## CVE-2026-90449

**PIR:** 1.b · **CVSS:** 6.9

When a particular authentication mode is configured, the reverse proxy forwards requests for a bundled third-party administrative interface directly to that interface without applying the gateway's own authentication requirement first. All access control for this administrative interface, which manages the credential store used to gate every other service in the deployment, is delegated entirely to that third-party interface's own login mechanism. Any authentication weakness in that bundled inte

## CVE-2026-89298

**PIR:** 1.b · **CVSS:** 4.9

A flaw was found in the Dynamic Client Registration service of Keycloak, an open-source identity and access management solution. The issue occurs when a user with the view-clients role accesses the client registration endpoint to retrieve client details. Due to a failure to mask sensitive information, the service returns the client's confidential secret in cleartext. This could allow a read-only administrator to obtain full access to the affected client's account and potentially escalate their p

