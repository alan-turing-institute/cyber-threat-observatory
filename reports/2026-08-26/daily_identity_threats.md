# Daily identity and access threats

- **Report date:** 2026-08-26
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-65956

**PIR:** 1.b · **CVSS:** 10.0

KubePi is a Kubernetes multi-cluster management panel. In versions up to and including 1.6.15, the SSO configuration API endpoints are exposed on the same public routing boundary as the SSO login and callback endpoints, so SSO, OIDC, and SAML management operations can be reached without administrator authorization. Because reading, creating, and updating the global SSO configuration is not restricted to administrators, an unauthorized or low-privileged user can inspect or alter the authenticatio

## CVE-2026-80192

**PIR:** 1.b · **CVSS:** 8.6

@better-auth/sso before 1.6.27 (and before 1.4.8 in the 1.4.x line and before 1.7.0-rc.5 in the 1.7 prerelease line) contains two domain-ownership flaws. When domain verification is disabled, automatic organization assignment accepts unverified provider domains, allowing an authenticated organization owner/administrator to register an SSO provider for an arbitrary domain and have users with matching email domains added to the attacker's organization with default member permissions. When domain v

