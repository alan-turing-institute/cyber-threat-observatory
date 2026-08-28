# Daily identity and access threats

- **Report date:** 2026-08-27
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-65956

**PIR:** 1.b · **CVSS:** 10.0

KubePi is a Kubernetes multi-cluster management panel. In versions up to and including 1.6.15, the SSO configuration API endpoints are exposed on the same public routing boundary as the SSO login and callback endpoints, so SSO, OIDC, and SAML management operations can be reached without administrator authorization. Because reading, creating, and updating the global SSO configuration is not restricted to administrators, an unauthorized or low-privileged user can inspect or alter the authenticatio

## CVE-2026-59354

**PIR:** 1.b · **CVSS:** 9.6

In versions of Spring Security's OAuth2 Authorization Server module 7.0.0 through 7.0.4, when Dynamic Client Registration is explicitly enabled, the registration endpoint performs insufficient validation of certain client metadata fields supplied by the registering client. An attacker who possesses a valid Initial Access Token can register a malicious client with crafted metadata, which, depending on server configuration and how the metadata is later rendered or used, may result in Stored Cross-

## CVE-2026-64632

**PIR:** 1.b · **CVSS:** 8.5

A vulnerability allowing a low-privileged user to capture the NTLM credentials of the Reporter service account.

