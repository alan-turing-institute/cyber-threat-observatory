# Daily identity and access threats

- **Report date:** 2026-08-28
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-59354

**PIR:** 1.b · **CVSS:** 9.6

In versions of Spring Security's OAuth2 Authorization Server module 7.0.0 through 7.0.4, when Dynamic Client Registration is explicitly enabled, the registration endpoint performs insufficient validation of certain client metadata fields supplied by the registering client. An attacker who possesses a valid Initial Access Token can register a malicious client with crafted metadata, which, depending on server configuration and how the metadata is later rendered or used, may result in Stored Cross-

## CVE-2026-81826

**PIR:** 1.b · **CVSS:** 9.1

Affected versions of Flowintel do not revoke existing authenticated sessions when a user’s password is changed.


This means that if an attacker already possesses a valid session—for example, from prior access or a stolen session token—the victim changing their password does not terminate that attacker’s access. The session remains usable until it expires naturally. The upstream commit describes this directly as:


“session keeps working until it expires.”

The fix detects password changes and e

