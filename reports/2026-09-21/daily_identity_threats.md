# Daily identity and access threats

- **Report date:** 2026-09-21
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-94215

**PIR:** 1.b · **CVSS:** 5.5

A flaw was found in the Admin REST API of Keycloak, an open-source identity and access management solution. The issue occurs because the API uses a per-request in-memory cache to resolve clients by their unique identifier without verifying if the client belongs to the realm specified in the request path. This allows an administrator with limited privileges to read or modify sensitive client configurations in the master realm by accessing them through a realm they control. Successful exploitation

## CVE-2026-94213

**PIR:** 1.b · **CVSS:** 4.9

A flaw was found in the Authorization Services component of Keycloak, an open-source identity and access management solution. The issue occurs in the policy evaluation endpoint, which is used by administrators to test how access policies apply to specific users. Due to missing authorization checks, a delegated administrator with limited viewing privileges can access the full profile and role information of any user in the realm, even if they are not permitted to view user details. This could lea

## CVE-2026-94217

**PIR:** 1.b · **CVSS:** 3.5

A flaw was found in the User-Managed Access (UMA) implementation of Keycloak. The issue occurs in the authorization token endpoint when processing permission tickets. If two different users own resources with the same name, the system incorrectly merges the permissions from both resources when one user requests an authorization token. This allows an attacker to gain access scopes on a victim's resource that were never intended to be shared.

## CVE-2026-94218

**PIR:** 1.b · **CVSS:** 3.1

A flaw was found in the authentication session management of Keycloak, an identity and access management solution. The issue occurs when an administrator enforces a stronger authentication flow, such as mandatory two-factor authentication (2FA) setup, through a client policy. A user can bypass this requirement by manually visiting a specific session restart web link during the login process. This action clears the internal markers that track the required security steps, allowing the user to log 

