# Daily identity and access threats

- **Report date:** 2026-09-20
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-94000

**PIR:** 1.b · **CVSS:** 6.6

A flaw was found in the Admin REST API of Keycloak, an open-source identity and access management solution. The issue occurs in the group-membership endpoints where the system fails to check if a group grants administrative privileges before allowing a user to be added. This allows a delegated administrator with limited permissions to add themselves to a high-privilege group, potentially gaining full control over the entire realm.

## CVE-2026-94001

**PIR:** 1.b · **CVSS:** 6.5

A flaw was found in the Admin REST API of Keycloak, an open-source identity and access management solution. The endpoint used for deleting user credentials does not correctly check for fine-grained reset-password permissions. This allows a delegated administrator, who should be restricted from resetting passwords, to delete a user's password credentials, resulting in the user being unable to log in.

## CVE-2026-93999

**PIR:** 1.b · **CVSS:** 4.2

A flaw was found in the OIDC protocol implementation of Keycloak, an open-source identity and access management solution. The issue occurs during the token refresh process when the server restores requested audiences from stored client IDs. Keycloak fails to verify if the target audience client is still enabled before issuing a new access token. This allows an application with an existing refresh token to continue obtaining valid access tokens for a disabled client, potentially bypassing adminis

