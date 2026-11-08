# Daily identity and access threats

- **Report date:** 2026-11-07
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-19868

**PIR:** 3.k · **CVSS:** 7.5

An authentication enforcement vulnerability in SonicOS SSLVPN service may allow a user with valid credentials for an alternate authentication method to bypass SAML authentication controls. Successful exploitation may also bypass SAML-enforced multi-factor authentication (MFA).

## CVE-2026-109469

**PIR:** 1.b · **CVSS:** 10.0

Authorization bypass through user-controlled key in Entra Device Registration allows an unauthorized attacker to elevate privileges over a network.

## CVE-2026-17158

**PIR:** 1.b · **CVSS:** 9.9

IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to gain elevated privileges due to improper authentication.

## CVE-2026-16720

**PIR:** 1.b · **CVSS:** 9.8

IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a remote attacker to obtain valid access tokens for other users due to improper authentication. Authentication against a connected directory service is not sufficiently enforced, which could allow another user's identity to be assumed.

## CVE-2026-63439

**PIR:** 1.b · **CVSS:** 9.8

2FAuth is a web app to manage Two-Factor Authentication (2FA) accounts and generate their security codes. Prior to 8.0.0, when AUTHENTICATION_GUARD=reverse-proxy-guard is enabled, ReverseProxyGuard::user() reads the default REMOTE_USER identity header, or a custom identity header selected by the AUTH_PROXY_HEADER_FOR_USER configuration setting, without confirming that the request originated from a configured trusted proxy. A remote client that can reach the application directly can forge the sel

## CVE-2026-63438

**PIR:** 1.b · **CVSS:** 9.8

2FAuth is a web app to manage Two-Factor Authentication (2FA) accounts and generate their security codes. Prior to 8.0.0, when AUTHENTICATION_GUARD=reverse-proxy-guard accepts authentication headers from a client that did not pass through a trusted proxy, RemoteUserProvider::retrieveById() creates an account for an unknown REMOTE_USER, promotes the first created account to administrator, and synchronizes the account email from the configured mail header. An unauthenticated remote client can ther

## CVE-2026-120984

**PIR:** 1.b · **CVSS:** 9.1

A flaw was found in the Keycloak server's client management component. When a client is created or imported with authorization services enabled, the system fails to properly clear an internal session attribute used during the setup process. This allows an authenticated attacker with client management permissions to bypass security controls and upload a malicious JavaScript policy, which is then executed on the server when an authorization request is made. Successful exploitation could allow the 

## CVE-2026-17324

**PIR:** 1.b · **CVSS:** 8.3

IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote attacker to access sensitive configuration data and perform unauthorized actions due to missing authentication for a critical function.

## CVE-2026-17358

**PIR:** 1.b · **CVSS:** 8.2

IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to bypass authentication across tenants due to improper authentication. Authentication checks are not sufficiently isolated between tenants, which could allow a user from one tenant to be accepted by another.

## CVE-2026-17326

**PIR:** 1.b · **CVSS:** 8.1

IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to bypass security restrictions due to improper authentication.

