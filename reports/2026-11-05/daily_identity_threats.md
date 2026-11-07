# Daily identity and access threats

- **Report date:** 2026-11-05
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-19868

**PIR:** 3.k · **CVSS:** 7.5

An authentication enforcement vulnerability in SonicOS SSLVPN service may allow a user with valid credentials for an alternate authentication method to bypass SAML authentication controls. Successful exploitation may also bypass SAML-enforced multi-factor authentication (MFA).

## CVE-2026-109469

**PIR:** 1.b · **CVSS:** 10.0

Authorization bypass through user-controlled key in Entra Device Registration allows an unauthorized attacker to elevate privileges over a network.

## CVE-2026-63439

**PIR:** 1.b · **CVSS:** 9.8

2FAuth is a web app to manage Two-Factor Authentication (2FA) accounts and generate their security codes. Prior to 8.0.0, when AUTHENTICATION_GUARD=reverse-proxy-guard is enabled, ReverseProxyGuard::user() reads the default REMOTE_USER identity header, or a custom identity header selected by the AUTH_PROXY_HEADER_FOR_USER configuration setting, without confirming that the request originated from a configured trusted proxy. A remote client that can reach the application directly can forge the sel

## CVE-2026-63438

**PIR:** 1.b · **CVSS:** 9.8

2FAuth is a web app to manage Two-Factor Authentication (2FA) accounts and generate their security codes. Prior to 8.0.0, when AUTHENTICATION_GUARD=reverse-proxy-guard accepts authentication headers from a client that did not pass through a trusted proxy, RemoteUserProvider::retrieveById() creates an account for an unknown REMOTE_USER, promotes the first created account to administrator, and synchronizes the account email from the configured mail header. An unauthenticated remote client can ther

## CVE-2026-121639

**PIR:** 1.b · **CVSS:** 9.2

A Missing Authentication for Critical Function vulnerability in WatchGuard AuthPoint Gateway allows a remote unauthenticated attacker with network access to the AuthPoint Gateway host to disrupt authentication services and delete the local directory synchronization configuration.

## CVE-2026-117691

**PIR:** 1.b · **CVSS:** 9.1

A flaw was found in the SAML HTTP-Redirect binding implementation of Keycloak. The issue occurs because the server processes percent-encoded parameter names (like %53AMLResponse) while the signature verification logic only checks literal parameter names. An attacker can use this discrepancy to provide a crafted, unsigned SAML message that the server processes instead of a legitimately signed one, leading to full account takeover of federated users.

## CVE-2026-113373

**PIR:** 1.b · **CVSS:** 9.1

Sonatype Nexus Repository 3 Pro does not check the local account status when a user signs in through a configured SAML or OAuth2/OpenID Connect identity provider. A user whose account was disabled or locked by an administrator in Nexus Repository can sign in again with valid identity provider credentials for the same account, and then receives a new session with the roles of that account. The attacker needs no Nexus Repository session and no Nexus Repository privilege. The attacker needs a named

## CVE-2026-97175

**PIR:** 1.b · **CVSS:** 8.8

A flaw was found in the idp-auto-link authenticator of the keycloak-services component, which handles user identity federation. The issue occurs when Keycloak automatically links an incoming identity from an external provider to an existing local account based on an email address without verifying if the provider has validated that email. This can allow an attacker to take over a victim's account by using a matching unverified email address at a brokered provider.

