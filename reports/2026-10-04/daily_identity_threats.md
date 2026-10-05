# Daily identity and access threats

- **Report date:** 2026-10-04
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-88779

**PIR:** 1.b · **CVSS:** 8.7

Vulnerability in NetScaler ADC and NetScaler Gateway.

This issue affects ADC: before 14.1-73.41, before 13.1-64.28, before 14.1-73.41 FIPS, and before 13.1-37.282; Gateway: before 14.1-73.41 and before 13.1-64.28.

## CVE-2026-105207

**PIR:** 1.b · **CVSS:** 9.8

ZITADEL 3.0.0 through 3.4.15 and 4.0.0 before 4.17.3 creates links between user accounts and external identity providers without verifying a primary factor or the caller's permission, including on identify-only Login V2 sessions and via the User Service V2 AddIDPLink endpoint. An unauthenticated attacker knowing a victim's login name can bind their own external IdP identity to the victim's account and then sign in as the victim.

## CVE-2026-105210

**PIR:** 1.b · **CVSS:** 8.8

ZITADEL 3.x before 3.4.15 and 4.x before 4.17.1 contains a missing authentication flaw in the hosted Login V1 UI, whose second-factor enrollment and initialization handlers act on an identify-only session before any primary factor is verified. Attackers knowing only a victim's login name can enroll attacker-controlled TOTP, OTP-SMS, OTP-Email, or U2F factors, overwrite the verified phone number, and enumerate users through discrepant errors.

## CVE-2026-105115

**PIR:** 1.b · **CVSS:** 8.8

OpenAM before 16.1.3 contains an unauthenticated arbitrary class instantiation vulnerability in the legacy JAX-RPC SOAP interface that allows remote attackers to load classes without authentication. Attackers can send SOAP requests to /jaxrpc/* with an unverified session identifier and a chosen class name, crashing the server, probing the classpath, or potentially reaching code execution via gadget chains.

## CVE-2026-105213

**PIR:** 1.b · **CVSS:** 8.8

ZITADEL 4.x before 4.17.1 does not check an organization's inactive state during Login V2 authentication, verifying only the individual user's status. Users of a deactivated organization who hold valid credentials, an existing session, or a refresh token can still sign in, create sessions, and obtain or refresh tokens.

## CVE-2026-105212

**PIR:** 1.b · **CVSS:** 8.7

ZITADEL 3.x before 3.4.14 and 4.x before 4.16.2 contains an authentication bypass in the hosted Login V1 and Login V2 UIs that accepts passkey or other authenticator enrollment on identify-only login sessions, before any primary factor is verified. Unauthenticated attackers knowing only a victim's login name can register an attacker-controlled authenticator and log in as that user, bypassing existing passwords and MFA.

## CVE-2026-105119

**PIR:** 1.b · **CVSS:** 7.6

OpenAM before 16.1.3 applies its OAuth2 Provider PKCE enforcement only to authorization requests whose response_type is exactly code, so codes issued through OpenID Connect hybrid flows (code token, code id_token, code token id_token) carry no bound challenge. An attacker who intercepts such a code can redeem it for a public client's tokens with any non-empty code_verifier.

## CVE-2026-105120

**PIR:** 1.b · **CVSS:** 6.9

OpenAM before 16.1.3 contains an authorization bypass vulnerability in the sessions REST endpoint query operation that allows realm administrators to list sessions of every realm. Attackers holding delegated RealmAdmin privileges can supply a _queryFilter naming another realm to disclose usernames, universal IDs, and session handles across tenant boundaries.

## CVE-2026-105121

**PIR:** 1.b · **CVSS:** 6.9

OpenAM before 16.1.3 contains an improper authorization vulnerability that allows delegated administrators to destroy sessions outside their realms because realm checks use the requester's realm. Authenticated accounts holding the iplanet-am-session-destroy-sessions attribute can supply a target session identifier or handle to forcibly log out users in any realm.

## CVE-2026-105116

**PIR:** 1.b · **CVSS:** 6.1

OpenAM before 16.1.3 contains a latent cross-site scripting defect that places the SAML message, relay state and target URL unencoded into the load-balancer cookie bounce auto-submit page. If reachable with cookieHashRedirectEnabled set, crafted requests could execute script in the OpenAM origin, though an unrelated HTTP 500 failure prevents exploitation in released versions.

## CVE-2026-105114

**PIR:** 1.b · **CVSS:** 6.1

OpenAM before 16.1.3 contains a reflected cross-site scripting vulnerability that allows unauthenticated attackers to inject script by supplying crafted parameters rendered unencoded on the OAuth2 authorization error page. Attackers can lure victims to a crafted /oauth2/authorize link with repeated parameters to run JavaScript in the OpenAM origin, acting within existing sessions or redirecting to phishing pages.

## CVE-2026-105117

**PIR:** 1.b · **CVSS:** 6.1

OpenAM before 16.1.3 contains an email content injection vulnerability that allows unauthenticated attackers to control notification email wording via the forgotPassword and register actions on /json/{realm}/users. Attackers can supply subject and message fields to send phishing mail from the organisation's configured From address, or abuse register as a relay to arbitrary recipients.

## CVE-2026-105122

**PIR:** 1.b · **CVSS:** 5.4

OpenAM before 16.1.3 contains a server-side request forgery vulnerability that allows attackers able to register or modify OAuth 2.0 clients to make OpenAM fetch internal resources via an unvalidated jwks_uri. Attackers can trigger unauthenticated fetches through client-authentication and ID-token validation to probe internal hosts, metadata endpoints or local files, or exhaust request threads for denial of service.

## CVE-2026-105118

**PIR:** 1.b · **CVSS:** 4.7

OpenAM before 16.1.3 contains an open redirect vulnerability that allows unauthenticated attackers to redirect users by supplying an unverified id_token_hint to the /oauth2/connect/endSession endpoint. Attackers can name any realm client in a forged hint to redirect victims to any registered post-logout URI, enabling phishing that borrows the OpenAM host's trust.

