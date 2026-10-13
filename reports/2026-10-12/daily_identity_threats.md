# Daily identity and access threats

- **Report date:** 2026-10-12
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-109575

**PIR:** 1.b · **CVSS:** 9.8

In HAProxy Data Plane API 2.2.0 through 3.4.3 (and corresponding Enterprise Edition releases), Server.ConfigureAPI() has process-global authentication logic that improperly drops security controls across multiple transport types. When a TLS Certificate Authority (tls_ca) is configured and a numeric TLS port (tls_port) is specified, the application globally disables Basic authentication on its shared internal request handler. Because this handler is shared concurrently among HTTP, HTTPS, and UNIX

## CVE-2026-109372

**PIR:** 1.b · **CVSS:** 9.3

ZITADEL 4.x before 4.19.2 and 3.x through 3.4.15 contains an authentication bypass in the SAML identity-provider intent callback, which verifies the assertion signature using the provider named in the request URL but resolves the user from the login intent without checking they match. Attackers with organization-administrator permission can register a SAML provider with their own signing key to obtain authenticated sessions as any user linked to another SAML provider on the instance, including i

## CVE-2026-53997

**PIR:** 1.b · **CVSS:** 9.1

Netherman Portal del Hermano (portaldelhermano.es) before 2026-10-06 contains a broken authentication vulnerability in its password-recovery flow at the POST /password/create-access and POST /password/email endpoints, allowing unauthenticated attackers to take over any member account across all tenants by exploiting the lack of rate limiting and distinct error messages that act as oracles for each of the four identity-verification factors (DNI, date of birth, phone number, last four IBAN digits)

## CVE-2026-84313

**PIR:** 1.b · **CVSS:** 8.8

Nginx UI is a web user interface for the Nginx web server. Prior to 2.4.1, POST /api/otp_enroll and POST /api/finish_passkey_register are registered outside RequireSecureSession and accept a normal authenticated session without verifying the current password. An attacker with a stolen JWT can bind an attacker-controlled TOTP secret when the victim has not already enabled TOTP, or can register an attacker-controlled passkey because that path has no equivalent existing-enrollment guard. These chan

## CVE-2026-108865

**PIR:** 1.b · **CVSS:** 8.8

AmoyLab Unla through 0.10.0 contains an authentication bypass vulnerability that allows unauthenticated attackers to obtain valid access tokens because the OAuth2 server never authenticates a resource owner. Attackers can register a client, request a code from /authorize, and exchange it at /token to access OAuth2-protected MCP prefixes, proxied upstream APIs and injected credentials.

## CVE-2026-109371

**PIR:** 1.b · **CVSS:** 8.8

ZITADEL 3.0.0 before 4.18.0 contains a missing authentication vulnerability in the hosted Login V1 UI, where the change-username handler acts on the account bound to a login flow before any factor is verified. Unauthenticated attackers can submit a victim's login name and then post a new username to rename any active human user, including administrators, locking them out.

## CVE-2026-85958

**PIR:** 1.b · **CVSS:** 7.5

Progress MarkLogic Server 12.x releases before 12.1.0 and 11.x releases before 11.3.7 contain an authentication validation weakness that could allow an attacker to use a token that should not be accepted by the affected server, which could result in unauthorized access.

## CVE-2026-85962

**PIR:** 1.b · **CVSS:** 7.5

Progress MarkLogic Server 12.x releases before 12.1.0 and 11.x releases before 11.3.7 contain an improper authentication vulnerability in SAML processing. In deployments that use SAML authentication, an unauthenticated remote attacker could cause the affected server to accept an assertion that should be rejected, potentially resulting in unauthorized access.

