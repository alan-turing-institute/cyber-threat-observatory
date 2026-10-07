# Daily identity and access threats

- **Report date:** 2026-10-06
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-106488

**PIR:** 1.b · **CVSS:** 8.1

Backstage is an open framework for building developer portals. Prior to 0.4.20, the @backstage/plugin-auth-backend-module-oidc-provider package is affected by improper authentication in the oidc provider. Deployments using OIDC email-based identity resolution with a provider that permits unverified email addresses may allow an authenticated provider user to assume another catalog identity. This may grant access and permissions associated with that user. No direct availability impact is demonstra

## CVE-2026-59358

**PIR:** 1.b · **CVSS:** 7.6

Improper authentication (CWE-287) in the OAuth token endpoint in Cloud Foundry UAA allows a remote, authenticated attacker holding a valid user access token to obtain a fully-privileged client_credentials token for the OAuth client that issued it, by presenting the user token as an OAuth 2.0 Bearer credential on a client_credentials grant request in place of the client’s configured secret.



UAA’s client_credentials handling does not verify that the Bearer credential supplied for client authent

## CVE-2026-105307

**PIR:** 1.b · **CVSS:** 7.3

A vulnerability was detected in Casdoor up to 3.161.1. Affected is the function ApiFilter of the file routers/authz_filter.go of the component API Endpoint. Performing a manipulation results in missing authentication. The attack can be initiated remotely. The exploit is now public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

## CVE-2026-106457

**PIR:** 1.b · **CVSS:** 6.8

Backstage is an open framework for building developer portals. From 0.1.0 until 0.5.0, the @backstage/plugin-auth-backend-module-cloudflare-access-provider package is affected by insufficient audience validation in the cloudflare access auth provider. The Cloudflare Access auth provider verifies a token's signature and team issuer, but affected versions do not verify that the token was issued for the Backstage application. A user holding a valid token for another Access application in the same C

## CVE-2026-106460

**PIR:** 1.b · **CVSS:** 6.8

Backstage is an open framework for building developer portals. From 0.3.0 until 0.6.15 and 0.7.5, the @backstage/plugin-auth-node package did not consistently honor explicit negative email verification during shared OAuth profile normalization. The affected paths include a selected profile email marked verified: false, a matching raw provider email marked email_verified: false, and an email obtained only from an ID token marked email_verified: false. Exploitation requires an admitted identity-pr

## CVE-2026-105306

**PIR:** 1.b · **CVSS:** 6.5

A flaw was found in the Dynamic Client Registration flow of the Keycloak identity and access management server. The issue occurs because the registration process fails to filter security-sensitive client attributes when a new client is created. An attacker with a valid Initial Access Token can register a client that bypasses audience checks during token introspection. This allows the attacker to view sensitive identity information, roles, and session details from access tokens belonging to other

