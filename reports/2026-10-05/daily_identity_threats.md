# Daily identity and access threats

- **Report date:** 2026-10-05
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-88779

**PIR:** 1.b · **CVSS:** 8.7

Vulnerability in NetScaler ADC and NetScaler Gateway.

This issue affects ADC: before 14.1-73.41, before 13.1-64.28, before 14.1-73.41 FIPS, and before 13.1-37.282; Gateway: before 14.1-73.41 and before 13.1-64.28.

## CVE-2026-105207

**PIR:** 1.b · **CVSS:** 9.8

ZITADEL 3.0.0 through 3.4.15 and 4.0.0 before 4.17.3 creates links between user accounts and external identity providers without verifying a primary factor or the caller's permission, including on identify-only Login V2 sessions and via the User Service V2 AddIDPLink endpoint. An unauthenticated attacker knowing a victim's login name can bind their own external IdP identity to the victim's account and then sign in as the victim.

## CVE-2026-105213

**PIR:** 1.b · **CVSS:** 8.8

ZITADEL 4.x before 4.17.1 does not check an organization's inactive state during Login V2 authentication, verifying only the individual user's status. Users of a deactivated organization who hold valid credentials, an existing session, or a refresh token can still sign in, create sessions, and obtain or refresh tokens.

## CVE-2026-105210

**PIR:** 1.b · **CVSS:** 8.8

ZITADEL 3.x before 3.4.15 and 4.x before 4.17.1 contains a missing authentication flaw in the hosted Login V1 UI, whose second-factor enrollment and initialization handlers act on an identify-only session before any primary factor is verified. Attackers knowing only a victim's login name can enroll attacker-controlled TOTP, OTP-SMS, OTP-Email, or U2F factors, overwrite the verified phone number, and enumerate users through discrepant errors.

## CVE-2026-105212

**PIR:** 1.b · **CVSS:** 8.7

ZITADEL 3.x before 3.4.14 and 4.x before 4.16.2 contains an authentication bypass in the hosted Login V1 and Login V2 UIs that accepts passkey or other authenticator enrollment on identify-only login sessions, before any primary factor is verified. Unauthenticated attackers knowing only a victim's login name can register an attacker-controlled authenticator and log in as that user, bypassing existing passwords and MFA.

## CVE-2026-59358

**PIR:** 1.b · **CVSS:** 7.6

Improper authentication (CWE-287) in the OAuth token endpoint in Cloud Foundry UAA allows a remote, authenticated attacker holding a valid user access token to obtain a fully-privileged client_credentials token for the OAuth client that issued it, by presenting the user token as an OAuth 2.0 Bearer credential on a client_credentials grant request in place of the client’s configured secret.



UAA’s client_credentials handling does not verify that the Bearer credential supplied for client authent

## CVE-2026-105307

**PIR:** 1.b · **CVSS:** 7.3

A vulnerability was detected in Casdoor up to 3.161.1. Affected is the function ApiFilter of the file routers/authz_filter.go of the component API Endpoint. Performing a manipulation results in missing authentication. The attack can be initiated remotely. The exploit is now public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

## CVE-2026-105306

**PIR:** 1.b · **CVSS:** 6.5

A flaw was found in the Dynamic Client Registration flow of the Keycloak identity and access management server. The issue occurs because the registration process fails to filter security-sensitive client attributes when a new client is created. An attacker with a valid Initial Access Token can register a client that bypasses audience checks during token introspection. This allows the attacker to view sensitive identity information, roles, and session details from access tokens belonging to other

## CVE-2026-105302

**PIR:** 1.b · **CVSS:** 5.7

A flaw was found in the User Session Note mapper of the Keycloak identity and access management solution. The issue occurs because the mapper does not validate whether a requested session note contains sensitive internal credentials, such as federated access tokens from external identity providers. This allows a delegated client administrator to leak a user's upstream bearer tokens into the tokens issued to their managed application, potentially leading to unauthorized access to the user's data 

## CVE-2026-105305

**PIR:** 1.b · **CVSS:** 5.4

A flaw was found in the OIDC implementation of Keycloak, specifically within the Device Authorization Grant flow. This component allows devices with limited input capabilities to obtain security tokens. The issue occurs because the flow fails to check the minimum authentication level required by a client configuration. This allows an attacker who has stolen a user's password to bypass mandatory multi-factor authentication and gain unauthorized access to the Keycloak Admin REST API.

