# Daily identity and access threats

- **Report date:** 2026-10-26
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-116163

**PIR:** 1.b · **CVSS:** 9.1

Parse Server before 8.6.102 and 9.0.0 before 9.10.5-alpha.2 contains an authentication bypass because the validateSetUp, validateLogin, and validateUpdate methods of custom adapters subclassing AuthAdapter are never called, and an inherited default that accepts any authData is used instead. Attackers can supply arbitrary authData to sign up, link identities, log in as existing users, or skip custom additional authentication factors.

## CVE-2026-89209

**PIR:** 1.b · **CVSS:** 7.6

A vulnerability has been identified in Mendix SAML (Mendix 10 compatible) (All versions < V4.2.4), Mendix SAML (Mendix 11 compatible) (All versions < V4.2.4), Mendix SAML (Mendix 9 compatible) (All versions < V3.6.29). Affected versions of the module do not properly protect against SAML assertion replay in IdP-initiated authentication flows. This could allow unauthenticated remote attackers to gain unauthorized access to the application by replaying a valid SAML response.

## CVE-2026-116006

**PIR:** 1.b · **CVSS:** 7.3

A vulnerability was detected in YunaiV/zhijiantianya ruoyi-vue-pro up to 2026.09. The affected element is an unknown function of the file AuthController.java of the component SMS Code Verification. The manipulation of the argument mobile/code results in improper authentication. The attack can be launched remotely. The exploit is now public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

## CVE-2026-115910

**PIR:** 1.b · **CVSS:** 6.8

Python Social Auth is a social authentication and registration mechanism. Prior to 6.2.0, OpenIdConnectAuth in social_core/backends/open_id_connect.py uses get_and_store_nonce to place the OpenID Connect nonce in a shared OpenIdConnectAssociation table, and get_nonce and validate_claims verify only that the nonce exists and has not expired rather than binding it to the browser session and OAuth state that initiated the login. An attacker who obtains a victim's unused authorization code can start

## CVE-2026-71455

**PIR:** 1.b · **CVSS:** 5.3

Cleartext storage of sensitive information in memory vulnerability in Johnson Controls Kantech Entrapass allows Retrieve Embedded Sensitive Data.

This issue affects Kantech Entrapass: before 9.20.

