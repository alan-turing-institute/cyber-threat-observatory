# Daily identity and access threats

- **Report date:** 2026-08-02
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-67327

**PIR:** 1.b · **CVSS:** 8.7

better-auth versions >= 1.1.3 and < 1.6.22 (and pre-release versions >= 1.7.0-beta.0 and < 1.7.0-beta.10) are vulnerable to account takeover via pre-account hijacking on magic-link and email-OTP sign-in when open email/password registration is enabled. An attacker registers an account with the victim's email address and an attacker-chosen password; the account remains unverified. When the legitimate owner later signs in via the magic-link or email-OTP passwordless flow, the account is marked ver

## CVE-2026-18571

**PIR:** 1.b · **CVSS:** 6.6

A flaw was found in the user creation component of Keycloak when Fine-Grained Admin Permissions V2 (FGAP V2) is enabled. This issue allows a sub-administrator with permission to create users to add those users to any group, even groups the sub-administrator is not authorized to manage. This could lead to unauthorized access to sensitive information or elevated privileges for the newly created users.

## CVE-2026-18573

**PIR:** 1.b · **CVSS:** 6.5

A flaw was found in the keycloak-services component of Keycloak, which is used for managing authentication and authorization flows. The issue occurs when a realm administrator configures client policies to enforce specific authentication requirements on confidential clients. Due to improper evaluation of the client state during an update operation, an attacker with client management permissions can bypass these security policies by first creating a public client and then updating it to a confide

## CVE-2026-18572

**PIR:** 1.b · **CVSS:** 6.5

Keycloak provides authorization services that allow administrators to restrict access to resources based on time policies (for example, only allowing access during business hours). A flaw was discovered where a user can include a fake time value in their authorization request that overrides the actual server time. This allows the user to bypass these time-based restrictions and access protected resources at unauthorized times.

## CVE-2026-67332

**PIR:** 1.b · **CVSS:** 6.4

@better-auth/oauth-provider before 1.7.0-beta.4 fails to bind access-token audience to the authorization grant, allowing clients to request tokens for unrelated resources. Attackers can complete an OAuth flow and obtain access tokens whose audience targets resource servers the authorization never covered, bypassing intended authorization boundaries.

## CVE-2026-67335

**PIR:** 1.b · **CVSS:** 6.0

better-auth versions before 1.6.2 fail to validate the OAuth state parameter against the stored nonce when using cookie-backed state storage without PKCE. Attackers can forge the state parameter and supply an attacker-controlled authorization code to create authenticated sessions bound to the attacker's external identity or persistently link attacker accounts to victim profiles.

## CVE-2026-18570

**PIR:** 1.b · **CVSS:** 5.4

A flaw was found in the full-scope-disabled client-policy executor within the keycloak-services component. This component is responsible for enforcing security policies during client registration and configuration in Red Hat Build of Keycloak. The issue occurs because the executor only validates the fullScopeAllowed field when it is explicitly provided in a request. By omitting this field, a delegated user can bypass the policy, resulting in a client created with full scope access. This allows t

