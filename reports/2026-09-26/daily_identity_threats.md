# Daily identity and access threats

- **Report date:** 2026-09-26
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-92609

**PIR:** 1.b · **CVSS:** 9.8

Session fixation in HTTP management authentication allows remote attackers to gain unauthorized access to an authenticated management session via reuse of a session identifier retained across successful authentication.

This issue affects Apache Qpid Broker-J: through 10.1.0.

Users are recommended to upgrade to version 10.1.1, which fixes the issue.

## CVE-2026-100684

**PIR:** 1.b · **CVSS:** 9.2

Budibase versions 3.41.0 before 3.45.0 contain an authentication bypass in the OIDC/SSO login path of @budibase/server. In sso.authenticate, when no existing user matches the incoming SSO subject, the server looks up pending user invites by the IdP-asserted email address alone — without validating an invite code and without an email_verified check (the email_verified gate protects only the existing-account lookup). An attacker who can register at an IdP that the tenant trusts for OIDC and assert

## CVE-2026-100607

**PIR:** 1.b · **CVSS:** 9.2

Flowise through 3.1.4 resolves SSO and local-password users solely by email without storing provider or subject identifier bindings, allowing attackers to authenticate as any existing user by claiming their email at any configured SSO provider. Attackers can gain complete account access including chatflows, credentials, and API keys by authenticating through a different SSO provider or local password than the victim's original registration method.

## CVE-2026-100606

**PIR:** 1.b · **CVSS:** 9.2

Flowise through 3.1.4 (Enterprise/platform mode with SSO enabled) contains an authentication bypass in the SSO login path. When an SSO callback arrives with an email matching a user whose status is INVITED, verifyAndLogin (SSOBase.ts:80-94) copies the user record from the database — including the server-stored single-use invitation tempToken — into the data passed to AccountService.register(). The register handler's token lookup, email match, and expiry checks therefore pass trivially against th

## CVE-2026-100709

**PIR:** 1.b · **CVSS:** 7.7

Froxlor through 2.3.10 stores only a numeric user ID in remembered-2FA tokens (panel_2fa_tokens) without recording the account namespace, and the remembered-token lookup during login is not constrained to the customer or administrator account type. Because customer and administrator IDs are allocated from separate namespaces, a remembered-2FA token legitimately issued to a customer with a given ID also matches an administrator with the same ID. An attacker who controls a customer account with a 

## CVE-2026-97846

**PIR:** 1.b · **CVSS:** 6.8

Keycloak provides a feature called mTLS holder-of-key binding which ensures that a token can only be used by the client that originally requested it by binding it to their digital certificate. A flaw was discovered where the new Standard Token Exchange V2 feature does not check for this certificate. This allows an attacker with stolen client credentials to obtain a standard, unrestricted token that bypasses these security protections.

## CVE-2026-96448

**PIR:** 1.b · **CVSS:** 6.6

A flaw was found in the Fine-Grained Admin Permissions (FGAP v2) feature of Keycloak, an identity and access management solution. The issue occurs when the system checks if a delegated administrator has permission to assign a specific role to a user. Because the check does not look inside composite roles to see what other permissions they contain, an administrator with limited rights can assign a role that secretly includes full administrative control. This allows the attacker to gain complete m

## CVE-2026-92289

**PIR:** 1.b · **CVSS:** 0.0

Lemonldap::NG::Portal versions from 2.23.0 before 2.23.4 for Perl allow a PKCE bypass for public Relying Parties in "PKCE or secret" mode because checkEndPointAuthenticationCredentials does not verify the client secret.

With oidcRPMetaDataOptionsRequirePKCE set to 2, the authorization endpoint issues a code even when the request carries no code_challenge, and token() admits the exchange as long as a challenge was stored or an authentication method was returned for the caller. checkEndPointAuthe

## CVE-2026-92288

**PIR:** 1.b · **CVSS:** 0.0

Lemonldap::NG::Portal versions from 2.20.0 before 2.21.6, from 2.22.0 before 2.23.4 for Perl allow unauthenticated OAuth2 token introspection because checkEndPointAuthenticationCredentials does not verify the client secret of a public Relying Party.

checkEndPointAuthenticationCredentials() skips the secret comparison for a Relying Party marked public and still returns the authentication method deduced from the request, client_secret_basic or client_secret_post. introspection() rejects a caller 

