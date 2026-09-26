# Daily identity and access threats

- **Report date:** 2026-09-25
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-94606

**PIR:** 1.b · **CVSS:** 8.9

authentik is an open-source identity provider. Prior to 2026.2.7, 2026.5.7, and 2026.8.2, authentik email authenticator enrollment during an authentication or enrollment flow accepts a recipient address supplied in the setup request instead of using the address already established by the flow. An actor who knows a target user's password can substitute an attacker-controlled address, receive the one-time code, and finish enrolling the factor as the target. The target must not have enrolled the em

## CVE-2026-94609

**PIR:** 1.b · **CVSS:** 8.8

authentik is an open-source identity provider. Prior to 2026.2.7, 2026.5.7, and 2026.8.2, an account with delegated permission to manage a group, group membership, or a user can grant superuser status to an account or assign an existing role to a group without holding the permissions that gate those privileges. Group hierarchy checks do not consistently account for superuser status inherited from ancestor groups, and role assignment to a group lacks the required authorization check. Only deploym

## CVE-2026-85056

**PIR:** 1.b · **CVSS:** 8.2

ZITADEL is an open source identity management platform. From 4.0.0 until 4.16.1, ZITADEL Login V2 creates a browser session after password verification and can reuse that session for a later authentication request without verifying a user's enrolled TOTP, OTP, or U2F second factor. When the MFA step is abandoned and login starts again, session-validity checks require MFA only when the organization enables Force MFA or Force MFA for local users only, so a voluntarily enrolled factor can be skippe

## CVE-2026-94611

**PIR:** 1.b · **CVSS:** 8.1

authentik is an open-source identity provider. Prior to 2026.2.7, 2026.5.7, and 2026.8.2, authentik API serializers return stored credentials when an account has view permission on an affected configuration, even when that account is not authorized to change the configuration or read its secrets. Affected configurations include one-time code delivery by mail or SMS, outbound provisioning targets, device trust integrations, identity sources, the Kubernetes outpost integration, applications using 

## CVE-2026-57178

**PIR:** 1.b · **CVSS:** 7.4

Python Social Auth is a social authentication/registration mechanism. Prior to version 5.0.0, the `vk-app` backend accepted VK application callback data without verifying the callback signature when the `auth_key` parameter was omitted. Applications using this backend could treat unsigned attacker-controlled data as a verified VK identity. An attacker could choose callback fields such as `viewer_id`, `access_token`, `api_id`, and `api_result`, potentially allowing authentication as an arbitrary 

## CVE-2026-94612

**PIR:** 1.b · **CVSS:** 7.4

authentik is an open-source identity provider. Prior to 2026.2.7, 2026.5.7, and 2026.8.2, an authentik SAML Source verifies an assertion's signature and validity period but does not ensure that the identity provider issued the assertion for that Source or in response to a login request from that Source. The SAML Source also does not record already accepted assertions, allowing replay. An unauthenticated actor who possesses such a valid assertion can use an assertion intended for another service 

## CVE-2026-97846

**PIR:** 1.b · **CVSS:** 6.8

Keycloak provides a feature called mTLS holder-of-key binding which ensures that a token can only be used by the client that originally requested it by binding it to their digital certificate. A flaw was discovered where the new Standard Token Exchange V2 feature does not check for this certificate. This allows an attacker with stolen client credentials to obtain a standard, unrestricted token that bypasses these security protections.

## CVE-2026-96448

**PIR:** 1.b · **CVSS:** 6.6

A flaw was found in the Fine-Grained Admin Permissions (FGAP v2) feature of Keycloak, an identity and access management solution. The issue occurs when the system checks if a delegated administrator has permission to assign a specific role to a user. Because the check does not look inside composite roles to see what other permissions they contain, an administrator with limited rights can assign a role that secretly includes full administrative control. This allows the attacker to gain complete m

## CVE-2026-97177

**PIR:** 1.b · **CVSS:** 6.6

A flaw was found in the user update mechanism of the Keycloak Admin REST API. When Fine-Grained Admin Permissions are enabled, the system fails to check for specific password reset authorizations during a general user profile update. This allows a delegated administrator, who should be restricted from resetting passwords, to change a user's credentials and take over their account.

## CVE-2026-57175

**PIR:** 1.b · **CVSS:** 6.4

Python Social Auth is a social authentication/registration mechanism. Prior to version 5.0.0, the SAML backend accepted SAML responses on the Assertion Consumer Service endpoint without verifying that they matched a previously issued `AuthnRequest`. Applications using SAML account association could allow an attacker with a valid account on a trusted IdP to link the attacker's SAML identity to a logged-in victim's local account. The attacker could then authenticate through SAML and gain access to

## CVE-2026-97311

**PIR:** 1.b · **CVSS:** 4.3

A flaw was found in the Admin REST API of Keycloak, an identity and access management solution. The endpoints used to retrieve groups associated with a specific role do not properly check for individual group visibility permissions. This allows a delegated administrator with basic search privileges to view detailed information about all groups assigned to a role, bypassing intended security restrictions that should limit their view to specific groups.

