# Daily identity and access threats

- **Report date:** 2026-09-03
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-83711

**PIR:** 1.b · **CVSS:** 10.0

Authorization bypass through user-controlled key in Microsoft Azure Active Directory B2C allows an unauthorized attacker to elevate privileges over a network.

## CVE-2026-19117

**PIR:** 1.b · **CVSS:** 9.8

Under specific conditions, an attacker can register an attacker-controlled FIDO2 credential against a target account and then authenticate as
that user. This issue affects on-premises deployments only.

## CVE-2026-84699

**PIR:** 1.b · **CVSS:** 9.3

Team Password Manager before 14.184.308 fails to enforce authentication requirements in the local account password reset flow. Unauthenticated attackers can reset local account passwords and authenticate as those users to gain unauthorized access.

## CVE-2026-62916

**PIR:** 1.b · **CVSS:** 9.1

Authentication bypass using an alternate path or channel in Microsoft Entra ID allows an unauthorized attacker to elevate privileges over a network.

## CVE-2026-84668

**PIR:** 1.b · **CVSS:** 8.8

Jenkins SAML Plugin 4.618.v441a_27fa_46d2 and earlier allows overwriting the SAML identity provider metadata file through Stapler data binding, allowing attackers to replace it with attacker-controlled content and authenticate as any user.

## CVE-2026-84672

**PIR:** 1.b · **CVSS:** 8.8

Jenkins Microsoft Entra ID (previously Azure AD) Plugin 710.v0b_ff8e9cc2d2 and earlier grants Entra group permissions using both the group's unique object ID and its display name, allowing attackers who can create an Entra group with a colliding display name to gain the permissions configured for a privileged group.

## CVE-2026-80465

**PIR:** 1.b · **CVSS:** 8.8

A vulnerability has been identified in Mendix SAML (Mendix 10 compatible) (All versions < V4.2.3), Mendix SAML (Mendix 11 compatible) (All versions < V4.2.3), Mendix SAML (Mendix 9.24 compatible) (All versions < V3.6.27). Affected versions of the module do not properly validate the SAML response signature. This could allow unauthenticated remote attackers to hijack an account (session) in specific SSO configurations.

## CVE-2026-84831

**PIR:** 1.b · **CVSS:** 7.7

SEPPmail Secure Email Gateway before 15.0.7 creates a fully privileged session before required multi-factor authentication enrollment is completed. An attacker with the password for an MFA-required but unenrolled account can access protected functionality without providing a second factor.

## CVE-2026-85238

**PIR:** 1.b · **CVSS:** 7.6

MISP contains a session fixation vulnerability in the CustomAuth authentication (a custom configuration) flow. When a user was successfully authenticated through CustomAuth, MISP stored the authenticated user identity in the existing session without first rotating the session identifier.


As a result, if an attacker can cause a victim to use a session identifier known to the attacker before authentication, that same session identifier remains valid after the victim successfully authenticates. T

