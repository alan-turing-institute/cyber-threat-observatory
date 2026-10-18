# Daily identity and access threats

- **Report date:** 2026-10-13
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-109372

**PIR:** 1.b · **CVSS:** 9.3

ZITADEL 4.x before 4.19.2 and 3.x through 3.4.15 contains an authentication bypass in the SAML identity-provider intent callback, which verifies the assertion signature using the provider named in the request URL but resolves the user from the login intent without checking they match. Attackers with organization-administrator permission can register a SAML provider with their own signing key to obtain authenticated sessions as any user linked to another SAML provider on the instance, including i

## CVE-2026-53997

**PIR:** 1.b · **CVSS:** 9.1

Netherman Portal del Hermano (portaldelhermano.es) before 2026-10-06 contains a broken authentication vulnerability in its password-recovery flow at the POST /password/create-access and POST /password/email endpoints, allowing unauthenticated attackers to take over any member account across all tenants by exploiting the lack of rate limiting and distinct error messages that act as oracles for each of the four identity-verification factors (DNI, date of birth, phone number, last four IBAN digits)

## CVE-2026-63160

**PIR:** 1.b · **CVSS:** 9.1

Omnispace Agora Project before 26.10.0 contains a vulnerability where the persistent remember-me token is stored verbatim server-side, making the stored value identical to the bearer credential held in the user's cookie. Attackers who gain access to the stored token, such as through database or backup disclosure, can replay the plaintext value to authenticate as the victim user without needing their password.

## CVE-2026-63159

**PIR:** 1.b · **CVSS:** 9.1

Omnispace Agora Project before 26.10.0 contains a predictable password-reset token vulnerability that allows unauthenticated attackers to take over user accounts by computing the reset token as sha1(login.password), a deterministic and reusable value. Attackers can derive or brute-force the reset token from known or guessed login and password combinations to forge valid password-reset requests and hijack arbitrary accounts.

## CVE-2026-93909

**PIR:** 1.b · **CVSS:** 9.1

IBM WebSphere Application Server - Liberty 17.0.0.3 through 26.0.0.10 is vulnerable by an authentication bypass vulnerability when samlWeb-2.0 feature is enabled.

## CVE-2026-109371

**PIR:** 1.b · **CVSS:** 8.8

ZITADEL 3.0.0 before 4.18.0 contains a missing authentication vulnerability in the hosted Login V1 UI, where the change-username handler acts on the account bound to a login flow before any factor is verified. Unauthenticated attackers can submit a victim's login name and then post a new username to rename any active human user, including administrators, locking them out.

## CVE-2026-70580

**PIR:** 1.b · **CVSS:** 8.8

Missing authentication for critical function in Windows Credential Guard allows an authorized attacker to perform spoofing locally.

## CVE-2026-77910

**PIR:** 1.b · **CVSS:** 8.8

Incorrect authorization in Microsoft Exchange Server allows an authorized attacker to elevate privileges over a network.

## CVE-2026-84313

**PIR:** 1.b · **CVSS:** 8.8

Nginx UI is a web user interface for the Nginx web server. Prior to 2.4.1, POST /api/otp_enroll and POST /api/finish_passkey_register are registered outside RequireSecureSession and accept a normal authenticated session without verifying the current password. An attacker with a stolen JWT can bind an attacker-controlled TOTP secret when the victim has not already enabled TOTP, or can register an attacker-controlled passkey because that path has no equivalent existing-enrollment guard. These chan

