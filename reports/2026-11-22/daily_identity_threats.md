# Daily identity and access threats

- **Report date:** 2026-11-22
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-134654

**PIR:** 1.b · **CVSS:** 8.6

Mailflare before 48957fb contains a host header injection vulnerability in the password-reset request handler that allows unauthenticated attackers to poison reset links when APP_URL is unset. Attackers can submit a reset request for a victim's email with a malicious Host header, capturing the single-use token when the victim clicks the link to take over the account.

## CVE-2026-134322

**PIR:** 1.b · **CVSS:** 8.6

better-auth 0.4.12-beta.7 before 1.7.16 and 1.8.0-beta.0 before 1.8.0-beta.5 contains an improper authentication vulnerability in the phone number plugin that lets sign-up and other flows save unverified phone numbers, which phone OTP sign-in then uses to select the account. Attackers can attach a victim's number to an attacker-controlled account so the victim's valid OTP sign-in yields a session for that account, exposing data the victim then enters.

## CVE-2026-134315

**PIR:** 1.b · **CVSS:** 7.4

better-auth 1.4.0 before 1.7.16 and 1.8.0-beta.0 before 1.8.0-beta.5 contains an improper authentication vulnerability because email-change links record the old and new addresses but not the requesting user. Attackers can open a still-valid link issued for their own account after a victim registers the attacker's released old address, gaining a session and changing the victim's email to one they control.

## CVE-2026-134312

**PIR:** 1.b · **CVSS:** 7.4

Better Auth 0.4.9 before 1.7.16 and 1.8.0-beta.0 before 1.8.0-beta.5 contains an OAuth sign-in authentication flaw that treats unverified provider emails as verified, including string "false" email_verified claims, unchecked generic OAuth profile/ID-token subject mismatches, and ignored Zoom provider options. Attackers holding a victim's address unverified at an affected provider can sign in, link to the victim's local account, and obtain its session.

## CVE-2026-134822

**PIR:** 1.b · **CVSS:** 5.1

Sustainsys.Saml2 before 1.0.4 and 2.x before 2.11.1 contains an improper signature verification vulnerability that allows attackers to tamper with signed parameters by exploiting mis-parsing in CheckSignature() of Saml2RedirectBinding.cs. Attackers can append data after an extra '=' in RelayState of an intercepted or replayed Redirect-binding message, causing applications to trust the tampered value.

