# Daily identity and access threats

- **Report date:** 2026-11-21
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-129073

**PIR:** 3.k · **CVSS:** 9.8

Authentication Bypass Using an Alternate Path or Channel vulnerability in miniOrange miniorange otp verification miniorange-otp-verification allows Authentication Abuse.This issue affects miniorange otp verification: from n/a through 5.6.1.

## CVE-2026-133659

**PIR:** 1.b · **CVSS:** 8.6

Flowintel contains multiple SSO identity and organisation trust boundary violations that collectively allow account takeover, privilege escalation, and unauthorized access to private case data.

- Keycloak SSO accepted unverified email claims, and all SSO providers (Keycloak, Entra ID, SimpleSAML) could resolve a claimed email address to an existing account that was created via a different sign-in method, enabling cross-provider account collision and unauthorized access to another user's account

## CVE-2026-134322

**PIR:** 1.b · **CVSS:** 8.6

better-auth 0.4.12-beta.7 before 1.7.16 and 1.8.0-beta.0 before 1.8.0-beta.5 contains an improper authentication vulnerability in the phone number plugin that lets sign-up and other flows save unverified phone numbers, which phone OTP sign-in then uses to select the account. Attackers can attach a victim's number to an attacker-controlled account so the victim's valid OTP sign-in yields a session for that account, exposing data the victim then enters.

## CVE-2026-55216

**PIR:** 1.b · **CVSS:** 8.1

Logto is the modern, open-source auth infrastructure for SaaS and AI apps. Prior to 1.46.0, social account linking can use an unverified email returned by the standard OAuth 2.0 or Azure AD connector to select an existing local account. When findSocialRelatedUser matches a victim's email and a request to POST /api/experience/identification enables linkSocialIdentity, an attacker who controls that unverified provider email can link an attacker-controlled social identity to the victim account and 

## CVE-2026-134312

**PIR:** 1.b · **CVSS:** 7.4

Better Auth 0.4.9 before 1.7.16 and 1.8.0-beta.0 before 1.8.0-beta.5 contains an OAuth sign-in authentication flaw that treats unverified provider emails as verified, including string "false" email_verified claims, unchecked generic OAuth profile/ID-token subject mismatches, and ignored Zoom provider options. Attackers holding a victim's address unverified at an affected provider can sign in, link to the victim's local account, and obtain its session.

## CVE-2026-134315

**PIR:** 1.b · **CVSS:** 7.4

better-auth 1.4.0 before 1.7.16 and 1.8.0-beta.0 before 1.8.0-beta.5 contains an improper authentication vulnerability because email-change links record the old and new addresses but not the requesting user. Attackers can open a still-valid link issued for their own account after a victim registers the attacker's released old address, gaining a session and changing the victim's email to one they control.

## CVE-2026-133652

**PIR:** 1.b · **CVSS:** 7.2

Flowintel , contained a session management vulnerability in its browser authentication mechanism. The session identifier used a bare numeric user ID rather than a credential-bound token, resulting in several related weaknesses:

- Remembered logins (remember-me cookies) remained valid after a user changed their password, allowing an attacker holding a previously issued cookie to retain access indefinitely.
- Server-side session identifiers were not rotated upon login (local, SSO, or remembered),

## CVE-2026-129074

**PIR:** 1.b · **CVSS:** 7.1

Missing Authorization vulnerability in miniOrange miniOrange's Google Authenticator miniorange-2-factor-authentication allows Exploiting Incorrectly Configured Access Control Security Levels.This issue affects miniOrange's Google Authenticator: from n/a through 6.6.0.

