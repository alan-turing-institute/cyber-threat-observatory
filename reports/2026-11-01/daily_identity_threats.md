# Daily identity and access threats

- **Report date:** 2026-11-01
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-103898

**PIR:** 1.b · **CVSS:** 8.1

The Wp Social Login and Register Social Counter plugin for WordPress is vulnerable to Authentication Bypass in all versions up to, and including, 3.2.2. This is due to the social login REST callback registered at `/wp-json/wslu-social-login/type/{provider}/` with `permission_callback => __return_true` locating an existing WordPress account solely by the email string returned from the OAuth provider and calling `wp_set_auth_cookie()` without a password check, while the only verification guard — `

## CVE-2026-82840

**PIR:** 1.b · **CVSS:** 7.2

Session fixation in Apache Wicket.

org.apache.wicket.authroles.authentication.AuthenticatedWebSession is the authentication base class of Wicket's role-based security module, and its signIn(String, String) method is the entry point through which an application authenticates a session. Renewing the container session id at that point is the standard defence against an attacker who has fixed a session id in a victim's browser, and Wicket provides that renewal as org.apache.wicket.Session#changeSes

## CVE-2026-120263

**PIR:** 1.b · **CVSS:** 0.0

When `[oauth2_client].ACCOUNT_LINKING` is set to `auto` (not the default) and registration is enabled, the link-account sign-up form looked up the existing account to link by the user name or email submitted in the form instead of the identity asserted by the OAuth2 provider. An attacker with an account on a configured OAuth2 provider could submit another user's name, link their external identity to that Gitea account and be signed in as it without its password, including as an administrator. Th

