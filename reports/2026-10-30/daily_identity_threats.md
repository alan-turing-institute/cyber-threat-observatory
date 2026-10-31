# Daily identity and access threats

- **Report date:** 2026-10-30
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-63377

**PIR:** 1.b · **CVSS:** 9.8

TAKO AI Agent for Okta is a local-first AI agent that helps Okta administrators query tenant data using natural language. Prior to 3.0.1-beta, `POST /api/auth/setup` in `src/api/routers/auth.py` allows an unauthenticated network attacker to create the first administrator account before the legitimate owner completes initial setup. The `initial_setup` function checks only the `is_setup` completion flag and requires no authentication, one-time bootstrap token, or network restriction. The default `

## CVE-2026-116239

**PIR:** 1.b · **CVSS:** 8.9

In server mode pgAdmin 4 keeps an account per authentication source, so the same username can exist as, for example, an internal account and an LDAP account. After LDAP or Kerberos authenticated a user, pgAdmin chose the account to log in by username alone, or took the account Flask-Security's login form had looked up, without checking that it came from the source that authenticated the user. The session therefore belonged to another account, with its role, its servers and its saved database pas

## CVE-2026-63378

**PIR:** 1.b · **CVSS:** 8.8

TAKO AI Agent for Okta is a local-first AI agent that helps Okta administrators query tenant data using natural language. Prior to 3.0.1-beta, any authenticated user with a valid `fctr_session` cookie can submit arbitrary Python source in the `script_code` field of `POST /api/react/execute-script`, without administrator privilege. In `src/api/routers/react_stream.py`, the source is stored with `skip_discovery=True`, bypassing AI-based content filtering, and is passed to `validate_generated_code`

## CVE-2026-92744

**PIR:** 1.b · **CVSS:** 8.7

Under certain conditions, privilege manager agent allows a remote unauthenticated attacker to execute
arbitrary code as LocalSystem.

## CVE-2026-115829

**PIR:** 1.b · **CVSS:** 8.7

In Secret Server versions earlier than 12.3.1, a user could bypass the initial login step and authenticate by successfully negotiating the second factor login step only.

## CVE-2026-115830

**PIR:** 1.b · **CVSS:** 8.7

In Secret Server versions earlier than 12.3.1, a user under certain conditions could submit an unsigned JWT and receive cloudadmin permissions in response.

