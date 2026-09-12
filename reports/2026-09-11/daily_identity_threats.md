# Daily identity and access threats

- **Report date:** 2026-09-11
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-80462

**PIR:** 1.b · **CVSS:** 10.0

A vulnerability in the Chef Automate API gateway and identity validation path may allow an unauthenticated actor to gain elevated access to protected Chef Automate functionality under specific conditions.

## CVE-2026-57967

**PIR:** 1.b · **CVSS:** 9.8

An unauthenticated remote attacker can craft a CORE protocol SESSION_REATTACH packet to steal an existing session and assume ongoing execution of the previously authenticated session.



This issue affects Apache Artemis: from 2.50.0 through 2.56.0; Apache ActiveMQ Artemis: from 1.0.0 through 2.44.0.



Users are recommended to upgrade to version 2.57.0, which fixes the issue.

## CVE-2026-82107

**PIR:** 1.b · **CVSS:** 9.6

IBM DataStage on Cloud Pak for Data 5.4.0.0 could allow a remote authenticated attacker to obtain sensitive information and bypass security restrictions due to improper authentication.

## CVE-2026-89042

**PIR:** 1.b · **CVSS:** 9.3

passport-saml-encrypted through 0.1.13 makes SAML signature verification conditional on an optional cert option, allowing attackers to bypass authentication by submitting unsigned SAML responses. Attackers can post forged SAML responses with arbitrary NameID and attributes to the assertion consumer service endpoint to receive authenticated profiles without valid signatures.

## CVE-2026-88007

**PIR:** 1.b · **CVSS:** 9.1

Traefik is an open source HTTP reverse proxy and load balancer. From 2.11.0 until 2.11.57 and 3.7.13, the HTTP/3 entrypoint ConnContext does not call service.AddTransportOnContext, so kerberosRoundTripper uses a shared backend transport instead of a transport dedicated to each frontend connection. With HTTP/3 enabled, a backend using connection-bound NTLM or Negotiate authentication, and backend keep-alive, an unrelated client can reuse a backend connection authenticated for a victim, read victi

## CVE-2026-89043

**PIR:** 1.b · **CVSS:** 9.1

passport-saml-encrypted through 0.1.13 contains an XML signature wrapping vulnerability where signature verification and assertion extraction use independent XPath lookups with no cross-validation. Attackers holding any validly signed SAML message can prepend a forged unsigned assertion that gets accepted as the verified identity while the genuine signature validates against the original assertion.

## CVE-2026-88895

**PIR:** 1.b · **CVSS:** 8.6

CyberPanel before 3.0.5 fails to enforce two-factor authentication on API endpoints, allowing attackers to bypass TOTP requirements using password-derived tokens. Attackers who obtain an administrator's password can derive API tokens and perform administrative operations or create authenticated sessions without the second factor.

## CVE-2026-0307

**PIR:** 1.b · **CVSS:** 8.5

Multiple local privilege escalation vulnerabilities in the Palo Alto Networks GlobalProtect™ app allows a local user to escalate their privileges to NT AUTHORITY\SYSTEM on Windows and root on macOS and Linux. This enables a non-administrative user to execute arbitrary commands with administrative privileges.



This GlobalProtect app on iOS, Android and ChromeOS is not impacted.

