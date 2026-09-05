# Daily identity and access threats

- **Report date:** 2026-09-04
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-83711

**PIR:** 1.b · **CVSS:** 10.0

Authorization bypass through user-controlled key in Microsoft Azure Active Directory B2C allows an unauthorized attacker to elevate privileges over a network.

## CVE-2026-85595

**PIR:** 1.b · **CVSS:** 9.3

Traefik versions before v2.11.55 contain an authentication bypass vulnerability in the digestAuth middleware where unknown usernames receive an empty secret instead of rejection. Attackers can compute a valid digest response using the empty secret and arbitrary credentials to bypass authentication on any digestAuth-protected route without a valid username or password.

## CVE-2026-62916

**PIR:** 1.b · **CVSS:** 9.1

Authentication bypass using an alternate path or channel in Microsoft Entra ID allows an unauthorized attacker to elevate privileges over a network.

## CVE-2026-80465

**PIR:** 1.b · **CVSS:** 8.8

A vulnerability has been identified in Mendix SAML (Mendix 10 compatible) (All versions < V4.2.3), Mendix SAML (Mendix 11 compatible) (All versions < V4.2.3), Mendix SAML (Mendix 9.24 compatible) (All versions < V3.6.27). Affected versions of the module do not properly validate the SAML response signature. This could allow unauthenticated remote attackers to hijack an account (session) in specific SSO configurations.

## CVE-2026-85596

**PIR:** 1.b · **CVSS:** 8.2

Traefik versions >= v3.7.0 and <= v3.7.10 contain an authentication bypass in the Kubernetes Ingress NGINX provider. The TLS option generated for an Ingress carrying the nginx.ingress.kubernetes.io/auth-tls-secret annotation was named after the Ingress namespace and name. As a result, two Ingress objects sharing the same host, the same client CA secret, and the same client-authentication mode produced two distinct TLS option names for that host. Traefik treats this as a TLS options conflict and 

## CVE-2026-84831

**PIR:** 1.b · **CVSS:** 7.7

SEPPmail Secure Email Gateway before 15.0.7 creates a fully privileged session before required multi-factor authentication enrollment is completed. An attacker with the password for an MFA-required but unenrolled account can access protected functionality without providing a second factor.

## CVE-2026-85238

**PIR:** 1.b · **CVSS:** 7.6

MISP contains a session fixation vulnerability in the CustomAuth authentication (a custom configuration) flow. When a user was successfully authenticated through CustomAuth, MISP stored the authenticated user identity in the existing session without first rotating the session identifier.


As a result, if an attacker can cause a victim to use a session identifier known to the attacker before authentication, that same session identifier remains valid after the victim successfully authenticates. T

## CVE-2026-8862

**PIR:** 1.b · **CVSS:** 7.5

IBM Netezza Software 11.3.0.3 through Interim Fix 002 has credentials that are hardcoded in the application source code, allowing unauthorized access to the container registry. The exposed secret enables attackers to pull private container images, potentially revealing proprietary code, configuration details, and other sensitive information.

## CVE-2026-53603

**PIR:** 1.b · **CVSS:** 7.1

nebula-mesh is a self-hosted control plane for Slack Nebula mesh VPN. Prior to version 0.3.8, Operator session tokens are stored in plaintext in the operator_sessions table (the token column is the PRIMARY KEY). The session token is a 32-byte random hex value sent directly in a cookie and valid for 24 hours. Anyone who can read the database (backup, snapshot, file copy, or SQL-level disclosure) obtains every active session token and can hijack operator sessions directly, with no further authenti

## CVE-2026-85700

**PIR:** 1.b · **CVSS:** 7.1

Onyx 4.6.6 fails to properly restrict access to custom tool credentials stored in custom_headers, allowing any authenticated user to read admin-defined API keys. Attackers with basic authentication can call GET /tool/{tool_id} or GET /tool endpoints to retrieve plaintext authorization headers and third-party API credentials, then use them to directly access upstream APIs.

