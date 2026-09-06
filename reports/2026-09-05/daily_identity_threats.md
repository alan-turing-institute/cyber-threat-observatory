# Daily identity and access threats

- **Report date:** 2026-09-05
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-75754

**PIR:** 1.b · **CVSS:** 10.0

Missing Authentication for Critical Function, Server-Side Request Forgery (SSRF), and Use of Hard-coded Credentials in ASUS Control Center allow an unauthorized user to obtain the encryption key via an HTTP request, causing a local service to enable SSH on port 2222. The attacker can then log in with the hardcode credentials to obtain a root shell, enabling direct reading, writing, and deletion of data on ASUS Control Center, as well as remote control of all servers, PCs, and workstations within

## CVE-2026-85595

**PIR:** 1.b · **CVSS:** 9.3

Traefik versions before v2.11.55 contain an authentication bypass vulnerability in the digestAuth middleware where unknown usernames receive an empty secret instead of rejection. Attackers can compute a valid digest response using the empty secret and arbitrary credentials to bypass authentication on any digestAuth-protected route without a valid username or password.

## CVE-2026-86117

**PIR:** 1.b · **CVSS:** 9.2

Coolify through 4.3.17 contains an authentication bypass vulnerability in the OAuth callback handler that signs users into existing accounts based solely on email address without verifying provider assertions or binding OAuth identities. Attackers can register a victim's email address on any enabled OAuth provider to obtain authenticated sessions as that user, bypassing password requirements and two-factor authentication.

## CVE-2026-9317

**PIR:** 1.b · **CVSS:** 9.2

Nango before 0.71.6 contains a missing authentication vulnerability in the runner tRPC server that allows unauthenticated attackers to execute arbitrary JavaScript code by invoking the exposed start procedure without credentials. Attackers with network access to the runner port can send requests to the unauthenticated start procedure, bypassing the unenforced RUNNER_SECRET_KEY environment variable, to achieve remote code execution within the runner process.

## CVE-2026-85596

**PIR:** 1.b · **CVSS:** 8.2

Traefik versions >= v3.7.0 and <= v3.7.10 contain an authentication bypass in the Kubernetes Ingress NGINX provider. The TLS option generated for an Ingress carrying the nginx.ingress.kubernetes.io/auth-tls-secret annotation was named after the Ingress namespace and name. As a result, two Ingress objects sharing the same host, the same client CA secret, and the same client-authentication mode produced two distinct TLS option names for that host. Traefik treats this as a TLS options conflict and 

## CVE-2026-18221

**PIR:** 1.b · **CVSS:** 8.1

IBM i 7.6, 7.5, 7.4, and 7.3 could allow a remote attacker to gain unauthorized access due to improper validation of client-supplied authentication parameters.

## CVE-2026-53603

**PIR:** 1.b · **CVSS:** 7.1

nebula-mesh is a self-hosted control plane for Slack Nebula mesh VPN. Prior to version 0.3.8, Operator session tokens are stored in plaintext in the operator_sessions table (the token column is the PRIMARY KEY). The session token is a 32-byte random hex value sent directly in a cookie and valid for 24 hours. Anyone who can read the database (backup, snapshot, file copy, or SQL-level disclosure) obtains every active session token and can hijack operator sessions directly, with no further authenti

