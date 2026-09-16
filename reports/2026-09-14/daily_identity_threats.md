# Daily identity and access threats

- **Report date:** 2026-09-14
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-76461

**PIR:** 3.k · **CVSS:** 9.8

A vulnerability in the email parsing of Cisco AsyncOS Software for Cisco Secure Email Gateway could allow an unauthenticated, remote attacker to execute arbitrary commands with root privileges on the underlying operating system.

This vulnerability is due to insufficient validation in the email parsing logic. An attacker could exploit this vulnerability by sending a crafted email message that contains malicious SQL statements through an affected device. A successful exploit could allow the att

## CVE-2026-21391

**PIR:** 1.b · **CVSS:** 9.5

An improper validation vulnerability exists within PingAM where a well-crafted request allows arbitrary or protected ID Token claims to be set or overridden. In certain configurations this could allow an attacker to bypass authentication controls via spoofing leading to privilege escalation or impersonation.

## CVE-2026-90961

**PIR:** 1.b · **CVSS:** 9.3

The LdapAuth and LinOTPAuth authentication plugins in MISP contain an authentication bypass vulnerability. Both LdapAuthenticate and LinOTPAuthenticate replace CakePHP's FormAuthenticate class but fail to replicate its _checkFields() input validation guard. As a result, the email and password fields extracted from the login request are passed to downstream authentication logic without verifying that they are non-empty strings.

In the LDAP authenticator, an empty or null password is forwarded to

## CVE-2026-90895

**PIR:** 1.b · **CVSS:** 8.4

Affected versions of MISP’s interactive CLI shell implement access control independently from the normal web application, causing several authorization inconsistencies.


The patch shows that CLI access could differ from the web application in multiple security-sensitive areas:

 - feed listings did not enforce the same lookup_visible restrictions for non-host-organisation users;
 - feed detail access did not enforce the same host-organisation/site-admin authorization as FeedsController::view();

## CVE-2026-53714

**PIR:** 1.b · **CVSS:** 7.4

Envoy Gateway is an open source project for managing Envoy Proxy as a standalone or Kubernetes-based application gateway. Prior to 1.7.4 and 1.8.1, the xDS gRPC server in GatewayNamespaceMode, configured through provider.kubernetes.deploy.type=GatewayNamespace, installs a JWT StreamInterceptor but no UnaryInterceptor, leaving every unary Fetch RPC unauthenticated. The streaming interceptor also authenticates only discoveryv3.DeltaDiscoveryRequest messages; a discoveryv3.DiscoveryRequest used by 

