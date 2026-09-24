# Daily identity and access threats

- **Report date:** 2026-09-23
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-93952

**PIR:** 3.k · **CVSS:** 10.0

VeloCloud Orchestrator (VCO) on-prem has a security issue where this issue may allow a remote attacker to access privileged internal functionality and impact the VCO host. Successful exploitation may compromise the confidentiality, integrity, and availability of the orchestrator and data managed by the orchestrator.

Hosted, including Dedicated, versions of VCO were impacted and have already been patched.

## CVE-2026-94127

**PIR:** 3.k · **CVSS:** 9.8

When a BIG-IP APM access policy and an OAuth profile is configured on a virtual server, specific malicious traffic can lead to Remote Code Execution (RCE).

Impact:
This vulnerability allows an unauthenticated attacker to perform remote code execution. The BIG-IP system in Appliance mode is also vulnerable. This is a data plane issue; there is no control plane exposure.

 


Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

## CVE-2026-93616

**PIR:** 3.k · **CVSS:** 9.8

A directory traversal and file upload vulnerability allows an unauthenticated attacker to upload and execute arbitrary scripts on Check Point Management Server.

## CVE-2026-77244

**PIR:** 1.b · **CVSS:** 10.0

MCP Atlassian is a Model Context Protocol (MCP) server for Atlassian products (Confluence and Jira). Prior to 0.22.0, the HTTP transport accepts requests without a verified user identity and downstream fetcher construction falls back to the operator's globally configured Jira or Confluence credentials. A network client that can reach the MCP endpoint can invoke Atlassian tools as the operator, including read and write operations available to that account. The advisory traces the vulnerable input

## CVE-2026-77254

**PIR:** 1.b · **CVSS:** 9.1

MCP Atlassian is a Model Context Protocol (MCP) server for Atlassian products (Confluence and Jira). Prior to 0.22.0, requests to the HTTP MCP endpoint without a per-user identity are allowed to reach tool handlers, which then use globally configured Jira or Confluence credentials. A network caller can perform operations with the operator account's permissions unless the deployment has an independent authentication boundary. The advisory traces the vulnerable input and processing flow through st

## CVE-2026-17635

**PIR:** 1.b · **CVSS:** 9.1

IBM Financial Transaction Manager (FTM) for RedHat OpenShift could allow a remote attacker to perform unauthorized actions due to improper configuration of HTTP method-based security constraints.

## CVE-2026-17643

**PIR:** 1.b · **CVSS:** 8.8

IBM Financial Transaction Manager (FTM) for RedHat OpenShift could allow a local attacker to obtain sensitive information and perform unauthorized actions due to insufficiently protected credentials.

## CVE-2026-75791

**PIR:** 1.b · **CVSS:** 8.6

Zohocorp ManageEngine ADSelfService Plus versions before build 7001 are vulnerable to an authentication bypass vulnerability in the REST API.

## CVE-2026-18074

**PIR:** 1.b · **CVSS:** 8.2

IBM Financial Transaction Manager (FTM) for RedHat OpenShift could allow a remote attacker to perform unauthorized actions due to improper authentication and missing authorization.

## CVE-2026-96445

**PIR:** 1.b · **CVSS:** 6.8

A flaw was found in the Conditional OTP authenticator of Keycloak, an identity and access management solution. The issue occurs when the system evaluates specific HTTP headers to determine if a one-time password (OTP) should be skipped, but fails to verify if those headers came from a trusted source. This could allow an attacker who already has a user's password to bypass the second-factor authentication by providing a specially crafted header in their request.

## CVE-2026-95503

**PIR:** 1.b · **CVSS:** 6.8

A flaw was found in the Kerberos federation provider of Keycloak, an open-source identity and access management solution. When Kerberos password authentication is used without SPNEGO, the system fails to verify the identity of the Key Distribution Center (KDC) by requesting a server ticket. This allows an attacker on the same network to spoof the KDC and bypass the authentication process, potentially gaining unauthorized access to user accounts.

## CVE-2026-18124

**PIR:** 1.b · **CVSS:** 6.5

IBM Financial Transaction Manager (FTM) for RedHat OpenShift could allow a local attacker to obtain sensitive information due to insufficiently protected credentials.

