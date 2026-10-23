# Daily identity and access threats

- **Report date:** 2026-10-16
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-102764

**PIR:** 1.b · **CVSS:** 9.8

The vulnerability exists within internal components of BeyondTrust’s Remote Support product. The components did not adequately validate the origin of the messages it received. Under the right conditions, this could allow an attacker to perform file operations on the appliance.

## CVE-2026-111357

**PIR:** 3.k · **CVSS:** 7.0

Ivanti Connect Secure 22.8R2.4 mishandles the manner in which the dsinvoked broker trusts DSCache configuration data, leading to privilege escalation to root, as exploited in the wild in October 2026.

## CVE-2026-84731

**PIR:** 1.b · **CVSS:** 10.0

An unauthenticated remote attacker can bypass authentication and gain full access to administrative API endpoints in Nutanix Prism Element by including a crafted internal management HTTP header. The vulnerability is caused by a misconfiguration in the application's authentication filters.



Consequently, the server responds with a Set-Cookie header containing a valid JSESSIONID. This session cookie decodes to a JSON Web Token (JWT) granting maximum cluster administrative privileges. Successful 

## CVE-2026-105279

**PIR:** 1.b · **CVSS:** 9.3

In the default configuration, the archive accepts DICOM associations from an unregistered calling AE. A remote peer can use C-FIND and C-GET to enumerate and retrieve patient information and medical images. It can also use C-STORE to file fabricated study content under an existing patient identity.

