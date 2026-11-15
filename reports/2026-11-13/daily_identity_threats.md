# Daily identity and access threats

- **Report date:** 2026-11-13
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-129110

**PIR:** 1.b · **CVSS:** 9.8

sysPass 3.0.1 through 3.2.11 contains an authentication bypass vulnerability that allows unauthenticated attackers to reinstall an already-installed instance by POSTing to the install/install handler, which never checks isInstalled(). Attackers can overwrite config.xml, point the application at an attacker-controlled database, create an administrator account, and plant serialized PublicLink gadget chains triggered via account/viewLink to execute commands.

## CVE-2026-120869

**PIR:** 1.b · **CVSS:** 9.3

An unauthenticated attacker can bypass authentication controls to access restricted resources on the Citrix NetScaler Console appliance

## CVE-2026-19422

**PIR:** 1.b · **CVSS:** 9.1

Zohocorp ManageEngine DDI Central versions below 6301 is affected by an authentication bypass vulnerability in Windows DNS and DHCP agent synchronization APIs, allowing unauthenticated user to impersonate onboarded Windows servers and perform unauthorized DNS and DHCP modifications.

## CVE-2026-75869

**PIR:** 1.b · **CVSS:** 8.8

Zohocorp ManageEngine DDI Central versions below 6301 is affected by an authorization bypass and PowerShell command injection vulnerability that allowed authenticated non-administrative users to target unauthorized Windows DHCP subnets and potentially execute arbitrary commands on managed Windows DHCP servers through crafted DNS suffix values.

## CVE-2026-19421

**PIR:** 1.b · **CVSS:** 8.8

Zohocorp ManageEngine DDI Central versions below 6301 is affected by a PowerShell injection vulnerability due to insufficient validation of user-supplied TXT record values in Windows DNS operations.

