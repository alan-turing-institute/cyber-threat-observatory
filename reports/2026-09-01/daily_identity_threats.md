# Daily identity and access threats

- **Report date:** 2026-09-01
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-82859

**PIR:** 1.b · **CVSS:** 9.8

hulumi versions before v1.3.2 contain a deployment SCP template that allows tag-on-create bypasses for hulumi:iac-role protections. Attackers can bypass intended IAM boundary restrictions by exploiting the weakened SCP template in downstream deployments.

## CVE-2026-82857

**PIR:** 1.b · **CVSS:** 9.8

hulumi versions before v1.3.2 contain a privilege escalation vulnerability in the weekly integration IAM policy that allows role lifecycle operations on af-e2e-* roles without sufficient boundary restrictions. Attackers with the documented principal can create persistent higher-privilege roles in the sandbox account.

## CVE-2026-84423

**PIR:** 1.b · **CVSS:** 7.3

A vulnerability has been found in Casdoor up to 4.0.0. This affects an unknown function of the file controllers/resource.go of the component upload-resource API. Such manipulation leads to missing authentication. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. The vendor deleted the GitHub issue for this vulnerability without any explanation. Afterwards the vendor was contacted early about this disclosure via email but did not respond i

## CVE-2026-84114

**PIR:** 1.b · **CVSS:** 6.3

A vulnerability has been found in Cleo Harmony up to 5.8.1.10. Impacted is the function LocalUserUtil.getNativeUserByAssertions of the component SAML Authentication. Such manipulation of the argument Email leads to improper authentication. The attack can be executed remotely. The exploit has been disclosed to the public and may be used. Upgrading to version 5.8.1.11 is recommended to address this issue. Upgrading the affected component is recommended.

