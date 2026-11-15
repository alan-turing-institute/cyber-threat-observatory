# Daily identity and access threats

- **Report date:** 2026-11-14
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-129110

**PIR:** 1.b · **CVSS:** 9.8

sysPass 3.0.1 through 3.2.11 contains an authentication bypass vulnerability that allows unauthenticated attackers to reinstall an already-installed instance by POSTing to the install/install handler, which never checks isInstalled(). Attackers can overwrite config.xml, point the application at an attacker-controlled database, create an administrator account, and plant serialized PublicLink gadget chains triggered via account/viewLink to execute commands.

## CVE-2026-126310

**PIR:** 1.b · **CVSS:** 8.7

OpenBao before 2.6.5 and 2.7.2 contains an authentication bypass vulnerability that allows unauthenticated callers to obtain OIDC ID tokens by abusing public clients with client_credentials enabled. Attackers who know a public client's client_id can request tokens from the identity/oidc/provider/<name>/token endpoint to impersonate the client without any secret.

## CVE-2026-107413

**PIR:** 1.b · **CVSS:** 8.7

Memory overflow in SAML authentication can lead to unpredictable or erroneous behavior or Denial of Service in Citrix NetScaler ADC and Citrix NetScaler Gateway.

## CVE-2026-111342

**PIR:** 1.b · **CVSS:** 8.7

Memory overflow in LDAP authentication can lead to unpredictable or erroneous behavior or Denial of Service in Citrix NetScaler ADC and Citrix NetScaler Gateway.

