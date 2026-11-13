# Daily identity and access threats

- **Report date:** 2026-11-10
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-120017

**PIR:** 1.b · **CVSS:** 10.0

SAP NetWeaver AS ABAP and ABAP Platform does not perform sufficient verification of incoming authentication assertions under certain configurations. An unauthenticated attacker could submit specially crafted data to bypass authentication and impersonate arbitrary users, including privileged accounts. Successful exploitation could cause a full system compromise, with the impact potentially extending to connected components and systems beyond the affected system. This results in a high impact on c

## CVE-2026-125297

**PIR:** 1.b · **CVSS:** 9.8

AsiaInfo Business Support System (BSS) 9.2.0 through 9.2.40 accepts unauthenticated requests via the management API '/bss/sysmgnt/api/'. A remote, unauthenticated attacker could provision a new account with administrative privileges or take over existing accounts, and perform other administrative actions. Fixed in 9.2.41.

## CVE-2026-126065

**PIR:** 1.b · **CVSS:** 9.8

OpenObserve is a cloud-native observability platform. Prior to 1.1.0, the shared authentication validator in src/api/common/src/auth/validator.rs accepts an empty or whitespace-only HTTP Basic password for an account whose password_ext value is missing or empty. SSO-provisioned and migration-created users can have this state, allowing an unauthenticated attacker who knows an affected user's email address and organization to authenticate on protected non-ingestion API routes with the victim's rol

## CVE-2026-121683

**PIR:** 1.b · **CVSS:** 9.4

Missing authentication in Ivanti Cloud Services Application version 5.0.8 allows a remote unauthenticated attacker to add and delete arbitrary trusted EPM Core certificate entries.

## CVE-2026-119446

**PIR:** 1.b · **CVSS:** 9.4

Session Fixation vulnerability in the CLI login flow in nerves-hub nerves_hub_web allows an unauthenticated attacker to obtain an API token for another user's account via a crafted login link. Starting a CLI login with POST /api/auth/cli_session needs no authentication and returns a polling token, a confirmation URL that carries that token, and a confirmation code. When a signed-in user opens that URL and clicks Confirm, NervesHub.Accounts.verify_cli_session_token/2 creates an API token for the 

## CVE-2026-60046

**PIR:** 1.b · **CVSS:** 8.7

An unauthenticated remote attacker can perform password resets for any user with known username and email without rate limiting. This can result in a total loss of availabilit since the password will be reseted.

