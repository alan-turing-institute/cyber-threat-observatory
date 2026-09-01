# Daily identity and access threats

- **Report date:** 2026-08-31
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-82859

**PIR:** 1.b · **CVSS:** 9.8

hulumi versions before v1.3.2 contain a deployment SCP template that allows tag-on-create bypasses for hulumi:iac-role protections. Attackers can bypass intended IAM boundary restrictions by exploiting the weakened SCP template in downstream deployments.

## CVE-2026-82857

**PIR:** 1.b · **CVSS:** 9.8

hulumi versions before v1.3.2 contain a privilege escalation vulnerability in the weekly integration IAM policy that allows role lifecycle operations on af-e2e-* roles without sufficient boundary restrictions. Attackers with the documented principal can create persistent higher-privilege roles in the sandbox account.

## CVE-2026-81888

**PIR:** 1.b · **CVSS:** 5.4

@hono/oauth-providers is Authentication middleware for Hono. Prior to version 0.8.6, the built-in social login providers accept an OAuth callback even when the `state` value is absent on both sides, so the anti-CSRF check passes for a callback that never came from a genuine login attempt. This defeats the `state`-based CSRF protection under default usage. Version 0.8.6 has a patch.

