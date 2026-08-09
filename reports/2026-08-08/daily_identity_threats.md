# Daily identity and access threats

- **Report date:** 2026-08-08
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-47662

**PIR:** 1.b · **CVSS:** 8.7

Pathling is a set of tools that make it easier to use FHIR and clinical terminology within health data analytics. Prior to version 2.0.0 of Pathling Server, Pathling's typed CRUD/search/batch FHIR surface allows an authenticated caller with only coarse operation authorities to act on attacker-chosen resource families because those entrypoints do not consistently enforce the documented per-resource `read` and `write` authorities. The documented authorization model requires an operation authority 

## CVE-2026-47660

**PIR:** 1.b · **CVSS:** 8.7

Pathling is a set of tools that make it easier to use FHIR and clinical terminology within health data analytics. Prior to version 2.0.0 of Pathling Server, Pathling's bulk-submit operation allows an allowed submitter to supply an explicit `oauthMetadataUrl` parameter that is not validated against `pathling.bulkSubmit.allowableSources`. When present, the bulk-submit OAuth flow trusts metadata and the returned `token_endpoint` from the caller-chosen location, then builds outbound OAuth client aut

