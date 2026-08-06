# Architecture decisions

## One transport path

New HTTP code uses the v2 transport. Legacy helpers remain only for migration compatibility.

## Fail-closed scope

Active target requests require a positive scope decision. An explicit deny rule takes precedence over implicit root-domain/subdomain allowance.

## Evidence before severity

Verified findings require evidence references. Severity is assigned after verification rather than inferred solely from the detector name.

## Incremental migration

The existing module entry point is retained until bundled modules have moved to the shared runtime.
