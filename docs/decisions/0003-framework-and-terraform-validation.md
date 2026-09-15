# Decision: measure framework coverage and validate suggestions independently

Status: implemented, September 14, 2026.

## Framework coverage

The report pipeline uses the unmodified HIPAA framework from Prowler 5.42.0, commit `73ae2eb1947a0912a05010a296f469bfa55ebe76`. The loader verifies its Git blob ID. This snapshot has 32 requirements and 95 distinct check IDs. The coverage command compares catalog handlers with this exact set, and reports separately identify how many framework check IDs appear in an upload.

Framework membership is not scan completeness: a check can produce many resource observations, missing permissions can suppress observations, and requirements can depend on scanner configuration. The original JSON retains upstream ConfigRequirements for later scanner integration. Imported data cannot establish whether those settings were used.

For matching findings, reports use the upstream check-to-requirement mappings with an eCFR link and an explicit Prowler source link. These remain low-confidence applicability mappings pending review. They are not claims that a setting is mandated by HIPAA or that implementing the suggestion establishes compliance. Unsupported findings retain these mappings but no invented code.

## Terraform validation

`scripts/validate_terraform.py` generates independent modules from every handler that emits code. It exercises known, missing, and malformed identifiers. It pins Terraform 1.14.0 and the AWS provider 6.0.0, initializes without a backend, and runs formatting and schema validation. Its subprocess environment excludes AWS credentials, profiles, user Terraform configuration, and variable overrides. It never runs plan or apply.

Validation is a development check, not an executable path in the web app. The provider download requires network access. A newer compatible provider can be adopted by deliberately changing the pin and rerunning the suite.

This checks syntax, references, argument names, and types. It does not prove correct business intent, resource ownership, compatible customer variables, applicability of a HIPAA mapping, or remediation of a live finding. Those remain separate acceptance checks.

References:

- [Prowler framework source](https://github.com/prowler-cloud/prowler/blob/73ae2eb1947a0912a05010a296f469bfa55ebe76/prowler/compliance/aws/hipaa_aws.json)
- [Terraform validate contract](https://developer.hashicorp.com/terraform/cli/commands/validate)
- [Pinned Terraform release](https://releases.hashicorp.com/terraform/1.14.0/)

## Checkpoint results

- Nine handlers total; six match the 95-check framework (the other three remain useful for imported general AWS scans).
- Terraform formatting and provider-schema validation passed for 24 examples across eight code-generating handlers. Root MFA remains manual guidance.
- 46 Python tests, Ruff, and strict mypy passed.
- Browser sample generation and expanded PDF citation pagination were checked locally.

Coverage is still incomplete. The next report work is additional reviewed handlers and explicit reconciliation of recommendations targeting shared resources. Customer authentication, live AWS scans, and deployment are also pending.
