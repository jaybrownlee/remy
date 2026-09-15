# Decision: flag possible shared-setting changes without merging findings

The report page and PDF now say “HIPAA mapping — needs review.” The legacy JSON confidence field is retained for compatibility; it is not a calculated score.

New reports compare the target inputs of the existing code-generating templates. Targets include account, setting, and resource, with a Region for regional controls. Account-wide and S3 bucket settings can overlap across observed Regions. Confirmed CloudTrail ARNs use their home Region. Missing or unconfirmed target information produces an explicit review note rather than an inferred match.

Items targeting the same setting link to each other in the report. PDF and JSON exports include the same notes, and the Terraform ZIP manifest includes targets, related item IDs, and groups. Every finding and suggestion stays separate. No Terraform is combined or applied.

This is a conservative overlap check, not full conflict or dependency analysis. Different settings on the same resource do not automatically overlap; dependencies such as shared KMS keys, S3 policy interactions, customer-supplied inputs, and existing state still require review. A zero-group result does not establish that suggestions can be applied together.

Report schema 1.1 adds optional coordination fields. Older snapshots are not retroactively assessed and retain their original JSON field sets when exported. Newly generated snapshots include and hash the new fields.

Validation: 55 Python tests pass, plus Ruff and strict mypy. Tests cover account and regional boundaries, bucket identity normalization, unknown targets, CloudTrail identity, links, ZIP contents, and legacy JSON compatibility. The existing saved report's label and all five pages of a synthetic overlap PDF were checked. Terraform template code was unchanged, so the prior 24-case Terraform validation remains applicable.
