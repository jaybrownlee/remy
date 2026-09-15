# Decision: treat IAM password checks as one account policy

Status: implemented, September 14, 2026.

Prowler 5.42.0 evaluates six separate HIPAA-framework checks for the IAM account password policy: lowercase, uppercase, number, symbol, minimum length 14, and password reuse prevention 24. AWS and the Terraform AWS provider expose one custom password policy per account, so Remy now maps all six findings to one shared setting instead of implying that each can be managed independently.

Each finding remains a separate report item with its own stable ID and upstream HIPAA mapping. Each item presents the same combined Terraform baseline for the six checked values. The overlap assessment groups those items by account and warns the customer to select one owning Terraform configuration. Remy does not merge or apply the suggestions.

Expiration, hard expiry, and self-service password changes affect the same policy but are not determined by these six scan results. They are required Terraform inputs without generated defaults. The guidance calls out immediate password-expiration effects, administrator-reset risk, the policy's limited scope, and the need for a separate MFA decision.

This is a reviewed technical mapping, not a conclusion that HIPAA prescribes Prowler's exact numeric or complexity baseline. Regulatory applicability remains marked for review.

Sources reviewed September 14, 2026:

- Prowler 5.42.0 check implementations at pinned commit `73ae2eb1947a0912a05010a296f469bfa55ebe76`.
- [AWS IAM account password policy](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html).
- [Terraform AWS provider 6.0.0 `aws_iam_account_password_policy`](https://github.com/hashicorp/terraform-provider-aws/blob/v6.0.0/website/docs/r/iam_account_password_policy.html.markdown).

Validation: unit tests cover all six catalog mappings, required unknown inputs, and grouping multiple findings into one account setting. The repository Terraform harness covers known, missing, and hostile observation variants without AWS credentials, plan, or apply.
