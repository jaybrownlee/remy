# Decision: require context before removing IAM credentials or permissions

Status: implemented, September 14, 2026.

Eight additional IAM checks now have reviewed guidance: access keys older than 90 days, access keys unused beyond the configured threshold, unused console passwords, three forms of administrative policy, and two forms of AWS Marketplace subscription policy.

Access-key rotation and removal remain manual because a saved finding does not identify every consumer or secret-distribution path. Remy directs customers toward temporary credentials, staged consumer migration, deactivation, observation, and deliberate deletion. It does not generate access keys or place secret material in Terraform state.

Unused console access is also manual. Removing a login profile affects password sign-in but does not revoke access keys, active sessions, or assumed-role access. Ownership, emergency-access purpose, other credentials, and the configured inactivity threshold must be reviewed first.

Administrative-policy findings are marked `needs_context` without generic Terraform. Prowler identifies an allow-all-actions/all-resources statement, but the report does not have the policy, attachments, job functions, access activity, permissions boundaries, resource policies, session policies, or Organizations controls needed to design a safe replacement. The guidance requires attachment inventory, least-privilege design, validation, workflow testing, staged rollout, and monitoring.

AWS Marketplace `Subscribe` has no resource type in the service authorization reference, so granting it requires a wildcard resource. Remy does not invent an ARN or claim the wildcard can be narrowed. It instead asks whether the principal should retain purchasing authority and recommends removing the action when it is not required or isolating and governing it when it is.

Sources reviewed September 14, 2026:

- Prowler 5.42.0 check implementations at pinned commit `73ae2eb1947a0912a05010a296f469bfa55ebe76`.
- [AWS secure access-key guidance](https://docs.aws.amazon.com/IAM/latest/UserGuide/securing_access-keys.html).
- [AWS IAM policy management](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_manage.html).
- [IAM Access Analyzer policy validation](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-validation.html).
- [AWS Marketplace service authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_marketplace-agreement.html).

Validation: tests cover status selection, absence of generated credentials and Terraform, migration-before-deletion language, effective-permission caveats, and the lack of resource-level authorization for `aws-marketplace:Subscribe`.
