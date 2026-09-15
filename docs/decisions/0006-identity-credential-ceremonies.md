# Decision: keep credential ceremonies manual

Status: implemented, September 14, 2026.

Three pinned HIPAA-framework checks now have reviewed manual guidance: active root access keys, root hardware MFA, and MFA for IAM users with console passwords. Remy emits no Terraform for these findings.

Root-key removal requires dependency discovery, migration to a least-privilege identity, deactivation, observation, and deliberate deletion. Deleting a key before replacing its consumers can cause an outage, and deleted credentials cannot be recovered.

MFA enrollment requires device custody, activation codes, recovery ownership, and access-policy decisions. Although AWS exposes APIs and Terraform can represent some virtual-device metadata, generated infrastructure code can put MFA seed material in state and cannot complete a secure human enrollment ceremony. IAM-user guidance therefore distinguishes removing an unnecessary login profile from retaining console access and enrolling MFA. It also states that removing console access does not remove access keys or assumed-role access.

The root-hardware check's limitations remain visible: Prowler 5.42.0 runs it only in the commercial partition and infers its result from account-summary and virtual-device data. The report asks an authorized owner to inspect the actual authenticator and centralized-root-access configuration rather than claiming the scanner identified device custody or recovery readiness.

Sources reviewed September 14, 2026:

- Prowler 5.42.0 check implementations at pinned commit `73ae2eb1947a0912a05010a296f469bfa55ebe76`.
- [AWS root access-key deletion](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user_manage_delete-key.html).
- [AWS root hardware TOTP enrollment](https://docs.aws.amazon.com/IAM/latest/UserGuide/enable-hw-mfa-for-root.html).
- [AWS IAM-user MFA assignment](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_cliapi.html).

Validation: unit tests require manual status, no Terraform filename or code, dependency migration before root-key deletion, and explicit separation of console access from other IAM credentials.
