# Decision: do not turn runtime signals into generic infrastructure patches

Status: implemented, September 14, 2026.

Eight checks now have reviewed context-dependent or manual guidance: high-severity GuardDuty findings, old running EC2 instances, KMS key rotation, three Nitro Enclave key-policy checks, and two runtime enclave-attestation checks.

A high-severity GuardDuty finding is an incident-triage input, not proof of compromise. The guidance requires evidence preservation, validation, scoped containment, service-specific remediation, and documented disposition. Archiving or suppressing a finding is not presented as remediation.

EC2 instance age is a maintenance signal rather than proof of vulnerability. Remy does not suggest stopping, terminating, or replacing a running instance without its workload, storage, image, patch, dependency, recovery, and maintenance context.

KMS automatic rotation is addressed as an update to an existing owned key. A standalone `aws_kms_key` snippet would imply ownership of the key policy and lifecycle and could create a second key or cause policy lockout. The report therefore explains the `enable_key_rotation` update path but emits no incomplete resource block.

Nitro Enclave findings require complete KMS and IAM authorization-path review plus trusted measurements from the customer's audited build pipeline. Remy does not invent policy JSON or PCR values. Runtime unknown-image and debug-attestation findings are security signals; policy bypass, missing-condition, and PCR mismatch findings require architecture context. Both paths require staged validation against a nonproduction key before changing the production key policy.

Sources reviewed September 14, 2026:

- Prowler 5.42.0 check implementations at pinned commit `73ae2eb1947a0912a05010a296f469bfa55ebe76`.
- [AWS KMS automatic key rotation](https://docs.aws.amazon.com/kms/latest/developerguide/rotating-keys-enable.html).
- [AWS KMS condition keys for Nitro Enclaves](https://docs.aws.amazon.com/kms/latest/developerguide/conditions-nitro-enclave.html).
- [AWS Nitro Enclaves cryptographic attestation with KMS](https://docs.aws.amazon.com/enclaves/latest/user/kms.html).

Validation: tests distinguish policy findings from runtime findings, require no invented Terraform or PCR values, and preserve incident, ownership, lockout, and workload-impact warnings.
