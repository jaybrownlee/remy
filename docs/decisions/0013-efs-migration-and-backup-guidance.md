# ADR 0013: Separate EFS migration from backup-policy review

- Status: Accepted
- Date: 2026-09-14

## Context

EFS encryption is immutable after file-system creation, so remediation requires a new encrypted file system and a data and client migration. EFS automatic backup can be enabled independently, but the default plan's schedule and retention are not necessarily the customer's approved recovery policy.

Neither pinned scanner finding contains the client, mount-target, access-point, KMS, data-consistency, backup-vault, retention, or Terraform state needed for a safe resource definition.

## Decision

Remy provides separate reviewed plans for encryption migration and backup enablement and emits no EFS or AWS Backup Terraform from these findings.

- Encryption guidance covers destination design, data transfer or replication, client cutover, validation, rollback, and explicit source-retirement approval.
- Backup guidance requires recovery objectives, plan and vault review, successful recovery points, alerts, and representative restore tests.
- The default automatic-backup retention is not presented as a customer-specific requirement.

## Consequences

Customers receive actionable sequencing and risk information without a partial file-system or backup configuration. Implementation still requires storage, application, security, recovery, and infrastructure owners.
