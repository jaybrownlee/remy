# ADR 0014: Preserve DynamoDB recovery and key-management context

- Status: Accepted
- Date: 2026-09-14

## Context

The pinned framework includes DAX encryption, DynamoDB KMS encryption, and point-in-time recovery checks. DAX encryption requires replacement. A PITR restore creates a new table and omits several operational settings. A DynamoDB table key can be updated in place, but key policy mistakes can make a table inaccessible.

The pinned `dynamodb_tables_kms_cmk_encryption_enabled` implementation passes for any collected `KMS` encryption type. That does not distinguish the AWS managed DynamoDB key from a customer-managed key despite the check name.

## Decision

Remy emits reviewed planning guidance and no partial DynamoDB or DAX Terraform resources.

- DAX remediation requires an encrypted replacement, client rollout, cache-warm capacity, validation, rollback, and explicit retirement approval.
- Table-key guidance makes the pinned detection limitation explicit and requires an independent managed-key versus customer-key decision.
- PITR guidance requires a selected recovery window and a restore exercise that recreates omitted operational settings and tests application cutover.

## Consequences

Reports will not imply that enabling one flag completes recovery or key governance. Customers must reconcile these findings with the full table or cluster owner, KMS policy, global topology, application dependencies, and tested recovery procedures.
