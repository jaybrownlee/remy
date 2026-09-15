# ADR 0011: Treat RDS remediation as stateful change planning

- Status: Accepted
- Date: 2026-09-14

## Context

The pinned HIPAA framework contains six RDS checks covering backups, CloudWatch log exports, Multi-AZ deployment, network exposure, storage encryption, and public snapshots. An `aws_db_instance` or `aws_rds_cluster` block reconstructed from a scanner row would omit required state and could cause downtime, replacement, data loss, or connectivity failure.

The Prowler checks are also intentionally narrower than a full control assessment. For example, any configured log export satisfies the log check, backup retention only needs to be nonzero, and the public-access check evaluates a compound network path.

## Decision

Remy provides reviewed, check-specific planning guidance for all six checks but emits no RDS Terraform resource.

- Instance changes require the complete live configuration and its existing owner.
- Backup guidance calls out the outage when changing retention from zero and the pinned read-replica configuration caveat.
- Logging guidance requires an engine-specific audit and retention decision rather than enabling an arbitrary log.
- Multi-AZ guidance distinguishes instance and cluster ownership and requires failover testing.
- Public-access guidance reviews endpoint, subnet, route, and security-group conditions together.
- Storage encryption is presented as an encrypted snapshot-copy, restore, validation, and cutover migration; source deletion is never generated.
- Public snapshots trigger a manual exposure investigation and revocation path, not deletion.

## Consequences

Reports remain actionable without pretending a partial Terraform resource is safe. Customers must supply database, application, network, recovery, and ownership context before implementation. These handlers improve explanation coverage but are not validated fixes or evidence of compliance.
