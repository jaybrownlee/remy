"""Reviewed guidance for DynamoDB, DAX, and recovery findings."""

# The guidance remains readable as complete prose in source.
# ruff: noqa: E501

from collections.abc import Callable

from remy.reports.schema import Citation, Observation, Recommendation

_ECFR_308 = (
    "https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/"
    "subpart-C/section-164.308"
)
_ECFR_312 = (
    "https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/"
    "subpart-C/section-164.312"
)
_AWS_DAX_CONTROL = "https://docs.aws.amazon.com/securityhub/latest/userguide/dynamodb-controls.html"
_AWS_DDB_ENCRYPTION = (
    "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/encryption.howitworks.html"
)
_AWS_DDB_KEY_UPDATE = (
    "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/encryption.tutorial.html"
)
_AWS_DDB_PITR = (
    "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/"
    "PointInTimeRecovery.Tutorial.html"
)


def _citation(section: str, title: str, url: str) -> Citation:
    return Citation(
        section=section,
        title=title,
        url=url,
        confidence="low",
        note=(
            "Draft safeguard mapping for reviewer assessment; this finding alone does not "
            "establish HIPAA noncompliance."
        ),
    )


def _name(observation: Observation, kind: str) -> str:
    return observation.resource_name.strip() or f"the reported {kind}"


def dax_encryption(observation: Observation) -> Recommendation:
    name = _name(observation, "DAX cluster")
    return Recommendation(
        status="needs_context",
        what=f"Prowler observed that encryption at rest is disabled for DAX cluster {name}.",
        why=(
            "DAX encryption at rest protects data persisted by the cache. It is fixed at cluster creation and is separate from DAX encryption in transit and the source table's encryption key."
        ),
        change=(
            "Create a replacement DAX cluster with encryption at rest enabled and complete subnet, security-group, IAM, parameter-group, maintenance, notification, logging, and in-transit encryption settings; validate it and shift clients."
        ),
        impact=(
            "DAX encryption at rest cannot be changed on the existing cluster. Replacement changes the endpoint and cache state, can cause cold-cache load on DynamoDB, and may require client TLS changes, IAM updates, capacity planning, DNS or configuration rollout, downtime, and rollback."
        ),
        citations=[
            _citation(
                "45 CFR 164.312(a)(2)(iv)",
                "Encryption and decryption",
                _ECFR_312,
            )
        ],
        terraform=None,
        filename=None,
        assumptions=[
            "The report does not retain cluster nodes, endpoint consumers, subnet and security groups, IAM, parameter groups, maintenance, notifications, encryption in transit, table traffic, capacity, or Terraform ownership.",
            "The pinned Prowler check tests only the collected DAX cluster encryption-at-rest flag.",
            "No replacement cluster, endpoint change, traffic shift, or source deletion is generated.",
        ],
        steps=[
            "Inventory every client, endpoint, subnet and security group, IAM role and policy, parameter group, table dependency, node type and count, load profile, maintenance setting, notification, and owning configuration.",
            "Design an encrypted replacement, including in-transit encryption and current client compatibility, least-privilege IAM, network controls, capacity for cache warm-up, monitoring, and cost.",
            "Create and test the replacement in a representative environment, validate table load and failure behavior, and rehearse client rollout and rollback.",
            "Shift production clients through the approved process and retain the old cluster until validation and explicit retirement approval.",
            f"AWS DAX encryption control reference: {_AWS_DAX_CONTROL}",
        ],
    )


def table_kms_encryption(observation: Observation) -> Recommendation:
    name = _name(observation, "DynamoDB table")
    return Recommendation(
        status="needs_context",
        what=f"Prowler observed the DEFAULT encryption type for DynamoDB table {name}, rather than an SSE type reported as KMS.",
        why=(
            "All DynamoDB tables are encrypted at rest. A KMS-backed table key adds key visibility and, for a customer-managed key, policy and lifecycle control; it also introduces a dependency that can make the table inaccessible if mismanaged."
        ),
        change=(
            "Decide whether the approved policy requires the AWS managed DynamoDB key or a specific customer-managed symmetric KMS key, review the key and global-table design, then update the existing table through its owning configuration."
        ),
        impact=(
            "KMS requests add cost, quotas, permissions, and CloudTrail events. Disabling, deleting, or denying DynamoDB access to a customer-managed key can make the table inaccessible and disrupt global replicas; existing on-demand backups retain their original encryption key."
        ),
        citations=[
            _citation(
                "45 CFR 164.312(a)(2)(iv)",
                "Encryption and decryption",
                _ECFR_312,
            )
        ],
        terraform=None,
        filename=None,
        assumptions=[
            "The report does not retain the table definition, global replicas, indexes, streams, backups, consumers, current key, key policy, grants, quotas, alarms, or Terraform ownership.",
            "Despite the pinned check name containing kms_cmk, Prowler 5.42.0 passes whenever the collected encryption_type equals KMS; that can represent the AWS managed DynamoDB key or a customer-managed key, so customer-key ownership must be verified separately.",
            "No KMS key ARN or partial aws_dynamodb_table resource is generated.",
        ],
        steps=[
            "Confirm the current SSE description, tables and replicas in every Region, backups, streams, consumers, and the configuration that owns the full table.",
            "Choose the approved AWS managed or customer-managed symmetric key. For a customer key, review policy, grants, administrators, application roles, DynamoDB access, rotation, monitoring, deletion protection, recovery, quotas, and cost.",
            "Test the key change and failure alarms on a representative table, including global replication, streams, backups, restore, and application traffic.",
            "Update the full owning table configuration, monitor SSE status and workload errors, verify the actual resolved key ARN, and rerun the check.",
            f"AWS DynamoDB encryption behavior: {_AWS_DDB_ENCRYPTION}",
            f"AWS DynamoDB key-update reference: {_AWS_DDB_KEY_UPDATE}",
        ],
    )


def table_pitr(observation: Observation) -> Recommendation:
    name = _name(observation, "DynamoDB table")
    return Recommendation(
        status="needs_context",
        what=f"Prowler observed that point-in-time recovery is disabled for DynamoDB table {name}.",
        why=(
            "PITR provides continuous backups within the configured recovery window. A restore creates a new table, so PITR alone does not provide application cutover, complete configuration recovery, or proof that recovery objectives are met."
        ),
        change=(
            "Select the approved recovery window, enable PITR in the table's existing owning configuration, and establish a tested restore, configuration-recreation, validation, and cutover runbook."
        ),
        impact=(
            "PITR adds backup and restore cost. Restores create a new table and do not automatically restore several operational settings, including auto scaling, IAM policies, alarms, tags, streams, TTL, deletion protection, and PITR on the new table."
        ),
        citations=[
            _citation(
                "45 CFR 164.308(a)(7)(ii)(A)",
                "Data backup plan",
                _ECFR_308,
            )
        ],
        terraform=None,
        filename=None,
        assumptions=[
            "The report does not retain the approved recovery window, table definition, replicas, indexes, streams, TTL, auto scaling, policies, alarms, tags, deletion protection, restore tests, or Terraform ownership.",
            "The pinned Prowler check tests only the collected PITR boolean; it does not validate retention length, recovery-point freshness, restore completion, configuration recreation, or application recovery.",
            "No partial aws_dynamodb_table resource or destructive restore and cutover action is generated.",
        ],
        steps=[
            "Define recovery point and time objectives, recovery-window and retention requirements, Regions, table dependencies, cutover method, data reconciliation, and rollback.",
            "Update PITR through the configuration that owns the complete table and monitor continuous-backup status.",
            "Restore a representative recovery point to a new table and recreate the omitted settings: auto scaling, IAM policies, alarms, tags, streams, TTL, deletion protection, and PITR.",
            "Validate data and application behavior, document measured recovery time and cutover steps, clean up only under approved retention rules, and rerun the check.",
            f"AWS DynamoDB PITR and restore reference: {_AWS_DDB_PITR}",
        ],
    )


DYNAMODB_BUILDERS: dict[str, Callable[[Observation], Recommendation]] = {
    "dynamodb_accelerator_cluster_encryption_enabled": dax_encryption,
    "dynamodb_tables_kms_cmk_encryption_enabled": table_kms_encryption,
    "dynamodb_tables_pitr_enabled": table_pitr,
}
