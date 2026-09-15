"""Reviewed guidance for stateful Amazon EFS findings."""

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
_AWS_EFS_CREATE = "https://docs.aws.amazon.com/efs/latest/ug/creating-using-create-fs.html"
_AWS_EFS_REPLICATION = "https://docs.aws.amazon.com/efs/latest/ug/create-replication.html"
_AWS_EFS_BACKUP = "https://docs.aws.amazon.com/efs/latest/ug/awsbackup.html"


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


def _name(observation: Observation) -> str:
    return observation.resource_name.strip() or "the reported EFS file system"


def encryption_at_rest(observation: Observation) -> Recommendation:
    name = _name(observation)
    return Recommendation(
        status="needs_context",
        what=f"Prowler observed that encryption at rest is disabled for {name}.",
        why=(
            "EFS encryption at rest protects file data and metadata using AWS KMS. It is fixed when a file system is created and does not address NFS transport encryption or client authorization."
        ),
        change=(
            "Create a new encrypted file system with an approved KMS key and complete network, access-point, policy, performance, lifecycle, backup, and monitoring settings; copy or replicate the data, validate it, then cut clients over."
        ),
        impact=(
            "Encryption cannot be enabled on the existing file system. Migration changes the file-system ID and mount targets and can affect DNS, mounts, permissions, ownership, hard links, sparse files, performance, replication, backups, cost, downtime, and rollback. A wrong or disabled KMS key can make the destination unavailable."
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
            "The report does not retain mount targets, clients, access points, file-system policy, POSIX identities, data scale and shape, throughput, lifecycle, replication, backups, KMS, DNS, or Terraform ownership.",
            "The pinned Prowler check tests only the collected encrypted flag; it does not test key policy, encryption in transit, application authorization, or migration readiness.",
            "No destination file system, KMS key, replication overwrite change, client remount, source deletion, or guessed Terraform resource is generated.",
        ],
        steps=[
            "Inventory every client and mount, access point, security group, file-system policy, POSIX identity, data feature, backup, replication, performance, lifecycle, DNS, and owning configuration.",
            "Choose and review the destination's availability mode, KMS key and policy, mount targets, network controls, access points, file policy, performance, lifecycle, backup, and monitoring.",
            "Select and test a copy or EFS replication method, including initial sync, changed-data handling, metadata fidelity, validation, cutover, rollback, and allowed downtime.",
            "Cut clients over through the approved process and keep the source until recovery, retention, and deletion approvals explicitly permit retirement.",
            f"AWS EFS creation and immutable-encryption reference: {_AWS_EFS_CREATE}",
            f"AWS EFS replication reference: {_AWS_EFS_REPLICATION}",
        ],
    )


def backup_enabled(observation: Observation) -> Recommendation:
    name = _name(observation)
    return Recommendation(
        status="needs_context",
        what=f"Prowler observed a DISABLED or DISABLING automatic-backup policy for {name}.",
        why=(
            "Automatic backups provide scheduled recovery points, but merely enabling the default policy does not prove that frequency, retention, vault protection, recovery objectives, or restore procedures meet the workload's requirements."
        ),
        change=(
            "Define the recovery and retention policy, then enable EFS automatic backups or assign the file system to a reviewed AWS Backup plan and vault that implements that policy."
        ),
        impact=(
            "Backups add storage and restore cost and can capture sensitive data. Concurrent writes can produce application-level inconsistencies, large file systems may exceed completion windows, and restores have different performance and storage-class behavior."
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
            "The report does not retain existing AWS Backup plans, assignments, vaults, keys, policies, locks, recovery points, copy actions, completion history, restore tests, resource tags, or Terraform ownership.",
            "The pinned Prowler check fails only for DISABLED or DISABLING and treats other collected states as passing; verify that backups actually complete and remain restorable.",
            "No default 35-day retention period is asserted as customer policy and no incomplete backup-plan or vault Terraform is generated.",
        ],
        steps=[
            "Confirm the file-system owner, data classification, recovery point and time objectives, retention and deletion rules, consistency requirements, Regions and accounts, and existing AWS Backup governance.",
            "Choose the automatic EFS plan or a customer-managed AWS Backup plan, and review schedule, windows, lifecycle, vault, KMS, vault access and lock, cross-account or cross-Region copies, notifications, and cost.",
            "Apply the complete plan and assignment through their owning configuration, verify successful recovery points and alerts, and monitor completion time.",
            "Perform and document representative full and item-level restores, validate permissions and application behavior, then rerun the Prowler check.",
            f"AWS EFS backup reference: {_AWS_EFS_BACKUP}",
        ],
    )


EFS_BUILDERS: dict[str, Callable[[Observation], Recommendation]] = {
    "efs_encryption_at_rest_enabled": encryption_at_rest,
    "efs_have_backup_enabled": backup_enabled,
}
