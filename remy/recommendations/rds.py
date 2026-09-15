"""Reviewed guidance for stateful Amazon RDS findings."""

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
_AWS_BACKUPS = (
    "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/"
    "USER_WorkingWithAutomatedBackups.BackupRetention.html"
)
_AWS_LOG_EXPORTS = (
    "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/"
    "USER_LogAccess.Procedural.UploadtoCloudWatch.html"
)
_AWS_MULTI_AZ = (
    "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.MultiAZ.Migrating.html"
)
_AWS_VPC_ACCESS = (
    "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/"
    "USER_VPC.WorkingWithRDSInstanceinaVPC.html"
)
_AWS_ENCRYPTION = "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html"
_AWS_SNAPSHOT_SHARING = (
    "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_ShareSnapshot.Public.html"
)


def _citation(section: str, title: str, *, url: str) -> Citation:
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


def _instance_name(observation: Observation) -> str:
    return observation.resource_name.strip() or "the reported RDS resource"


def _shared_assumptions() -> list[str]:
    return [
        "The report does not retain the complete DB or cluster configuration, engine settings, dependencies, maintenance window, recovery objectives, data classification, or Terraform state.",
        "No aws_db_instance or aws_rds_cluster resource is emitted because taking ownership of an incomplete stateful resource can cause disruptive updates or replacement.",
        "The recommendation must be reconciled with the database owner, application owner, network owner, and the configuration that already owns the resource.",
    ]


def backup_enabled(observation: Observation) -> Recommendation:
    name = _instance_name(observation)
    return Recommendation(
        status="needs_context",
        what=f"Prowler observed a zero automated-backup retention period for {name}.",
        why=(
            "A nonzero retention period enables RDS automated backups and point-in-time recovery within the retained window. It does not prove that recovery objectives are met or that restores have been tested."
        ),
        change=(
            "Choose a retention period from the approved recovery and retention policy, then update the existing owning DB configuration and schedule restore testing."
        ),
        impact=(
            "Changing a DB instance from zero to a nonzero backup retention period causes an outage according to AWS. Backups add storage and operational cost, and backup windows can affect I/O."
        ),
        citations=[
            _citation(
                "45 CFR 164.308(a)(7)(ii)(A)",
                "Data backup plan",
                url=_ECFR_308,
            )
        ],
        terraform=None,
        filename=None,
        assumptions=_shared_assumptions()
        + [
            "The pinned Prowler check passes when backup_retention_period is greater than zero; that threshold is detection logic, not a customer-specific retention recommendation.",
            "The pinned check skips read replicas unless its check_rds_instance_replicas setting is enabled, so coverage of replicas must be confirmed separately.",
        ],
        steps=[
            "Confirm whether the resource is an instance, cluster member, or read replica and retrieve its current and pending configuration.",
            "Define recovery point, recovery time, retention, deletion, cross-Region, and restore-test requirements with the system owner.",
            "Plan the required outage and backup window, update the complete owning configuration, and monitor the first successful backup.",
            "Perform and document a representative restore test, then rerun the Prowler check.",
            f"AWS backup-retention reference: {_AWS_BACKUPS}",
        ],
    )


def cloudwatch_logs(observation: Observation) -> Recommendation:
    name = _instance_name(observation)
    return Recommendation(
        status="needs_context",
        what=f"Prowler observed no enabled CloudWatch Logs exports for {name}.",
        why=(
            "Publishing appropriate database logs supports centralized investigation, monitoring, and retention. Enabling any one export satisfies this check but does not prove that the required audit events are captured."
        ),
        change=(
            "Identify the engine-supported error, general, slow-query, audit, or upgrade logs required for this workload; enable those exports in the existing DB configuration and explicitly manage the resulting log groups."
        ),
        impact=(
            "Log types and prerequisite engine parameters vary. Exports can expose sensitive query or identity data and add ingestion, retention, KMS, and analysis cost; indefinite default retention can conflict with policy."
        ),
        citations=[_citation("45 CFR 164.312(b)", "Audit controls", url=_ECFR_312)],
        terraform=None,
        filename=None,
        assumptions=_shared_assumptions()
        + [
            "The pinned Prowler check passes when at least one CloudWatch log export is enabled; required log types, content, retention, protection, alarms, and delivery health still need review."
        ],
        steps=[
            "Confirm the engine, version, parameter and option groups, supported log exports, current audit settings, and expected event volume.",
            "Select the log types needed for operations and investigations, minimizing unnecessary sensitive content.",
            "Update the owning DB configuration and manage each CloudWatch log group's retention, encryption, access, subscriptions, and alarms through its owning configuration.",
            "Generate representative events, confirm timely searchable delivery, and rerun the Prowler check.",
            f"AWS RDS log-export reference: {_AWS_LOG_EXPORTS}",
        ],
    )


def multi_az(observation: Observation) -> Recommendation:
    name = _instance_name(observation)
    return Recommendation(
        status="needs_context",
        what=f"Prowler observed that {name} was not in a Multi-AZ deployment.",
        why=(
            "Multi-AZ can provide an automatically managed standby or multi-instance topology for higher availability. It is not a backup substitute and does not by itself meet an application's recovery objectives."
        ),
        change=(
            "Confirm the resource topology and availability requirements, then plan the appropriate Multi-AZ DB instance or Multi-AZ DB cluster change in the existing owning configuration."
        ),
        impact=(
            "Multi-AZ increases cost and changes failure, maintenance, performance, and capacity behavior. Converting an instance creates and initializes standby storage and can affect performance; cluster-member settings must be changed at cluster level."
        ),
        citations=[
            _citation(
                "45 CFR 164.308(a)(7)(ii)(B)",
                "Disaster recovery plan",
                url=_ECFR_308,
            )
        ],
        terraform=None,
        filename=None,
        assumptions=_shared_assumptions()
        + [
            "The pinned Prowler check evaluates a containing cluster's Multi-AZ state for cluster members and otherwise evaluates the instance MultiAZ flag.",
            "No topology is selected from the finding; engine support, Regions, storage, replicas, connection behavior, and recovery objectives are customer decisions.",
        ],
        steps=[
            "Identify whether the finding represents a standalone instance, an Aurora member, or another RDS cluster member and locate the owning configuration.",
            "Validate availability and recovery objectives, engine support, subnet and Availability Zone capacity, cost, backup design, and connection retry behavior.",
            "Test conversion, failover, DNS handling, connection-pool recovery, monitoring, and rollback in a representative nonproduction environment.",
            "Schedule and monitor the production change through the owning configuration, run a controlled failover exercise, and rerun the check.",
            f"AWS Multi-AZ conversion reference: {_AWS_MULTI_AZ}",
        ],
    )


def no_public_access(observation: Observation) -> Recommendation:
    name = _instance_name(observation)
    return Recommendation(
        status="needs_context",
        what=(
            f"Prowler found that {name} was publicly addressable, in a public subnet, and reachable from an internet CIDR on its database port."
        ),
        why=(
            "Internet-reachable database endpoints expand the attack surface. PubliclyAccessible alone does not grant traffic, but the reported combination creates a network path that needs an explicit business justification."
        ),
        change=(
            "Remove internet CIDR ingress, set the DB to nonpublic where feasible, and move or rebuild it in an approved private subnet design. Preserve required access through narrowly scoped security-group references, private connectivity, VPN, or Direct Connect."
        ),
        impact=(
            "Changing accessibility, subnet groups, routes, DNS resolution, or security groups can immediately break applications, administrators, monitoring, migrations, and vendor integrations. Some topology changes require a migration rather than an in-place edit."
        ),
        citations=[_citation("45 CFR 164.312(a)(1)", "Access control", url=_ECFR_312)],
        terraform=None,
        filename=None,
        assumptions=_shared_assumptions()
        + [
            "For Prowler 5.42.0 this check fails only when public accessibility, a public subnet, and an internet-open security-group path to the DB port are all observed; review each component rather than changing one flag blindly.",
            "A PASS for this specific check does not establish a complete private-network design or rule out other network paths.",
        ],
        steps=[
            "Treat the exposure as an investigation input: confirm data sensitivity, intended clients, connection logs, authentication failures, and whether unauthorized access occurred.",
            "Map endpoint DNS, subnet routes and internet gateway, every attached security-group rule, peering and transit paths, VPN or Direct Connect, and all current clients.",
            "Design and test private connectivity and least-privilege security-group references before removing any required public path.",
            "Deploy through the owning network and DB configurations, monitor client errors and security telemetry, verify effective reachability, and rerun the check.",
            f"AWS RDS VPC-access reference: {_AWS_VPC_ACCESS}",
        ],
    )


def storage_encrypted(observation: Observation) -> Recommendation:
    name = _instance_name(observation)
    return Recommendation(
        status="needs_context",
        what=f"Prowler observed that storage encryption was disabled for {name}.",
        why=(
            "RDS encryption at rest covers underlying storage, logs, automated backups, read replicas, and snapshots for an encrypted DB instance. It does not replace application access controls or in-transit encryption."
        ),
        change=(
            "Plan an encrypted replacement: snapshot the source, copy the snapshot with an approved KMS key, restore a new encrypted resource, validate it, and migrate traffic and data using a method consistent with the allowed downtime and recovery objectives."
        ),
        impact=(
            "Encryption cannot be enabled in place on an existing unencrypted RDS DB instance. Migration changes resource identity and can affect endpoints, downtime, replication, option groups, parameter groups, integrations, performance, cost, rollback, and deletion sequencing. A wrong or disabled KMS key can make data unavailable."
        ),
        citations=[
            _citation(
                "45 CFR 164.312(a)(2)(iv)",
                "Encryption and decryption",
                url=_ECFR_312,
            )
        ],
        terraform=None,
        filename=None,
        assumptions=_shared_assumptions()
        + [
            "No KMS key, cutover method, endpoint, name, snapshot, deletion action, or Terraform resource is generated from the finding.",
            "The source remains unencrypted; successful restoration of an encrypted copy does not authorize deleting it.",
        ],
        steps=[
            "Inventory the engine and version, topology, storage, replicas, extensions, option and parameter groups, secrets, DNS, integrations, maintenance constraints, and Terraform ownership.",
            "Select and review a KMS key, key policy, administrators and readers, Region strategy, grants, quotas, rotation, monitoring, recovery, and cost.",
            "Create a fresh source snapshot, copy it with encryption, restore an isolated target, and validate configuration, data, backups, logs, monitoring, performance, and application compatibility.",
            "Choose and rehearse a cutover and rollback plan that accounts for changes after the snapshot; migrate through the customer's approved change process.",
            "After validation and retention approvals, separately decide how to retire the source without losing required evidence or recovery data; rerun the check against the replacement.",
            f"AWS RDS encryption reference: {_AWS_ENCRYPTION}",
        ],
    )


def snapshots_public(observation: Observation) -> Recommendation:
    name = _instance_name(observation)
    return Recommendation(
        status="manual_action",
        what=f"Prowler observed that {name} is a publicly shared RDS DB or cluster snapshot.",
        why=(
            "A public snapshot can be copied by any AWS account and used to create a database containing its data. Public visibility is exposure, but the finding alone does not prove that another account copied or accessed it."
        ),
        change=(
            "Confirm the snapshot owner and intended recipients, investigate the exposure window, and remove the public restore attribute through the authoritative operational path. If sharing is required, use only specifically approved accounts and a supported encryption design."
        ),
        impact=(
            "Removing public sharing stops new public restores and copies but cannot revoke copies already made by other accounts. Changing or deleting snapshots can affect recovery and evidence retention; encrypted-snapshot sharing has KMS and engine limitations."
        ),
        citations=[_citation("45 CFR 164.312(a)(1)", "Access control", url=_ECFR_312)],
        terraform=None,
        filename=None,
        assumptions=_shared_assumptions()
        + [
            "The report does not establish whether the snapshot contains regulated data, who changed its restore attributes, how long it was public, or whether another account copied it.",
            "No deletion is recommended and no snapshot-policy Terraform is emitted; preserve recovery material and investigation evidence according to approved retention requirements.",
        ],
        steps=[
            "Confirm the owning account, Region, snapshot type and identifier, data classification, restore attributes, creation time, source database, and CloudTrail history.",
            "Initiate the applicable incident or privacy review and assess whether another account copied or restored the snapshot while it was public.",
            "Remove the all-accounts restore permission through an authorized path, preserving only explicitly approved account sharing if required.",
            "Verify the snapshot is private, review related snapshots and preventive controls across Regions and accounts, and rerun the Prowler check.",
            f"AWS public-snapshot reference: {_AWS_SNAPSHOT_SHARING}",
        ],
    )


RDS_BUILDERS: dict[str, Callable[[Observation], Recommendation]] = {
    "rds_instance_backup_enabled": backup_enabled,
    "rds_instance_integration_cloudwatch_logs": cloudwatch_logs,
    "rds_instance_multi_az": multi_az,
    "rds_instance_no_public_access": no_public_access,
    "rds_instance_storage_encrypted": storage_encrypted,
    "rds_snapshots_public_access": snapshots_public,
}
