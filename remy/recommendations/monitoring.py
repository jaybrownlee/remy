"""Reviewed monitoring and operational control plans."""

# ruff: noqa: E501

from remy.recommendations.plans import ChangePlan

_ALARM_REFERENCE = "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudwatch-alarms-for-cloudtrail.html"
_ALARM_CONTEXT = "CloudTrail delivery and log-group ARN, existing filters and metric names, alarm thresholds and periods, missing-data behavior, notification destinations, subscriber confirmation, response owner, IAM and KMS policies, and cost."
_ALARM_CAVEAT = "The pinned check looks for a matching filter on a CloudTrail log group and an associated metric alarm. It does not establish successful notification delivery or response. Incomplete listing can produce MANUAL instead of FAIL."

# These are explicit, reviewed event sets from the pinned implementations.
_EVENTS = {
    "cloudwatch_changes_to_network_acls_alarm_configured": "CreateNetworkAcl, CreateNetworkAclEntry, DeleteNetworkAcl, DeleteNetworkAclEntry, ReplaceNetworkAclEntry, ReplaceNetworkAclAssociation",
    "cloudwatch_changes_to_network_gateways_alarm_configured": "CreateCustomerGateway, DeleteCustomerGateway, AttachInternetGateway, CreateInternetGateway, DeleteInternetGateway, DetachInternetGateway",
    "cloudwatch_changes_to_network_route_tables_alarm_configured": "ec2.amazonaws.com events CreateRoute, CreateRouteTable, ReplaceRoute, ReplaceRouteTableAssociation, DeleteRouteTable, DeleteRoute, DisassociateRouteTable",
    "cloudwatch_changes_to_vpcs_alarm_configured": "CreateVpc, DeleteVpc, ModifyVpcAttribute, AcceptVpcPeeringConnection, CreateVpcPeeringConnection, DeleteVpcPeeringConnection, RejectVpcPeeringConnection, AttachClassicLinkVpc, DetachClassicLinkVpc, DisableVpcClassicLink, EnableVpcClassicLink",
    "cloudwatch_log_metric_filter_authentication_failures": "ConsoleLogin with errorMessage equal to Failed authentication",
    "cloudwatch_log_metric_filter_root_usage": "userIdentity.type equal to Root, userIdentity.invokedBy absent, and eventType not equal to AwsServiceEvent",
}

MONITORING_PLANS = {
    check: ChangePlan(
        what=f"Prowler did not find its expected metric filter and alarm for: {events}.",
        why="Detection of these events gives the response team a signal to investigate configuration or identity activity.",
        change=f"Configure aws_cloudwatch_log_metric_filter for {events} on the confirmed CloudTrail log group. Connect its metric namespace and name to an aws_cloudwatch_metric_alarm with approved thresholds, evaluation periods, missing-data behavior, and notification actions.",
        impact="Incorrect filters or thresholds can miss events or flood responders. Broken topic permissions, KMS access, or unconfirmed subscribers can silently prevent notifications. Metrics and logs add cost.",
        context=_ALARM_CONTEXT,
        verify="Test matching and nonmatching synthetic log records, confirm metric emission, exercise the alarm and notification path, and verify receipt by the intended responder without performing disruptive production API actions.",
        reference=_ALARM_REFERENCE,
        caveat=_ALARM_CAVEAT,
    )
    for check, events in _EVENTS.items()
}

MONITORING_PLANS.update(
    {
        "cloudwatch_log_group_kms_encryption_enabled": ChangePlan(
            what="Prowler observed no KMS key associated with the log group.",
            why="CloudWatch Logs already encrypts data by default. An associated KMS key adds explicit key control and an availability dependency.",
            change="Set kms_key_id on the existing aws_cloudwatch_log_group after selecting a supported symmetric key and reviewing the regional Logs service principal, encryption-context restrictions, and reader permissions.",
            impact="The association affects newly ingested data. Old KMS-encrypted records continue to depend on their original key even after disassociation; disabling it can prevent reads. Key requests add cost.",
            context="log-group ownership, Region, existing key associations, key policy and grants, service integrations, readers, retention, and key recovery procedures.",
            verify="Confirm ingestion and authorized retrieval after association, check denied operations, and preserve key access for all retained records.",
            reference="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html",
            caveat="The pinned check tests presence of kms_id, not key ownership, effective permissions, or encryption of historical records.",
        ),
        "cloudwatch_log_group_retention_policy_specific_days_enabled": ChangePlan(
            what="Prowler observed a finite log retention shorter than its configured minimum.",
            why="Retention must support investigations while honoring the approved data retention and deletion policy.",
            change="Choose an approved supported retention period and update retention_in_days on the owning aws_cloudwatch_log_group. Resolve conflicts with the scanner threshold before changing production retention.",
            impact="Shortening retention can expire existing records; lengthening it cannot recover records already deleted and increases storage cost.",
            context="the scan's log_group_retention_days setting, current retention, data classification, legal holds, archives, deletion requirements, and log-group ownership.",
            verify="Verify the effective retention and archival coverage. Confirm held evidence remains available without generating or collecting sensitive log contents in Remy.",
            reference="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Working-with-log-groups-and-streams.html",
            caveat="Prowler's default minimum is 365 days, and never-expire passes. Neither value is a statement that HIPAA requires that retention period.",
        ),
        "config_recorder_all_regions_enabled": ChangePlan(
            what="Prowler observed a missing, stopped, or failing AWS Config recorder in a scanned Region.",
            why="Recording configuration changes supports inventory and investigations; coverage depends on resource types and Regions.",
            change="Reconcile organization governance, then configure or repair aws_config_configuration_recorder, its IAM role and recording scope, aws_config_delivery_channel and destination policies, and aws_config_configuration_recorder_status in dependency order.",
            impact="Recording and delivery incur cost. Duplicate management or an incorrect role or destination can disrupt organization controls; high-change resources can produce substantial volume.",
            context="organization ownership, enabled Regions, recorder and recording scope, global resource treatment, delivery channel, bucket and topic policies, role, and error status.",
            verify="Confirm recording is active, last status is healthy, and representative configuration changes appear with expected resource coverage in every intended Region.",
            reference="https://docs.aws.amazon.com/config/latest/developerguide/gs-cli-subscribe.html",
            caveat="The pinned check inspects observed recorders and their status. Its name does not prove complete Region or resource-type coverage; mute_non_default_regions can mute failures.",
        ),
        "securityhub_enabled": ChangePlan(
            what="Prowler observed Security Hub inactive, or active without any standard or integration.",
            why="Security Hub CSPM can centralize posture findings and their operational review.",
            change="Use the delegated administrator's central configuration when present. Otherwise configure aws_securityhub_account and explicitly selected standards subscriptions or integrations in each intended Region; verify AWS Config prerequisites for selected controls.",
            impact="Enablement changes finding volume, service dependencies, and cost. Local settings can conflict with organization policies; enabling the service alone does not establish an operating response process.",
            context="delegated administrator, central policies, home and linked Regions, standards, integrations, Config recording, subscriptions, routing, and response ownership.",
            verify="Confirm active service status, intended standards or integrations, control evaluation health, and receipt and ownership of test findings.",
            reference="https://docs.aws.amazon.com/securityhub/latest/userguide/start-central-configuration.html",
            caveat="The pinned check requires ACTIVE plus a standard or integration. It does not evaluate control outcomes; mute_non_default_regions can mute failures.",
        ),
        "ssm_managed_compliant_patching": ChangePlan(
            what="Prowler observed a managed resource with a compliance status other than COMPLIANT.",
            why="Fresh patch assessments help identify systems missing the approved updates.",
            change="Inspect the compliance type, failed items, baseline, and assessment time. Run an approved patch Scan, then remediate through the existing Patch Manager baseline and maintenance window or image replacement workflow with an explicit reboot decision.",
            impact="Installing patches or rebooting can interrupt services and change dependencies. A Scan only assesses; an Install changes the host. Stale or unrelated compliance records need diagnosis before patching.",
            context="compliance type and timestamp, missing updates, approved baseline, OS and repositories, exclusions, backups, service redundancy, maintenance windows, and reboot requirements.",
            verify="Test application health and recovery after a staged rollout, rerun patch Scan, and confirm fresh compliance results for the intended baseline.",
            reference="https://docs.aws.amazon.com/systems-manager/latest/userguide/patch-manager-patch-now-on-demand.html",
            caveat="The pinned implementation tests collected compliance resource status; it does not install patches or prove coverage of unmanaged or unreported hosts.",
            status="manual_action",
        ),
        "vpc_flow_logs_enabled": ChangePlan(
            what="Prowler did not observe flow logging for an in-scope VPC.",
            why="Flow records support network investigations using traffic metadata. They are not packet captures or complete records of every traffic category.",
            change="Configure aws_flow_log for the confirmed VPC with an approved traffic_type, destination, format, aggregation interval, delivery role or bucket policy, encryption, and retention.",
            impact="Logging adds delivery and storage cost and retains network identifiers. Some traffic is excluded; an incorrect destination policy can prevent delivery.",
            context="existing VPC, subnet and ENI flow logs, required accepted and rejected traffic, destination ownership, IAM, KMS, format, retention, and analysis needs.",
            verify="Generate representative allowed and denied traffic, confirm delivery and useful record fields, inspect delivery errors, and document coverage limitations.",
            reference="https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-limitations.html",
            caveat="The pinned check tests the collected VPC flow_log value and can skip unused VPCs. It does not prove delivery, traffic scope, retention, or complete capture.",
        ),
    }
)
