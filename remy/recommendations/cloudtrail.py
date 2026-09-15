"""Reviewed guidance for CloudTrail checks that share complete trail state."""

# The guidance remains readable as complete prose in source.
# ruff: noqa: E501

from collections.abc import Callable

from remy.reports.schema import Citation, Observation, Recommendation

_ECFR_308 = (
    "https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/"
    "subpart-C/section-164.308"
)
_CLOUDTRAIL_UPDATE = (
    "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/"
    "cloudtrail-create-and-update-a-trail-by-using-the-aws-cli-update-trail.html"
)
_CLOUDTRAIL_EVENTS = "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-management-events-with-cloudtrail.html"
_CLOUDTRAIL_DATA_EVENTS = "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html"
_CLOUDTRAIL_CLOUDWATCH = "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/send-cloudtrail-events-to-cloudwatch-logs.html"
_CLOUDTRAIL_KMS = "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html"
_CLOUDTRAIL_VALIDATION = "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html"


def _citation() -> Citation:
    return Citation(
        section="45 CFR 164.312(b)",
        title="Audit controls",
        url=(
            "https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/"
            "subpart-C/section-164.312"
        ),
        confidence="low",
        note=(
            "Draft safeguard mapping for reviewer assessment; this finding alone does not "
            "establish HIPAA noncompliance."
        ),
    )


def _shared_assumptions() -> list[str]:
    return [
        "The report does not retain the complete trail, selectors, destination policies, KMS policy, CloudWatch role, organization ownership, costs, or Terraform state.",
        "CloudTrail settings share one trail resource and must be reconciled with every other recommendation for that trail before a change is planned.",
        "No partial aws_cloudtrail block is emitted because applying it as a complete resource can overwrite selectors or omit required delivery dependencies.",
    ]


def _shared_steps(reference: str) -> list[str]:
    return [
        "Identify the owning account, organization or account trail, home Region, Terraform workspace, destinations, key policy, event selectors, and service owners.",
        "Retrieve and review the complete current trail configuration and delivery health; reconcile every CloudTrail finding into one proposed configuration.",
        "Estimate event, ingestion, retention, KMS, and storage costs and validate destination, role, and key policies in a nonproduction trail or account.",
        "Update the complete trail only in its owning configuration, monitor delivery errors and expected events, then rerun all applicable CloudTrail checks.",
        f"AWS reference: {reference}",
        f"General trail update reference: {_CLOUDTRAIL_UPDATE}",
    ]


def bedrock_logging(_observation: Observation) -> Recommendation:
    return Recommendation(
        status="needs_context",
        what=(
            "Prowler did not find a logging trail that its pinned check recognizes as covering Amazon Bedrock control-plane management events or supported Bedrock data-resource events."
        ),
        why=(
            "Without appropriate CloudTrail coverage, investigation and accountability for Bedrock configuration or runtime activity can be incomplete. Management and data events have different scope and cost."
        ),
        change=(
            "Determine which Bedrock services and operations are in scope, then add management-event or advanced Bedrock data-event selectors to the existing owning trail without dropping other selectors."
        ),
        impact=(
            "Broader event selection can materially increase CloudTrail, storage, and analysis cost. A selector that is too narrow can omit required activity; an incorrect full-trail update can remove unrelated audit coverage."
        ),
        citations=[_citation()],
        terraform=None,
        filename=None,
        assumptions=_shared_assumptions()
        + [
            "The pinned check recognizes selected Bedrock event sources and resource types; that inventory must be compared with the customer's actual Bedrock usage and current CloudTrail support."
        ],
        steps=_shared_steps(_CLOUDTRAIL_EVENTS),
    )


def cloudwatch_delivery(_observation: Observation) -> Recommendation:
    return Recommendation(
        status="needs_context",
        what=(
            "Prowler observed no CloudWatch Logs delivery timestamp for the trail in the last 24 hours, or no CloudWatch Logs delivery configuration."
        ),
        why=(
            "CloudWatch Logs delivery supports timely monitoring and alarms. This check is about that delivery path; it does not by itself establish whether S3 trail delivery is healthy."
        ),
        change=(
            "Inspect the trail's CloudWatch log group, delivery role, permissions, and recent activity. Repair the existing integration or configure an approved log group and role on the owning trail."
        ),
        impact=(
            "A wrong role or log-group ARN prevents delivery. Retention and ingestion add cost, and an inactive account can lack a recent delivery timestamp even when configuration exists, so current delivery errors and test events require review."
        ),
        citations=[_citation()],
        terraform=None,
        filename=None,
        assumptions=_shared_assumptions()
        + [
            "The saved finding does not distinguish a missing integration, a permission failure, an old delivery timestamp, or a lack of recent qualifying events."
        ],
        steps=_shared_steps(_CLOUDTRAIL_CLOUDWATCH),
    )


def kms_encryption(_observation: Observation) -> Recommendation:
    return Recommendation(
        status="needs_context",
        what="Prowler observed a CloudTrail trail without an associated KMS key.",
        why=(
            "SSE-KMS provides customer-controlled key policy and auditability for CloudTrail log encryption beyond the S3 default encryption baseline."
        ),
        change=(
            "Select an approved KMS key in the trail's Region, update its key policy for CloudTrail encryption and authorized readers, and associate the key with the existing owning trail."
        ),
        impact=(
            "An incorrect or disabled key, key policy, encryption context, or reader permission can stop log delivery or prevent investigators from reading logs. KMS requests add dependency, quota, and cost."
        ),
        citations=[_citation()],
        terraform=None,
        filename=None,
        assumptions=_shared_assumptions()
        + [
            "No KMS ARN is generated; key ownership, policy administration, readers, multi-account delivery, and recovery must be decided by the customer."
        ],
        steps=_shared_steps(_CLOUDTRAIL_KMS),
    )


def log_file_validation(_observation: Observation) -> Recommendation:
    return Recommendation(
        status="needs_context",
        what="Prowler observed that log file integrity validation is disabled on a CloudTrail trail.",
        why=(
            "When enabled, CloudTrail delivers digest files that can be used to determine whether delivered log files were changed or deleted after delivery."
        ),
        change=(
            "Enable log-file validation on the existing owning trail and preserve digest files with the associated logs. Integrate validation into the customer's investigation or evidence process."
        ),
        impact=(
            "Enabling validation does not retroactively create digests for older logs and does not prevent modification or deletion. Validation depends on retaining the digest chain and running a supported verification process."
        ),
        citations=[_citation()],
        terraform=None,
        filename=None,
        assumptions=_shared_assumptions(),
        steps=_shared_steps(_CLOUDTRAIL_VALIDATION),
    )


def s3_data_events(observation: Observation) -> Recommendation:
    read_check = observation.check_id == "cloudtrail_s3_dataevents_read_enabled"
    direction = "read" if read_check else "write"
    return Recommendation(
        status="needs_context",
        what=(
            f"Prowler did not find an event selector that its pinned check recognizes as recording S3 object-level {direction} activity."
        ),
        why=(
            "S3 object data events provide object-level API evidence that management events do not include. Broad all-bucket coverage can be expensive and may collect metadata beyond the customer's intended scope."
        ),
        change=(
            f"Define the approved buckets, prefixes, event categories, and {direction} scope, then merge a classic or advanced S3 object data-event selector into the owning trail without dropping existing selectors."
        ),
        impact=(
            "S3 data events can produce high event volume and cost. Overbroad selectors increase collection; narrow selectors can omit evidence. Selector limits and interactions require full-trail review."
        ),
        citations=[_citation()],
        terraform=None,
        filename=None,
        assumptions=_shared_assumptions()
        + [
            "In Prowler 5.42.0 the advanced-selector path checks for AWS::S3::Object but does not fully establish readOnly direction or all-bucket resource coverage; verify the actual selector rather than treating a PASS as complete proof.",
            "The check can depend on whether S3 resources were observed or unused-service scanning was enabled.",
        ],
        steps=_shared_steps(_CLOUDTRAIL_DATA_EVENTS),
    )


CLOUDTRAIL_BUILDERS: dict[str, Callable[[Observation], Recommendation]] = {
    "cloudtrail_bedrock_logging_enabled": bedrock_logging,
    "cloudtrail_cloudwatch_logging_enabled": cloudwatch_delivery,
    "cloudtrail_kms_encryption_enabled": kms_encryption,
    "cloudtrail_log_file_validation_enabled": log_file_validation,
    "cloudtrail_s3_dataevents_read_enabled": s3_data_events,
    "cloudtrail_s3_dataevents_write_enabled": s3_data_events,
}
