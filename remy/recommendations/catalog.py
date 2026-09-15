"""Pure recommendation lookup for a small set of reviewed Prowler checks.

This module deliberately has no AWS client or runtime model dependency.  It turns
one saved observation into reviewable guidance and leaves unknown checks visible
as explicit catalog gaps.
"""

# The user-facing guidance remains readable as complete prose in source.
# ruff: noqa: E501

import json
import re
from collections.abc import Callable

from remy.reports.schema import Citation, Observation, Recommendation

_ECFR_164_312 = (
    "https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/"
    "subpart-C/section-164.312"
)
_ECFR_164_308 = (
    "https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/"
    "subpart-C/section-164.308"
)
_AWS_S3_PUBLIC_ACCESS = (
    "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
)
_TF_S3_BUCKET_PUBLIC_ACCESS = (
    "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/"
    "s3_bucket_public_access_block"
)
_TF_S3_ACCOUNT_PUBLIC_ACCESS = (
    "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/"
    "s3_account_public_access_block"
)
_AWS_CLOUDTRAIL = (
    "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/"
    "cloudtrail-create-and-update-a-trail-by-using-the-aws-cli-create-trail.html"
)
_TF_CLOUDTRAIL = (
    "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail"
)
_AWS_ROOT_MFA = (
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html#id_root-user_manage_mfa"
)
_AWS_ACCESS_ANALYZER = (
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-create-external.html"
)
_TF_ACCESS_ANALYZER = (
    "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/"
    "accessanalyzer_analyzer"
)
_AWS_ALTERNATE_CONTACTS = (
    "https://docs.aws.amazon.com/accounts/latest/reference/"
    "manage-acct-update-contact-alternate.html"
)
_TF_ALTERNATE_CONTACT = (
    "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/"
    "account_alternate_contact"
)
_AWS_EBS_DEFAULT_ENCRYPTION = "https://docs.aws.amazon.com/ebs/latest/userguide/ebs-encryption.html"
_TF_EBS_DEFAULT_ENCRYPTION = (
    "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/"
    "ebs_encryption_by_default"
)
_AWS_S3_VERSIONING = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html"
_TF_S3_VERSIONING = (
    "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/"
    "s3_bucket_versioning"
)
_AWS_GUARDDUTY = "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_settingup.html"
_TF_GUARDDUTY = (
    "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/guardduty_detector"
)
_PROWLER_HUB = "https://hub.prowler.com/check/"

_S3_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
_S3_ARN_RE = re.compile(r"^arn:(?:aws|aws-cn|aws-us-gov):s3:::(?P<bucket>[^/]+)$")
_TRAIL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,126}[A-Za-z0-9]$")
_TRAIL_ARN_RE = re.compile(
    r"^arn:(?:aws|aws-cn|aws-us-gov):cloudtrail:[^:]+:\d{12}:trail/(?P<name>[^/]+)$"
)
_IP_ADDRESS_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_AWS_REGION_RE = re.compile(r"^(?:af|ap|ca|cn|eu|il|me|mx|sa|us)-[a-z0-9-]+-\d+$")

SUPPORTED_CHECK_IDS = frozenset(
    {
        "s3_bucket_level_public_access_block",
        "s3_account_level_public_access_blocks",
        "cloudtrail_multi_region_enabled",
        "iam_root_mfa_enabled",
        "accessanalyzer_enabled",
        "account_maintain_different_contact_details_to_security_billing_and_operations",
        "ec2_ebs_default_encryption",
        "s3_bucket_object_versioning",
        "guardduty_is_enabled",
    }
)


def _draft_citation(section: str, title: str, *, url: str = _ECFR_164_312) -> Citation:
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


def _valid_bucket_name(value: str) -> bool:
    """Validate a general-purpose S3 bucket name before rendering it as a default."""
    if not _S3_BUCKET_RE.fullmatch(value):
        return False
    if ".." in value or _IP_ADDRESS_RE.fullmatch(value):
        return False
    return not (
        value.startswith("xn--")
        or value.startswith("sthree-")
        or value.startswith("amzn_s3_demo_")
        or value.endswith("-s3alias")
        or value.endswith("--ol-s3")
        or value.endswith(".mrap")
        or value.endswith("--x-s3")
        or value.endswith("--table-s3")
    )


def _bucket_name(observation: Observation) -> str | None:
    if _valid_bucket_name(observation.resource_name):
        return observation.resource_name
    match = _S3_ARN_RE.fullmatch(observation.resource_uid)
    if match and _valid_bucket_name(match.group("bucket")):
        return match.group("bucket")
    return None


def _trail_name(observation: Observation) -> str | None:
    if _TRAIL_NAME_RE.fullmatch(observation.resource_name):
        return observation.resource_name
    match = _TRAIL_ARN_RE.fullmatch(observation.resource_uid)
    if match and _TRAIL_NAME_RE.fullmatch(match.group("name")):
        return match.group("name")
    return None


def _variable(name: str, description: str, default: str | None = None) -> str:
    default_line = "" if default is None else f"  default     = {json.dumps(default)}\n"
    return (
        f'variable "{name}" {{\n'
        f"  description = {json.dumps(description)}\n"
        "  type        = string\n"
        f"{default_line}"
        "}\n"
    )


def _s3_bucket_public_access(observation: Observation) -> Recommendation:
    bucket_name = _bucket_name(observation)
    terraform = (
        "# Suggested Terraform — review and adapt before applying.\n"
        + _variable(
            "bucket_name",
            "Existing general-purpose S3 bucket to protect",
            bucket_name,
        )
        + "\n"
        'resource "aws_s3_bucket_public_access_block" "recommended" {\n'
        "  bucket = var.bucket_name\n\n"
        "  block_public_acls       = true\n"
        "  block_public_policy     = true\n"
        "  ignore_public_acls      = true\n"
        "  restrict_public_buckets = true\n"
        "}\n"
    )
    bucket_assumption = (
        f"The bucket input default came from the validated observation value {bucket_name!r}."
        if bucket_name
        else "The observation did not contain a valid general-purpose S3 bucket name; set bucket_name explicitly."
    )
    return Recommendation(
        status="needs_context",
        what=(
            "The bucket-level S3 Block Public Access check failed, so one or more of the four "
            "bucket controls is absent or disabled."
        ),
        why=(
            "Those controls prevent new public ACLs or policies and suppress access granted by "
            "existing public ACLs or policies. They reduce accidental disclosure risk, but the "
            "scan result does not show whether public delivery is intentional."
        ),
        change=(
            "After confirming the bucket is intended to be private, manage all four bucket-level "
            "Block Public Access flags as true. The snippet manages only the public-access-block "
            "configuration; it does not create or replace the bucket."
        ),
        impact=(
            "Public S3 website access can stop. CloudFront delivery can also stop if it still "
            "depends on public access rather than Origin Access Control or Origin Access Identity. "
            "RestrictPublicBuckets may also block cross-account access from a policy AWS considers public."
        ),
        citations=[_draft_citation("45 CFR 164.312(a)(1)", "Access control")],
        terraform=terraform,
        filename="s3_bucket_public_access_block.tf",
        assumptions=[
            bucket_assumption,
            "Bucket ownership, Terraform state ownership, website hosting, CloudFront origin design, ACLs, and bucket policy were not inferred from this observation.",
            "Account- and organization-level Block Public Access may impose stricter effective settings.",
        ],
        steps=[
            "Confirm the bucket owner and whether the bucket intentionally serves a public website or another public workload.",
            "Review bucket and access-point policies, ACLs, CloudFront origin access, and effective account/organization Block Public Access before selecting flags.",
            "If this public-access-block resource is already managed by Terraform, update that resource rather than adding a duplicate.",
            "If it exists in AWS but is outside Terraform, import it only after confirming the target workspace owns it; otherwise add this resource for the existing bucket.",
            "Run terraform plan in the customer workspace, review access loss and cross-account effects, apply through the customer's process, then rerun the Prowler check.",
            f"AWS behavior reference: {_AWS_S3_PUBLIC_ACCESS}",
            f"Terraform resource reference: {_TF_S3_BUCKET_PUBLIC_ACCESS}",
        ],
    )


def _s3_account_public_access(observation: Observation) -> Recommendation:
    account_id = observation.account_id if re.fullmatch(r"\d{12}", observation.account_id) else None
    terraform = (
        "# Suggested Terraform — review and adapt before applying.\n"
        + _variable(
            "aws_account_id",
            "Twelve-digit AWS account whose S3 public access settings are being managed",
            account_id,
        )
        + "\n"
        'resource "aws_s3_account_public_access_block" "recommended" {\n'
        "  account_id = var.aws_account_id\n\n"
        "  block_public_acls       = true\n"
        "  block_public_policy     = true\n"
        "  ignore_public_acls      = true\n"
        "  restrict_public_buckets = true\n"
        "}\n"
    )
    account_assumption = (
        f"The account input default came from the validated 12-digit account ID {account_id}."
        if account_id
        else "The observation did not contain a valid 12-digit account ID; set aws_account_id explicitly."
    )
    return Recommendation(
        status="needs_context",
        what=(
            "The account-level S3 Block Public Access check failed, so the account does not "
            "currently enforce all four settings as a common S3 baseline."
        ),
        why=(
            "Account-level controls can prevent public access configurations across current and "
            "future buckets. The finding does not show which buckets intentionally depend on public access."
        ),
        change=(
            "After an account-wide inventory, manage all four account-level Block Public Access "
            "flags as true. Only one such Terraform resource should manage an AWS account."
        ),
        impact=(
            "This account-wide change can disrupt every public S3 website and any public or "
            "cross-account bucket policy AWS classifies as public. CloudFront origins that rely on "
            "public bucket access may fail until moved to a private origin access design."
        ),
        citations=[_draft_citation("45 CFR 164.312(a)(1)", "Access control")],
        terraform=terraform,
        filename="s3_account_public_access_block.tf",
        assumptions=[
            account_assumption,
            "No bucket inventory, website configuration, CloudFront origin design, organization policy, or existing Terraform state was available.",
            "This account-scoped resource affects S3 buckets in every AWS Region after propagation.",
        ],
        steps=[
            "Inventory intentional public access, cross-account policies, S3 websites, and CloudFront origins across the account before enabling these flags.",
            "Check whether an AWS Organizations policy already owns or constrains the effective setting.",
            "If the account public-access-block resource is already managed, update it in that workspace; if it exists outside Terraform, import only after confirming ownership.",
            "Run terraform plan, review account-wide access changes, apply through the customer's process, and rerun the Prowler check after settings propagate.",
            f"AWS behavior reference: {_AWS_S3_PUBLIC_ACCESS}",
            f"Terraform resource reference: {_TF_S3_ACCOUNT_PUBLIC_ACCESS}",
        ],
    )


def _cloudtrail_multi_region(observation: Observation) -> Recommendation:
    trail_name = _trail_name(observation)
    terraform = (
        "# Suggested Terraform — review and adapt before applying.\n"
        + _variable("trail_name", "Name of the CloudTrail trail to create or manage", trail_name)
        + "\n"
        + _variable(
            "cloudtrail_s3_bucket_name",
            "Existing S3 bucket configured to accept CloudTrail log delivery",
        )
        + "\n"
        'resource "aws_cloudtrail" "recommended" {\n'
        "  name                          = var.trail_name\n"
        "  s3_bucket_name                = var.cloudtrail_s3_bucket_name\n"
        "  enable_logging                = true\n"
        "  is_multi_region_trail         = true\n"
        "  include_global_service_events = true\n"
        "}\n"
    )
    trail_assumption = (
        f"The trail name default came from the validated observation value {trail_name!r}."
        if trail_name
        else "The observation did not identify a valid trail name; set trail_name explicitly."
    )
    return Recommendation(
        status="needs_context",
        what=(
            "Prowler did not observe an actively logging CloudTrail trail covering every enabled "
            "AWS Region. Event history alone is not a durable multi-Region trail."
        ),
        why=(
            "A coverage or logging gap reduces the audit record available for detection and "
            "investigation of account activity."
        ),
        change=(
            "Create or update a trail so logging is enabled and all enabled Regions plus global "
            "service events are covered. The snippet is intentionally minimal and requires an "
            "existing log-delivery bucket input."
        ),
        impact=(
            "CloudTrail and S3 storage charges may increase. A wrong bucket policy, KMS policy, "
            "home Region, or organization/account choice can prevent delivery or create a second, "
            "overlapping trail."
        ),
        citations=[_draft_citation("45 CFR 164.312(b)", "Audit controls")],
        terraform=terraform,
        filename="cloudtrail_multi_region.tf",
        assumptions=[
            trail_assumption,
            "The CloudTrail S3 bucket name is unknown and therefore has no generated default.",
            "Bucket policy, KMS encryption, log retention, event selectors, organization ownership, account scope, home Region, and Terraform state require review.",
            "The snippet covers management events; service data events require a separate event-selector decision and may add cost.",
        ],
        steps=[
            "Decide whether to update an existing trail, create an account trail, or use an organization trail from its management or delegated administrator account.",
            "Choose the trail home Region and a protected S3 destination, then configure the required CloudTrail bucket policy and any KMS key policy before creating the trail.",
            "If the trail is already managed by Terraform, update it there. If it exists outside Terraform, import it only after confirming the workspace should own the complete trail configuration.",
            "Review management and data event scope, retention, encryption, duplicate-event cost, and delivery health; then plan, apply through the customer's process, and rerun the Prowler check.",
            f"AWS trail reference: {_AWS_CLOUDTRAIL}",
            f"Terraform resource reference: {_TF_CLOUDTRAIL}",
        ],
    )


def _root_mfa(_observation: Observation) -> Recommendation:
    return Recommendation(
        status="manual_action",
        what=(
            "The AWS root identity has active credentials but Prowler did not observe multi-factor "
            "authentication enabled for that identity."
        ),
        why=(
            "Root credentials have unrestricted account authority. A second authentication factor "
            "reduces the chance that a stolen password alone leads to account takeover."
        ),
        change=(
            "An authorized account owner should enroll an MFA device for a standalone root user, "
            "or review centralized root access for an Organizations member account and remove "
            "unneeded member-account root credentials."
        ),
        impact=(
            "The account owner must preserve secure recovery access and update the documented "
            "break-glass procedure. Losing both the MFA device and recovery path can delay emergency access."
        ),
        citations=[_draft_citation("45 CFR 164.312(d)", "Person or entity authentication")],
        terraform=None,
        filename=None,
        assumptions=[
            "The finding does not establish whether the account is standalone or uses centralized root access in AWS Organizations.",
            "MFA enrollment requires control of the root sign-in and a physical or virtual authenticator; no Terraform snippet can safely perform that ceremony.",
        ],
        steps=[
            "Confirm whether this is a standalone account, an Organizations management account, or a member account with centralized root access.",
            "For a root identity that remains sign-in capable, sign in through the AWS root-user flow and assign a securely controlled MFA device.",
            "For an eligible member account, review centralized root access and removal of unnecessary root credentials instead of recreating persistent root access.",
            "Document device custody and recovery, remove root access keys, avoid routine root use, and rerun the Prowler check.",
            f"AWS root-user and MFA reference: {_AWS_ROOT_MFA}",
        ],
    )


def _access_analyzer(_observation: Observation) -> Recommendation:
    terraform = (
        "# Suggested Terraform — review and adapt before applying.\n"
        + _variable(
            "access_analyzer_name",
            "Name for the account-scoped external access analyzer in this AWS Region",
        )
        + "\n"
        + 'resource "aws_accessanalyzer_analyzer" "recommended" {\n'
        + "  analyzer_name = var.access_analyzer_name\n"
        + '  type          = "ACCOUNT"\n'
        + "}\n"
    )
    return Recommendation(
        status="needs_context",
        what=(
            "Prowler did not observe an active IAM Access Analyzer in the scanned account and "
            "Region."
        ),
        why=(
            "Without an analyzer, unintended public or cross-account access to supported resources "
            "is less likely to be surfaced for review."
        ),
        change=(
            "Create an account-scoped external access analyzer in the affected Region, or confirm "
            "that an organization-scoped analyzer owned by the management or delegated administrator "
            "account is the intended control. The snippet shows the account-scoped option."
        ),
        impact=(
            "Creating an analyzer creates an AWS service-linked role and starts producing findings. "
            "An account analyzer uses the current account as its trust boundary; choosing it where "
            "an organization analyzer is intended can duplicate findings and administration."
        ),
        citations=[_draft_citation("45 CFR 164.312(a)(1)", "Access control")],
        terraform=terraform,
        filename="access_analyzer_account.tf",
        assumptions=[
            "The analyzer name is an explicit input because the scan does not provide one.",
            "The snippet must run with an AWS provider configured for the affected account and Region.",
            "Organization membership, delegated administrator ownership, archive rules, alert routing, and existing Terraform state were not available.",
        ],
        steps=[
            "Confirm the affected Region and whether the account or AWS Organization should be the analyzer's zone of trust.",
            "If an analyzer already exists but is inactive or managed elsewhere, repair it in its owning configuration rather than creating a duplicate.",
            "For the account-scoped option, choose access_analyzer_name, plan in a provider configured for the affected account and Region, and review creation of the service-linked role.",
            "If an unmanaged analyzer already exists, import it only after confirming the target workspace should own its full configuration.",
            "After creation, define who reviews findings and rerun the Prowler check in that Region.",
            f"AWS analyzer reference: {_AWS_ACCESS_ANALYZER}",
            f"Terraform resource reference: {_TF_ACCESS_ANALYZER}",
        ],
    )


def _alternate_contacts(observation: Observation) -> Recommendation:
    account_id = observation.account_id if re.fullmatch(r"\d{12}", observation.account_id) else None
    terraform = (
        "# Suggested Terraform — review and adapt before applying.\n"
        + _variable(
            "aws_account_id",
            "Target AWS account ID; cross-account management requires Organizations setup",
            account_id,
        )
        + "\n"
        + 'variable "alternate_contacts" {\n'
        + '  description = "Distinct monitored contacts keyed by BILLING, OPERATIONS, and SECURITY"\n'
        + "  type = map(object({\n"
        + "    name          = string\n"
        + "    title         = string\n"
        + "    email_address = string\n"
        + "    phone_number  = string\n"
        + "  }))\n\n"
        + "  validation {\n"
        + '    condition     = toset(keys(var.alternate_contacts)) == toset(["BILLING", "OPERATIONS", "SECURITY"])\n'
        + '    error_message = "Provide exactly BILLING, OPERATIONS, and SECURITY contacts."\n'
        + "  }\n\n"
        + "  validation {\n"
        + "    condition = (\n"
        + "      length(toset([for contact in values(var.alternate_contacts) : lower(contact.email_address)])) == 3 &&\n"
        + "      length(toset([for contact in values(var.alternate_contacts) : contact.name])) == 3 &&\n"
        + "      length(toset([for contact in values(var.alternate_contacts) : contact.phone_number])) == 3\n"
        + "    )\n"
        + '    error_message = "Each contact must have a distinct name, email address, and phone number."\n'
        + "  }\n"
        + "}\n\n"
        + 'resource "aws_account_alternate_contact" "recommended" {\n'
        + "  for_each = var.alternate_contacts\n\n"
        + "  account_id             = var.aws_account_id\n"
        + "  alternate_contact_type = each.key\n"
        + "  name                   = each.value.name\n"
        + "  title                  = each.value.title\n"
        + "  email_address          = each.value.email_address\n"
        + "  phone_number           = each.value.phone_number\n"
        + "}\n"
    )
    account_assumption = (
        f"The account input default came from the validated 12-digit account ID {account_id}."
        if account_id
        else "The observation did not contain a valid 12-digit account ID; set aws_account_id explicitly."
    )
    return Recommendation(
        status="needs_context",
        what=(
            "The Billing, Operations, and Security alternate contacts are missing, incomplete, or "
            "not distinct from one another or the primary account contact."
        ),
        why=(
            "Distinct monitored routes help AWS reach the responsible team quickly for security, "
            "service, or billing events and reduce dependence on the root contact."
        ),
        change=(
            "Supply approved team contact details for all three roles and manage one alternate-contact "
            "resource for each role. The snippet intentionally contains no invented personal or contact data."
        ),
        impact=(
            "These fields are operational contact data that AWS may use for urgent notices. Wrong, "
            "unmonitored, or personal values can delay response and expose personal information; "
            "updating a member account centrally also requires Organizations trusted access."
        ),
        citations=[
            _draft_citation(
                "45 CFR 164.308(a)(6)(ii)",
                "Security incident procedures — response and reporting",
                url=_ECFR_164_308,
            )
        ],
        terraform=terraform,
        filename="aws_account_alternate_contacts.tf",
        assumptions=[
            account_assumption,
            "Names, titles, email addresses, and phone numbers are required inputs and were not copied from scanner text.",
            "The primary account contact must be reviewed separately because this snippet cannot verify that alternate contacts differ from it.",
            "Standalone versus Organizations management, delegated administration, trusted access, provider account, and Terraform state ownership require review.",
        ],
        steps=[
            "Choose monitored company distribution lists and team phone routes for Billing, Operations, and Security; keep all three distinct and different from the primary account contact.",
            "Decide whether the standalone account or an Organizations management/delegated administrator account owns these settings, and configure the Terraform AWS provider accordingly.",
            "If alternate contacts are already managed, update those resources. If they exist outside Terraform, import each contact type only after confirming ownership.",
            "Protect contact values in variables and state according to the customer's data-handling rules, review the plan, apply through the customer's process, and rerun the Prowler check.",
            f"AWS alternate-contact reference: {_AWS_ALTERNATE_CONTACTS}",
            f"Terraform resource reference: {_TF_ALTERNATE_CONTACT}",
        ],
    )


def _ebs_default_encryption(observation: Observation) -> Recommendation:
    region = observation.region if _AWS_REGION_RE.fullmatch(observation.region) else None
    terraform = (
        "# Suggested Terraform — review and adapt before applying.\n"
        + _variable(
            "aws_region",
            "AWS Region in which to enable EBS encryption by default",
            region,
        )
        + "\n"
        + 'resource "aws_ebs_encryption_by_default" "recommended" {\n'
        + "  region  = var.aws_region\n"
        + "  enabled = true\n"
        + "}\n"
    )
    region_assumption = (
        f"The Region input default came from the validated observation value {region!r}."
        if region
        else "The observation did not contain a valid AWS Region; set aws_region explicitly."
    )
    return Recommendation(
        status="needs_context",
        what=(
            "Prowler observed that EBS encryption by default is disabled for the account in the "
            "reported AWS Region."
        ),
        why=(
            "Enabling the setting makes encryption mandatory for newly created EBS volumes and "
            "new snapshot copies in that Region. It does not encrypt existing volumes or snapshots."
        ),
        change=(
            "Manage the Region-scoped EBS default-encryption setting as enabled. This snippet leaves "
            "the Region's existing default EBS KMS key unchanged."
        ),
        impact=(
            "New EBS resources will depend on the selected default KMS key and authorized principals "
            "must be able to use it. Existing unencrypted resources remain unencrypted, and removing "
            "this Terraform resource disables default encryption according to the provider contract."
        ),
        citations=[_draft_citation("45 CFR 164.312(a)(2)(iv)", "Encryption and decryption")],
        terraform=terraform,
        filename="ebs_default_encryption.tf",
        assumptions=[
            region_assumption,
            "Prowler 5.42.0 reports this Region only when it found EBS volumes or unused-service scanning was enabled.",
            "The current default EBS KMS key, its key policy, cross-account snapshot workflows, and Terraform state ownership were not inferred.",
        ],
        steps=[
            "Confirm the affected account and Region and decide whether the current default EBS KMS key is appropriate before enabling the setting.",
            "If the singleton Region setting is already managed by Terraform, update it there. If it exists outside Terraform, import the default setting only after confirming workspace ownership.",
            "Plan with an AWS provider authorized for the affected account and Region; review KMS permissions and snapshot-copy workflows.",
            "After applying through the customer's process, verify newly created EBS resources and rerun the Prowler check. Plan a separate migration for existing unencrypted resources if required.",
            f"AWS EBS encryption reference: {_AWS_EBS_DEFAULT_ENCRYPTION}",
            f"Terraform resource reference: {_TF_EBS_DEFAULT_ENCRYPTION}",
        ],
    )


def _s3_object_versioning(observation: Observation) -> Recommendation:
    bucket_name = _bucket_name(observation)
    terraform = (
        "# Suggested Terraform — review and adapt before applying.\n"
        + _variable(
            "bucket_name",
            "Existing general-purpose S3 bucket on which to enable versioning",
            bucket_name,
        )
        + "\n"
        + 'resource "aws_s3_bucket_versioning" "recommended" {\n'
        + "  bucket = var.bucket_name\n\n"
        + "  versioning_configuration {\n"
        + '    status = "Enabled"\n'
        + "  }\n"
        + "}\n"
    )
    bucket_assumption = (
        f"The bucket input default came from the validated observation value {bucket_name!r}."
        if bucket_name
        else "The observation did not contain a valid general-purpose S3 bucket name; set bucket_name explicitly."
    )
    return Recommendation(
        status="needs_context",
        what=(
            "Prowler observed that object versioning is disabled or suspended for this S3 bucket. "
            "In Prowler 5.42.0, a denied versioning read is reported as MANUAL instead of FAIL."
        ),
        why=(
            "Versioning retains distinct versions created by future writes and delete operations, "
            "which can help recover from accidental changes. Versioning alone is not a complete backup plan."
        ),
        change=(
            "Enable versioning on the existing general-purpose bucket. The snippet manages only the "
            "bucket's versioning configuration and does not create or replace the bucket."
        ),
        impact=(
            "Stored noncurrent versions can increase S3 charges and change delete behavior. Existing "
            "objects keep their current null version until changed, and lifecycle or replication rules "
            "may need updates. AWS recommends waiting 15 minutes before writes after first enablement."
        ),
        citations=[
            _draft_citation(
                "45 CFR 164.308(a)(7)(ii)(A)",
                "Contingency plan — data backup plan",
                url=_ECFR_164_308,
            )
        ],
        terraform=terraform,
        filename="s3_bucket_versioning.tf",
        assumptions=[
            bucket_assumption,
            "Bucket ownership, directory-bucket status, MFA Delete, replication, lifecycle rules, retention requirements, and Terraform state ownership were not inferred.",
            "This suggestion improves object recovery behavior but does not by itself establish a backup or retention program.",
        ],
        steps=[
            "Confirm the bucket is a supported general-purpose bucket and review retention, lifecycle, replication, and storage-cost requirements.",
            "If bucket versioning is already managed by Terraform, update that resource. If it exists outside Terraform, import it only after confirming the workspace owns the configuration.",
            "Plan and apply through the customer's process, allow for AWS's first-enable propagation guidance, then verify version creation and rerun the Prowler check.",
            "Treat lifecycle expiration, backup isolation, Object Lock, and MFA Delete as separate decisions where required.",
            f"AWS S3 Versioning reference: {_AWS_S3_VERSIONING}",
            f"Terraform resource reference: {_TF_S3_VERSIONING}",
        ],
    )


def _guardduty_enabled(observation: Observation) -> Recommendation:
    region = observation.region if _AWS_REGION_RE.fullmatch(observation.region) else None
    terraform = (
        "# Suggested Terraform — review and adapt before applying.\n"
        + _variable(
            "aws_region",
            "AWS Region in which to create or enable the GuardDuty detector",
            region,
        )
        + "\n"
        + 'resource "aws_guardduty_detector" "recommended" {\n'
        + "  region = var.aws_region\n"
        + "  enable = true\n"
        + "}\n"
    )
    region_assumption = (
        f"The Region input default came from the validated observation value {region!r}."
        if region
        else "The observation did not contain a valid AWS Region; set aws_region explicitly."
    )
    return Recommendation(
        status="needs_context",
        what=(
            "Prowler 5.42.0 reports this check as failed when GuardDuty is absent in the account, "
            "the detector is not configured, or an existing detector is suspended in the Region."
        ),
        why=(
            "An enabled detector analyzes GuardDuty's foundational data sources for potential threats "
            "and produces findings for review in that Region."
        ),
        change=(
            "Create an enabled regional detector or bring the existing detector under management and "
            "set enable to true. Protection-plan features and organization enrollment remain separate choices."
        ),
        impact=(
            "GuardDuty is billed by analyzed activity after applicable trials. First enablement creates "
            "service-linked roles and may enable supported protection plans by default. Deleting the "
            "Terraform-managed detector disables GuardDuty in the Region and removes existing findings."
        ),
        citations=[
            _draft_citation(
                "45 CFR 164.308(a)(1)(ii)(D)",
                "Information system activity review",
                url=_ECFR_164_308,
            )
        ],
        terraform=terraform,
        filename="guardduty_detector.tf",
        assumptions=[
            region_assumption,
            "Prowler may mute failed non-default-Region findings when its mute_non_default_regions setting is enabled.",
            "Standalone, member, or delegated-administrator ownership, existing detector ID, protection plans, alert routing, publishing frequency, and Terraform state were not inferred.",
        ],
        steps=[
            "Confirm the affected account and Region and whether GuardDuty is managed centrally through AWS Organizations.",
            "If a detector exists but is suspended, import or update it in its owning workspace instead of creating a competing detector. Import only after confirming state ownership.",
            "Review regional coverage, delegated administration, member auto-enrollment, protection plans, finding routing, retention, and expected charges.",
            "Plan and apply through the customer's process, confirm the detector is enabled, and rerun the Prowler check in the Region.",
            f"AWS GuardDuty reference: {_AWS_GUARDDUTY}",
            f"Terraform resource reference: {_TF_GUARDDUTY}",
        ],
    )


_CATALOG: dict[str, Callable[[Observation], Recommendation]] = {
    "s3_bucket_level_public_access_block": _s3_bucket_public_access,
    "s3_account_level_public_access_blocks": _s3_account_public_access,
    "cloudtrail_multi_region_enabled": _cloudtrail_multi_region,
    "iam_root_mfa_enabled": _root_mfa,
    "accessanalyzer_enabled": _access_analyzer,
    "account_maintain_different_contact_details_to_security_billing_and_operations": (
        _alternate_contacts
    ),
    "ec2_ebs_default_encryption": _ebs_default_encryption,
    "s3_bucket_object_versioning": _s3_object_versioning,
    "guardduty_is_enabled": _guardduty_enabled,
}


def recommend(observation: Observation) -> Recommendation:
    """Return reviewed guidance, or an explicit and actionable coverage gap."""
    builder = _CATALOG.get(observation.check_id)
    if builder is not None:
        return builder(observation)

    check_reference = f"{_PROWLER_HUB}{observation.check_id}"
    return Recommendation(
        status="unsupported",
        what=(
            f"The finding for Prowler check {observation.check_id!r} has no reviewed recommendation "
            "template in this bounded prototype catalog."
        ),
        why=(
            "Generating Terraform without a reviewed check-to-resource mapping could target the "
            "wrong AWS control or conceal required inputs."
        ),
        change=(
            "A reviewer must confirm the check's current Prowler behavior, affected AWS resource, "
            "authoritative remediation guidance, Terraform ownership model, and required inputs "
            "before adding a versioned template."
        ),
        impact=(
            "No configuration change is suggested. The finding remains visible and unresolved; "
            "report generation must not present this coverage gap as a fix."
        ),
        terraform=None,
        filename=None,
        assumptions=[
            "No AWS configuration or Terraform ownership was inferred from the scanner title, detail, or resource name."
        ],
        steps=[
            f"Review the current check definition and remediation metadata: {check_reference}",
            "Confirm the resource's intended behavior and ownership with the responsible AWS and Terraform administrators.",
            "Add and validate a reviewed catalog template before offering code for this check.",
        ],
    )
