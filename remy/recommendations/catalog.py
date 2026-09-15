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

from remy.recommendations.cloudtrail import CLOUDTRAIL_BUILDERS
from remy.recommendations.dynamodb import DYNAMODB_BUILDERS
from remy.recommendations.ec2 import EC2_BUILDERS
from remy.recommendations.efs import EFS_BUILDERS
from remy.recommendations.identifiers import (
    AWS_REGION_RE as _AWS_REGION_RE,
)
from remy.recommendations.identifiers import (
    bucket_name as _bucket_name,
)
from remy.recommendations.identifiers import (
    trail_name as _trail_name,
)
from remy.recommendations.rds import RDS_BUILDERS
from remy.recommendations.s3 import S3_BUILDERS
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
_AWS_ROOT_ACCESS_KEYS = (
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user_manage_delete-key.html"
)
_AWS_ROOT_HARDWARE_MFA = (
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/enable-hw-mfa-for-root.html"
)
_AWS_IAM_USER_MFA = (
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_cliapi.html"
)
_AWS_ACCESS_KEYS = "https://docs.aws.amazon.com/IAM/latest/UserGuide/securing_access-keys.html"
_AWS_IAM_POLICY_MANAGEMENT = (
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_manage.html"
)
_AWS_IAM_POLICY_VALIDATION = (
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-validation.html"
)
_AWS_MARKETPLACE_AUTHORIZATION = (
    "https://docs.aws.amazon.com/service-authorization/latest/reference/"
    "list_marketplace-agreement.html"
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
_AWS_GUARDDUTY_FINDINGS = (
    "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings-summary.html"
)
_AWS_EC2_INSTANCE_LIFECYCLE = (
    "https://docs.aws.amazon.com/prescriptive-guidance/latest/strategy-automating-patching/"
    "operationalize-and-optimize.html"
)
_AWS_KMS_ROTATION = (
    "https://docs.aws.amazon.com/kms/latest/developerguide/rotating-keys-enable.html"
)
_AWS_NITRO_KMS_ATTESTATION = (
    "https://docs.aws.amazon.com/kms/latest/developerguide/conditions-nitro-enclave.html"
)
_AWS_IAM_PASSWORD_POLICY = (
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html"
)
_TF_IAM_PASSWORD_POLICY = (
    "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/"
    "iam_account_password_policy"
)
_PROWLER_HUB = "https://hub.prowler.com/check/"

SUPPORTED_CHECK_IDS = frozenset(
    {
        "s3_bucket_level_public_access_block",
        "s3_account_level_public_access_blocks",
        "cloudtrail_multi_region_enabled",
        "iam_root_mfa_enabled",
        "iam_no_root_access_key",
        "iam_root_hardware_mfa_enabled",
        "iam_user_mfa_enabled_console_access",
        "iam_rotate_access_key_90_days",
        "iam_user_accesskey_unused",
        "iam_user_console_access_unused",
        "iam_aws_attached_policy_no_administrative_privileges",
        "iam_customer_attached_policy_no_administrative_privileges",
        "iam_inline_policy_no_administrative_privileges",
        "iam_inline_policy_no_wildcard_marketplace_subscribe",
        "iam_policy_no_wildcard_marketplace_subscribe",
        "accessanalyzer_enabled",
        "account_maintain_different_contact_details_to_security_billing_and_operations",
        "ec2_ebs_default_encryption",
        "s3_bucket_object_versioning",
        "guardduty_is_enabled",
        "guardduty_no_high_severity_findings",
        "ec2_instance_older_than_specific_days",
        "kms_cmk_rotation_enabled",
        "kms_key_enclave_attestation_bypassable_path",
        "kms_key_enclave_attestation_not_enforced",
        "kms_key_enclave_attestation_pcr_mismatch",
        "kms_key_enclave_attestation_unknown_image",
        "kms_key_enclave_debug_attestation_detected",
        *S3_BUILDERS,
        *CLOUDTRAIL_BUILDERS,
        *DYNAMODB_BUILDERS,
        *EC2_BUILDERS,
        *EFS_BUILDERS,
        *RDS_BUILDERS,
        "iam_password_policy_lowercase",
        "iam_password_policy_minimum_length_14",
        "iam_password_policy_number",
        "iam_password_policy_reuse_24",
        "iam_password_policy_symbol",
        "iam_password_policy_uppercase",
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


def _root_access_key(_observation: Observation) -> Recommendation:
    return Recommendation(
        status="manual_action",
        what=("Prowler observed one or two active access keys for the AWS account root user."),
        why=(
            "A root access key has unrestricted account authority and cannot be limited with an IAM "
            "permissions policy. Long-lived root keys create a high-impact credential exposure risk."
        ),
        change=(
            "Identify every dependency on each root access key, replace it with a least-privilege IAM "
            "role or other workload identity, deactivate the root key, verify the replacement, and "
            "then delete the key through an authorized root-user procedure."
        ),
        impact=(
            "Deactivation or deletion immediately breaks any workload still using the key. A deleted "
            "access key cannot be recovered, so usage evidence, an owner-approved migration, and a "
            "tested replacement are required before deletion."
        ),
        citations=[_draft_citation("45 CFR 164.312(a)(2)(i)", "Unique user identification")],
        terraform=None,
        filename=None,
        assumptions=[
            "The finding does not identify workloads, scripts, people, or external systems that use the root key.",
            "Remy does not collect, display, rotate, deactivate, or delete customer credentials.",
            "AWS Organizations centralized root access may change the recovery and credential-removal procedure for a member account.",
        ],
        steps=[
            "Confirm the account type and whether centralized root access is enabled in AWS Organizations.",
            "Use approved credential-usage evidence and owner interviews to identify dependencies without copying the secret access key into Remy.",
            "Replace each dependency with a least-privilege role or other short-lived credential mechanism and test it.",
            "Using the authorized root-user process, deactivate the key first, monitor for failures, and delete it only after the migration is confirmed. Record the key ID, not the secret, in the change record.",
            "Rerun the Prowler check and separately review root password, MFA, contacts, and recovery controls.",
            f"AWS root access-key deletion reference: {_AWS_ROOT_ACCESS_KEYS}",
        ],
    )


def _root_hardware_mfa(_observation: Observation) -> Recommendation:
    return Recommendation(
        status="manual_action",
        what=(
            "For a commercial-partition account with active root credentials, Prowler 5.42.0 did "
            "not observe the root MFA state it classifies as hardware-backed. The result can mean "
            "that MFA is absent or that Prowler observed a virtual MFA device."
        ),
        why=(
            "Root credentials have unrestricted authority. A separately controlled physical factor "
            "reduces reliance on a root password and a general-purpose authenticator device."
        ),
        change=(
            "The account owner should review the actual registered root authenticators and recovery "
            "model, then enroll an approved physical authenticator—preferring a phishing-resistant "
            "security key where supported—or remove unnecessary member-account root credentials through "
            "centralized root access."
        ),
        impact=(
            "Changing root MFA requires secure custody, recovery planning, and access to the root-user "
            "sign-in flow. Removing the old device too early or losing the new device and recovery "
            "factors can delay emergency account access."
        ),
        citations=[_draft_citation("45 CFR 164.312(d)", "Person or entity authentication")],
        terraform=None,
        filename=None,
        assumptions=[
            "The Prowler check is limited to the commercial AWS partition and infers hardware status from account-summary and virtual-device data.",
            "The finding alone does not identify the exact physical authenticator, its custodian, backup device, or recovery readiness.",
            "Root MFA enrollment is a credential ceremony and is not represented as Terraform guidance.",
        ],
        steps=[
            "Confirm whether the account retains individual root credentials or uses AWS Organizations centralized root access.",
            "Have the authorized account owners inspect registered root authenticators and update verified account contact and recovery information.",
            "If root sign-in remains enabled, enroll the approved physical authenticator using the AWS root-user console flow, verify it, document custody, and only then retire superseded devices.",
            "Test the approved recovery procedure without exposing authentication seeds or one-time codes, then rerun both root MFA checks.",
            f"AWS hardware MFA enrollment reference: {_AWS_ROOT_HARDWARE_MFA}",
        ],
    )


def _iam_user_mfa(_observation: Observation) -> Recommendation:
    return Recommendation(
        status="manual_action",
        what=(
            "Prowler observed an IAM user with an enabled console password and no active MFA device."
        ),
        why=(
            "A console password without MFA can allow account access when that password is stolen. "
            "Long-lived IAM users also require explicit lifecycle and credential ownership."
        ),
        change=(
            "Confirm whether the IAM user's console access is still required. Remove the login profile "
            "if it is not; otherwise enroll an approved MFA device with the user and enforce the "
            "organization's MFA-based access policy."
        ),
        impact=(
            "Removing console access prevents direct password sign-in but does not remove access keys "
            "or assumed-role access. MFA enrollment handles authentication secrets and activation "
            "codes; generating a Terraform resource can put sensitive seed material in state and does "
            "not complete secure custody or access-policy enforcement."
        ),
        citations=[_draft_citation("45 CFR 164.312(d)", "Person or entity authentication")],
        terraform=None,
        filename=None,
        assumptions=[
            "The finding does not establish whether this is a human, service, emergency, or obsolete IAM user.",
            "The user's manager, identity-provider eligibility, device choice, access-key use, and recovery process require review.",
            "Remy does not collect MFA seeds, QR codes, one-time codes, passwords, or recovery factors.",
        ],
        steps=[
            "Confirm the IAM user's owner, purpose, recent activity, permissions, access keys, and eligibility for federation or IAM Identity Center.",
            "If console access is unnecessary, remove the login profile through the customer's identity lifecycle process and verify that other credentials are handled separately.",
            "If console access remains necessary, enroll an approved MFA device with the user, verify activation, and apply the customer's policy that requires MFA for sensitive actions.",
            "Document recovery and offboarding ownership without storing authentication secrets in Remy, then rerun the Prowler check.",
            f"AWS IAM-user MFA reference: {_AWS_IAM_USER_MFA}",
        ],
    )


def _iam_access_key_lifecycle(observation: Observation) -> Recommendation:
    stale = observation.check_id == "iam_user_accesskey_unused"
    what = (
        "Prowler observed an active IAM-user access key whose recorded last use is older than the "
        "configured inactivity threshold. Prowler 5.42.0 defaults that threshold to 45 days."
        if stale
        else "Prowler observed an active IAM-user access key whose last rotation is more than 90 days old."
    )
    reason = "inactivity" if stale else "age"
    return Recommendation(
        status="manual_action",
        what=what,
        why=(
            f"Long-lived access-key {reason} increases the time a copied credential can remain usable. "
            "Recorded inactivity can support a removal decision, but it does not prove that no "
            "infrequent or external dependency still uses the key."
        ),
        change=(
            "Prefer replacing the IAM-user key with a role or another temporary-credential mechanism. "
            "If a long-lived key is still required, create and distribute a replacement through the "
            "customer's secret-management process, verify consumers, deactivate the old key, observe, "
            "and then delete it."
        ),
        impact=(
            "Rotating, deactivating, or deleting a key can immediately break scripts, workloads, CI "
            "jobs, or external integrations. A deleted secret access key cannot be recovered. Creating "
            "keys in generic Terraform also stores sensitive key material in Terraform state."
        ),
        citations=[
            _draft_citation(
                "45 CFR 164.308(a)(3)(ii)(C)",
                "Workforce security — termination procedures",
                url=_ECFR_164_308,
            )
        ],
        terraform=None,
        filename=None,
        assumptions=[
            "The observation does not identify every consumer, secret store, owner, permission use, or emergency dependency.",
            "Last-used data and the Prowler threshold require confirmation against the customer's scan configuration and retention needs.",
            "Remy does not generate, collect, display, distribute, rotate, deactivate, or delete customer access keys.",
        ],
        steps=[
            "Confirm the IAM user owner, key ID, creation or rotation date, last-used service and Region, permissions, and all known consumers without copying the secret into Remy.",
            "Determine whether the consumer can use an AWS role, workload identity, federation, or another temporary-credential mechanism instead.",
            "Migrate and test each consumer. If a long-lived replacement remains necessary, distribute it only through the approved secret-management path.",
            "Deactivate the old key, monitor for failures for an owner-approved period, and delete it only after dependencies are confirmed migrated.",
            "Review the IAM user's remaining permissions and credentials, then rerun the relevant Prowler check.",
            f"AWS access-key guidance: {_AWS_ACCESS_KEYS}",
        ],
    )


def _iam_unused_console_access(_observation: Observation) -> Recommendation:
    return Recommendation(
        status="manual_action",
        what=(
            "Prowler observed an IAM user with console access whose recorded password use is older "
            "than the configured threshold. Prowler 5.42.0 defaults that threshold to 45 days."
        ),
        why=(
            "An unused console password remains a long-lived sign-in path. Inactivity is a review "
            "signal, not proof that the identity is obsolete or that access can be removed safely."
        ),
        change=(
            "Confirm ownership and business need. Remove the IAM login profile when direct console "
            "access is no longer required, or retain it only with an approved exception, MFA, and "
            "documented lifecycle owner. Prefer federation or IAM Identity Center for workforce access."
        ),
        impact=(
            "Removing the login profile prevents direct password sign-in for that IAM user but does "
            "not revoke access keys, active sessions, or access obtained by assuming roles. An "
            "incorrect removal can block emergency or infrequent operational access."
        ),
        citations=[
            _draft_citation(
                "45 CFR 164.308(a)(3)(ii)(B)",
                "Workforce security — workforce clearance procedure",
                url=_ECFR_164_308,
            )
        ],
        terraform=None,
        filename=None,
        assumptions=[
            "The observation does not establish the user's owner, employment state, emergency role, federation eligibility, or other credentials.",
            "The configured inactivity threshold and AWS password-last-used data require confirmation before access removal.",
            "A generic Terraform login-profile change is not emitted because identity ownership and the rest of the user's credential lifecycle are unknown.",
        ],
        steps=[
            "Confirm the user's owner, business purpose, last activity, groups and policies, MFA state, access keys, and emergency-access designation.",
            "Obtain the identity owner's removal or exception decision and verify that an approved alternative access path exists where needed.",
            "Remove the login profile through the customer's identity lifecycle process, or document a time-bounded exception with MFA and review ownership.",
            "Review other credentials and sessions separately, notify affected owners, and rerun the Prowler check.",
        ],
    )


def _iam_administrative_policy(observation: Observation) -> Recommendation:
    policy_kind = {
        "iam_aws_attached_policy_no_administrative_privileges": "an attached AWS-managed policy",
        "iam_customer_attached_policy_no_administrative_privileges": (
            "an attached customer-managed policy"
        ),
        "iam_inline_policy_no_administrative_privileges": "an inline policy",
    }[observation.check_id]
    return Recommendation(
        status="needs_context",
        what=(
            f"Prowler found {policy_kind} that allows both all actions and all resources. The saved "
            "observation does not include the full policy, attachments, or effective-permission context."
        ),
        why=(
            "Unrestricted administrative permission can let a compromised or misused principal alter "
            "security controls, data, identities, and logging across the account."
        ),
        change=(
            "Identify every attached principal and required job function, design a tested "
            "least-privilege replacement, and then update or detach the broad policy in its owning "
            "configuration. AWS-managed policies cannot be edited and require replacement."
        ),
        impact=(
            "Removing broad permissions before validating replacement access can cause an outage or "
            "lock out administrators. Identity policies also interact with resource policies, "
            "permissions boundaries, session policies, and Organizations controls, so changing one "
            "document does not by itself establish effective least privilege."
        ),
        citations=[_draft_citation("45 CFR 164.312(a)(1)", "Access control")],
        terraform=None,
        filename=None,
        assumptions=[
            "Policy JSON, attachment inventory, principal purpose, access activity, permission boundaries, SCPs, and Terraform ownership were not available to the report generator.",
            "No replacement policy can be derived safely from the check name, policy name, or finding text alone.",
            "The recommendation addresses an identity-policy finding and does not assert that all effective permissions have been evaluated.",
        ],
        steps=[
            "Inventory every user, group, and role that receives the policy and identify the owner and required tasks for each principal.",
            "Review CloudTrail and IAM last-accessed information with appropriate retention caveats, then draft separate least-privilege permissions where job functions differ.",
            "Validate policy grammar and security findings with IAM Access Analyzer, simulate and test representative workflows, and preserve a reviewed emergency-access path.",
            "Update the customer-managed or inline policy in its owning configuration, or replace and detach an AWS-managed administrator policy. Roll out in stages and monitor denied actions.",
            "Rerun the Prowler check and review other policy layers before recording the remediation as verified.",
            f"AWS IAM policy management reference: {_AWS_IAM_POLICY_MANAGEMENT}",
            f"AWS IAM policy validation reference: {_AWS_IAM_POLICY_VALIDATION}",
        ],
    )


def _iam_marketplace_subscribe_policy(observation: Observation) -> Recommendation:
    policy_kind = (
        "inline"
        if observation.check_id == "iam_inline_policy_no_wildcard_marketplace_subscribe"
        else "customer-managed"
    )
    return Recommendation(
        status="needs_context",
        what=(
            f"Prowler found a {policy_kind} IAM policy allowing aws-marketplace:Subscribe with a "
            "wildcard resource. AWS does not currently define a resource type for this action, so a "
            "policy that grants it must use a wildcard resource."
        ),
        why=(
            "Subscribe is a purchasing-capable permission. Granting it to a principal that does not "
            "need procurement authority can allow unapproved product subscriptions and charges."
        ),
        change=(
            "Remove aws-marketplace:Subscribe from principals that do not have approved purchasing "
            "responsibility. Where the action is required, isolate it in an explicitly owned policy "
            "and apply available approval, condition, budget, and monitoring controls; do not invent a "
            "resource ARN for an action that lacks resource-level authorization."
        ),
        impact=(
            "Removing the action can block legitimate marketplace procurement and deployment workflows. "
            "Keeping it may be an accepted business requirement, but the wildcard resource cannot be "
            "made narrower unless AWS adds resource-level support."
        ),
        citations=[
            _draft_citation(
                "45 CFR 164.308(a)(4)(ii)(B)",
                "Information access management — access authorization",
                url=_ECFR_164_308,
            )
        ],
        terraform=None,
        filename=None,
        assumptions=[
            "The policy document, attached principals, procurement workflow, AWS Organizations controls, and Terraform ownership were not available.",
            "A failed check is not enough to decide that the permission is unauthorized; the responsible procurement and security owners must decide.",
            "No resource-scoped Terraform example is emitted because the AWS service authorization reference lists no resource type for aws-marketplace:Subscribe.",
        ],
        steps=[
            "Identify every principal receiving the policy and confirm whether each principal has approved marketplace purchasing responsibility.",
            "Remove the action for principals that do not need it. For approved purchasers, isolate the permission and add the organization's applicable approval, condition, budget, and alerting controls.",
            "Validate and test the revised policy, update it in its owning configuration, monitor denied subscription attempts, and rerun the Prowler check.",
            f"AWS Marketplace authorization reference: {_AWS_MARKETPLACE_AUTHORIZATION}",
        ],
    )


def _guardduty_high_severity(_observation: Observation) -> Recommendation:
    return Recommendation(
        status="manual_action",
        what=(
            "Prowler observed one or more high-severity GuardDuty findings associated with an "
            "enabled regional detector."
        ),
        why=(
            "A high-severity finding is a security signal requiring triage. Its presence does not "
            "identify the root cause or establish that a compromise occurred."
        ),
        change=(
            "Open each current finding in the owning account and Region, preserve relevant evidence, "
            "validate the affected resources and activity, contain confirmed threats, remediate the "
            "underlying cause, and archive a finding only after the response owner documents disposition."
        ),
        impact=(
            "Containment can interrupt workloads, credentials, network paths, or data access. "
            "Suppressing or archiving findings without investigation can hide continuing activity and "
            "does not remediate the underlying condition."
        ),
        citations=[
            _draft_citation(
                "45 CFR 164.308(a)(6)(ii)",
                "Security incident procedures — response and reporting",
                url=_ECFR_164_308,
            )
        ],
        terraform=None,
        filename=None,
        assumptions=[
            "The saved observation does not include the complete GuardDuty finding, affected-resource state, evidence, or investigation history.",
            "Severity is a prioritization input; it is not proof of malicious activity, breach, or regulatory noncompliance.",
            "A generic infrastructure patch cannot safely substitute for incident triage and service-specific remediation.",
        ],
        steps=[
            "Assign the finding to the security-response owner and retrieve the complete current finding in its account and Region.",
            "Preserve relevant GuardDuty, CloudTrail, network, identity, and workload evidence under the customer's response procedures.",
            "Validate the activity, scope affected resources and credentials, and follow the finding-type remediation guidance with service owners.",
            "Contain and eradicate confirmed threats with explicit change authority, verify recovery and monitoring, and document false-positive or accepted-risk decisions.",
            "Archive or suppress only under the approved disposition process, then rerun the Prowler check and confirm no qualifying active findings remain.",
            f"AWS GuardDuty finding reference: {_AWS_GUARDDUTY_FINDINGS}",
        ],
    )


def _ec2_instance_age(_observation: Observation) -> Recommendation:
    return Recommendation(
        status="needs_context",
        what=(
            "Prowler observed a running EC2 instance older than the configured age threshold. "
            "Prowler 5.42.0 defaults the threshold to 180 days."
        ),
        why=(
            "Instance age is a maintenance signal. A long-running instance can miss immutable-image "
            "refreshes or lifecycle controls, but age alone does not prove that its operating system, "
            "packages, agent state, or configuration is vulnerable."
        ),
        change=(
            "Identify the workload owner and maintenance model, verify patch and configuration state, "
            "and choose an owner-approved response: replace from a current image, patch in place, "
            "retire the instance, or document an exception with compensating monitoring."
        ),
        impact=(
            "Stopping, terminating, patching, or replacing an instance can cause downtime, data loss, "
            "address changes, capacity changes, or application incompatibility. A generic Terraform "
            "replacement could destroy instance-local state and is not emitted."
        ),
        citations=[
            _draft_citation(
                "45 CFR 164.308(a)(1)(ii)(B)",
                "Risk management",
                url=_ECFR_164_308,
            )
        ],
        terraform=None,
        filename=None,
        assumptions=[
            "The configured age threshold, workload criticality, launch template, image pipeline, patch state, storage layout, and recovery readiness were not available.",
            "The observation does not establish whether the instance is immutable, stateful, clustered, autoscaled, or already under an approved maintenance exception.",
            "No stop, terminate, replacement, or in-place patch action is authorized by this report.",
        ],
        steps=[
            "Confirm the scan threshold and identify the workload, owner, environment, dependencies, data location, recovery point, and maintenance window.",
            "Review current patch, vulnerability, configuration-management, backup, launch-template, and image provenance evidence.",
            "Choose and test replacement, patching, retirement, or exception handling with the service owner; preserve data and rollback capability.",
            "Execute through the customer's change process, validate service health and monitoring, and rerun the relevant Prowler checks.",
            f"AWS lifecycle and patching reference: {_AWS_EC2_INSTANCE_LIFECYCLE}",
        ],
    )


def _kms_rotation(_observation: Observation) -> Recommendation:
    return Recommendation(
        status="needs_context",
        what=(
            "Prowler observed an enabled, customer-managed symmetric KMS key with automatic key "
            "rotation disabled."
        ),
        why=(
            "Automatic rotation periodically replaces the backing cryptographic material while "
            "preserving the key ID, ARN, aliases, policies, and ability to decrypt older ciphertext."
        ),
        change=(
            "Enable automatic rotation for the existing key after confirming its origin, key type, "
            "multi-Region role, ownership, and approved rotation period. If the key is already managed "
            "by Terraform, update its owning aws_kms_key resource rather than declaring a second key."
        ),
        impact=(
            "Supported automatic rotation is designed not to interrupt cryptographic operations, but "
            "the setting is shared for related multi-Region keys and is changed on the primary. "
            "Imported material, asymmetric keys, HMAC keys, and custom key stores require different "
            "rotation procedures. Taking ownership of an existing KMS key policy can cause lockout."
        ),
        citations=[_draft_citation("45 CFR 164.312(a)(2)(iv)", "Encryption and decryption")],
        terraform=None,
        filename=None,
        assumptions=[
            "The report has not verified key origin, multi-Region primary or replica role, policy ownership, aliases, grants, application dependencies, or current Terraform state.",
            "No complete aws_kms_key block is emitted because safely importing the key requires ownership of its policy and lifecycle settings, not only rotation.",
            "The Prowler finding does not choose a custom rotation period or a manual-rotation procedure for unsupported key types.",
        ],
        steps=[
            "Confirm the key ARN, Region, enabled state, origin, key spec, multi-Region role, owner, aliases, grants, policy, and dependent services.",
            "Select the approved rotation period and confirm that automatic rotation is supported; for multi-Region keys, make the change on the primary.",
            "If Terraform already manages the key, set enable_key_rotation and any approved rotation period there. Otherwise use the owning KMS process or import only after full policy and lifecycle review.",
            "Validate authorization, apply through the customer's process, verify rotation status and next rotation date, and rerun the Prowler check.",
            f"AWS KMS rotation reference: {_AWS_KMS_ROTATION}",
        ],
    )


_ENCLAVE_POLICY_CHECKS = {
    "kms_key_enclave_attestation_bypassable_path",
    "kms_key_enclave_attestation_not_enforced",
    "kms_key_enclave_attestation_pcr_mismatch",
}


def _kms_enclave_attestation(observation: Observation) -> Recommendation:
    runtime_check = observation.check_id not in _ENCLAVE_POLICY_CHECKS
    what_by_check = {
        "kms_key_enclave_attestation_bypassable_path": (
            "Prowler found a sensitive KMS allow path that can be used without a restrictive "
            "recipient-attestation condition and is not neutralized by a matching deny."
        ),
        "kms_key_enclave_attestation_not_enforced": (
            "Prowler found a sensitive allow statement on an enclave-designated KMS key without a "
            "kms:RecipientAttestation condition."
        ),
        "kms_key_enclave_attestation_pcr_mismatch": (
            "Prowler found a KMS key-policy attestation measurement outside the operator-supplied "
            "golden PCR values."
        ),
        "kms_key_enclave_attestation_unknown_image": (
            "Prowler found a recent non-debug KMS request whose enclave attestation measurements are "
            "not present in the configured golden image registry."
        ),
        "kms_key_enclave_debug_attestation_detected": (
            "Prowler found a recent sensitive KMS request with zeroed PCR0, PCR1, and PCR2 values, "
            "which its check interprets as Nitro Enclave debug mode."
        ),
    }
    return Recommendation(
        status="manual_action" if runtime_check else "needs_context",
        what=what_by_check[observation.check_id],
        why=(
            "Nitro Enclave KMS authorization depends on signed attestation measurements matching "
            "trusted policy conditions. Missing, bypassable, stale, unknown, or debug measurements can "
            "allow sensitive operations outside the intended production enclave identity."
        ),
        change=(
            "Treat runtime unknown-image or debug events as security signals requiring evidence "
            "preservation and workload investigation. For policy findings, reconcile trusted build "
            "measurements, principals, sensitive actions, IAM policies, grants, allow statements, and "
            "explicit deny coverage before updating the complete owning KMS policy."
        ),
        impact=(
            "An incorrect attestation value or policy condition can block every legitimate enclave "
            "decrypt or data-key request. Relaxing conditions can expose plaintext or data keys outside "
            "the intended enclave. Replacing a policy without preserving administration paths can make "
            "the KMS key unmanageable."
        ),
        citations=[_draft_citation("45 CFR 164.312(a)(1)", "Access control")],
        terraform=None,
        filename=None,
        assumptions=[
            "The report does not retain full KMS policies, IAM policies, grants, CloudTrail events, attestation documents, build provenance, or the customer's golden PCR registry.",
            "Prowler identifies enclave keys through its configured tags or descriptive markers and relies on operator-supplied audit configuration for golden measurements and runtime coverage.",
            "No policy JSON or PCR value is generated because trusted measurements must come from the customer's audited enclave build pipeline.",
        ],
        steps=[
            "Assign the finding to the KMS, enclave-platform, workload, and security owners; retrieve the current key policy, grants, relevant IAM policies, audit configuration, and retained CloudTrail evidence.",
            "Verify the enclave image and signing/build provenance, independently derive expected measurements, and compare them with the approved golden registry and observed attestation values.",
            "For a runtime finding, contain unapproved or debug workloads and rotate exposed application secrets or data keys when the investigation determines exposure is possible.",
            "For a policy finding, model every sensitive authorization path and preserve a separate administrative path that cannot perform sensitive data operations; test the revised policy in a nonproduction key.",
            "Deploy through the owning configuration with staged verification, confirm legitimate enclave operations and denied bypasses, then rerun all applicable enclave checks with complete regional event coverage.",
            f"AWS KMS Nitro Enclave attestation reference: {_AWS_NITRO_KMS_ATTESTATION}",
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


def _iam_password_policy(_observation: Observation) -> Recommendation:
    terraform = (
        "# Suggested Terraform — review and adapt before applying.\n"
        + 'variable "allow_users_to_change_password" {\n'
        + '  description = "Whether IAM users may change their own console password"\n'
        + "  type        = bool\n"
        + "}\n\n"
        + 'variable "hard_expiry" {\n'
        + '  description = "Whether expired passwords require an administrator reset"\n'
        + "  type        = bool\n"
        + "}\n\n"
        + 'variable "max_password_age" {\n'
        + '  description = "Approved password lifetime in days; use 0 to disable expiration"\n'
        + "  type        = number\n"
        + "}\n\n"
        + 'resource "aws_iam_account_password_policy" "recommended" {\n'
        + "  minimum_password_length        = 14\n"
        + "  password_reuse_prevention      = 24\n"
        + "  require_lowercase_characters   = true\n"
        + "  require_numbers                = true\n"
        + "  require_symbols                = true\n"
        + "  require_uppercase_characters   = true\n"
        + "  allow_users_to_change_password = var.allow_users_to_change_password\n"
        + "  hard_expiry                    = var.hard_expiry\n"
        + "  max_password_age               = var.max_password_age\n"
        + "}\n"
    )
    return Recommendation(
        status="needs_context",
        what=(
            "One of the six reviewed IAM account password-policy checks failed. The account's "
            "custom policy does not meet the complete reviewed baseline for length, reuse, and "
            "lowercase, uppercase, number, and symbol requirements."
        ),
        why=(
            "A stronger account policy improves passwords chosen for IAM users who sign in to the "
            "AWS console. It does not govern the root user, access keys, IAM Identity Center, or "
            "federated identities, and it does not replace MFA."
        ),
        change=(
            "Manage the account's single IAM password policy as one resource. The suggested baseline "
            "sets all six reviewed controls together; supply explicit decisions for password "
            "expiration, hard expiry, and users changing their own passwords before planning."
        ),
        impact=(
            "Most complexity changes apply when IAM users next change passwords and do not force "
            "existing passwords to change. A nonzero maximum age applies immediately and can expire "
            "older passwords. Hard expiry can require administrator resets. Terraform takes ownership "
            "of the account's only custom password policy, so parallel snippets must not be applied."
        ),
        citations=[
            _draft_citation(
                "45 CFR 164.308(a)(5)(ii)(D)",
                "Security awareness and training — password management",
                url=_ECFR_164_308,
            )
        ],
        terraform=terraform,
        filename="iam_account_password_policy.tf",
        assumptions=[
            "The six complexity values are a combined Prowler 5.42.0 check baseline, not a claim that HIPAA prescribes these exact values.",
            "The scan does not supply approved values for password expiration, hard expiry, or self-service password changes, so those inputs have no defaults.",
            "Existing policy ownership, IAM-user population, break-glass procedures, federation, IAM Identity Center, and Terraform state were not inferred.",
        ],
        steps=[
            "Inventory IAM users with console passwords and confirm whether workforce access should instead use federation or IAM Identity Center.",
            "Review the current account policy and decide max_password_age, hard_expiry, and allow_users_to_change_password with the identity and support owners.",
            "Use one Terraform resource for all password-policy findings in the account. Import the existing singleton policy only after confirming the workspace should own every setting.",
            "Run terraform plan and review immediate expiration and support effects before applying through the customer's process; then rerun all six Prowler password-policy checks.",
            "Require MFA separately and verify that recovery and administrator-reset procedures remain workable.",
            f"AWS account password-policy reference: {_AWS_IAM_PASSWORD_POLICY}",
            f"Terraform resource reference: {_TF_IAM_PASSWORD_POLICY}",
        ],
    )


_CATALOG: dict[str, Callable[[Observation], Recommendation]] = {
    "s3_bucket_level_public_access_block": _s3_bucket_public_access,
    "s3_account_level_public_access_blocks": _s3_account_public_access,
    "cloudtrail_multi_region_enabled": _cloudtrail_multi_region,
    "iam_root_mfa_enabled": _root_mfa,
    "iam_no_root_access_key": _root_access_key,
    "iam_root_hardware_mfa_enabled": _root_hardware_mfa,
    "iam_user_mfa_enabled_console_access": _iam_user_mfa,
    "iam_rotate_access_key_90_days": _iam_access_key_lifecycle,
    "iam_user_accesskey_unused": _iam_access_key_lifecycle,
    "iam_user_console_access_unused": _iam_unused_console_access,
    "iam_aws_attached_policy_no_administrative_privileges": _iam_administrative_policy,
    "iam_customer_attached_policy_no_administrative_privileges": _iam_administrative_policy,
    "iam_inline_policy_no_administrative_privileges": _iam_administrative_policy,
    "iam_inline_policy_no_wildcard_marketplace_subscribe": _iam_marketplace_subscribe_policy,
    "iam_policy_no_wildcard_marketplace_subscribe": _iam_marketplace_subscribe_policy,
    "accessanalyzer_enabled": _access_analyzer,
    "account_maintain_different_contact_details_to_security_billing_and_operations": (
        _alternate_contacts
    ),
    "ec2_ebs_default_encryption": _ebs_default_encryption,
    "s3_bucket_object_versioning": _s3_object_versioning,
    "guardduty_is_enabled": _guardduty_enabled,
    "guardduty_no_high_severity_findings": _guardduty_high_severity,
    "ec2_instance_older_than_specific_days": _ec2_instance_age,
    "kms_cmk_rotation_enabled": _kms_rotation,
    "kms_key_enclave_attestation_bypassable_path": _kms_enclave_attestation,
    "kms_key_enclave_attestation_not_enforced": _kms_enclave_attestation,
    "kms_key_enclave_attestation_pcr_mismatch": _kms_enclave_attestation,
    "kms_key_enclave_attestation_unknown_image": _kms_enclave_attestation,
    "kms_key_enclave_debug_attestation_detected": _kms_enclave_attestation,
    "iam_password_policy_lowercase": _iam_password_policy,
    "iam_password_policy_minimum_length_14": _iam_password_policy,
    "iam_password_policy_number": _iam_password_policy,
    "iam_password_policy_reuse_24": _iam_password_policy,
    "iam_password_policy_symbol": _iam_password_policy,
    "iam_password_policy_uppercase": _iam_password_policy,
    **S3_BUILDERS,
    **CLOUDTRAIL_BUILDERS,
    **DYNAMODB_BUILDERS,
    **EC2_BUILDERS,
    **EFS_BUILDERS,
    **RDS_BUILDERS,
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
