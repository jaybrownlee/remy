"""Reviewed recommendation builders for pinned S3 checks."""

# The guidance remains readable as complete prose in source.
# ruff: noqa: E501

import json
from collections.abc import Callable

from remy.recommendations.identifiers import bucket_name
from remy.reports.schema import Citation, Observation, Recommendation

_ECFR_308 = (
    "https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/"
    "subpart-C/section-164.308"
)
_ECFR_312 = (
    "https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/"
    "subpart-C/section-164.312"
)
_AWS_DEFAULT_ENCRYPTION = (
    "https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html"
)
_AWS_PUBLIC_ACCESS = (
    "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
)
_AWS_SECURE_TRANSPORT = (
    "https://docs.aws.amazon.com/AmazonS3/latest/userguide/amazon-s3-policy-keys.html"
)
_AWS_SERVER_LOGGING = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html"
_TF_DEFAULT_ENCRYPTION = (
    "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/"
    "s3_bucket_server_side_encryption_configuration"
)
_TF_SERVER_LOGGING = (
    "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_logging"
)


def _citation(section: str, title: str, url: str = _ECFR_312) -> Citation:
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


def _string_variable(name: str, description: str, default: str | None = None) -> str:
    default_line = "" if default is None else f"  default     = {json.dumps(default)}\n"
    return (
        f'variable "{name}" {{\n'
        f"  description = {json.dumps(description)}\n"
        "  type        = string\n"
        f"{default_line}"
        "}\n"
    )


def _bucket_input(observation: Observation, purpose: str) -> tuple[str, str]:
    name = bucket_name(observation)
    variable = _string_variable("bucket_name", purpose, name)
    assumption = (
        f"The bucket input default came from the validated observation value {name!r}."
        if name
        else "The observation did not contain a valid general-purpose S3 bucket name; set bucket_name explicitly."
    )
    return variable, assumption


def default_encryption(observation: Observation) -> Recommendation:
    bucket_variable, bucket_assumption = _bucket_input(
        observation, "Existing general-purpose S3 bucket whose default encryption is managed"
    )
    terraform = (
        "# Suggested Terraform — review and adapt before applying.\n"
        + bucket_variable
        + "\n"
        + 'variable "sse_algorithm" {\n'
        + '  description = "Approved default: AES256 or aws:kms"\n'
        + "  type        = string\n\n"
        + "  validation {\n"
        + '    condition     = contains(["AES256", "aws:kms"], var.sse_algorithm)\n'
        + '    error_message = "Use AES256 or aws:kms."\n'
        + "  }\n"
        + "}\n\n"
        + 'variable "kms_key_arn" {\n'
        + '  description = "Approved KMS key ARN for aws:kms; leave null for AES256"\n'
        + "  type        = string\n"
        + "  default     = null\n"
        + "  nullable    = true\n"
        + "}\n\n"
        + 'variable "bucket_key_enabled" {\n'
        + '  description = "Whether to use an S3 Bucket Key with aws:kms"\n'
        + "  type        = bool\n"
        + "}\n\n"
        + 'resource "aws_s3_bucket_server_side_encryption_configuration" "recommended" {\n'
        + "  bucket = var.bucket_name\n\n"
        + "  rule {\n"
        + '    bucket_key_enabled = var.sse_algorithm == "aws:kms" ? var.bucket_key_enabled : null\n\n'
        + "    apply_server_side_encryption_by_default {\n"
        + "      sse_algorithm     = var.sse_algorithm\n"
        + '      kms_master_key_id = var.sse_algorithm == "aws:kms" ? var.kms_key_arn : null\n'
        + "    }\n"
        + "  }\n"
        + "}\n"
    )
    return Recommendation(
        status="needs_context",
        what="Prowler did not observe an explicit default server-side encryption configuration for this S3 bucket.",
        why=(
            "A bucket-level default makes the intended encryption mode and, for SSE-KMS, key ownership explicit for new object writes. It does not prove that existing object versions use that mode."
        ),
        change=(
            "Choose the approved default encryption mode. Use AES256 for S3-managed keys or supply a confirmed KMS key ARN and bucket-key decision for aws:kms, then manage the existing bucket's encryption configuration."
        ),
        impact=(
            "SSE-KMS adds KMS permissions, quota, policy, availability, and cost dependencies. A wrong or disabled key can block reads and writes. Changing the default affects new writes only; existing object versions require a separate inventory and migration decision."
        ),
        citations=[_citation("45 CFR 164.312(a)(2)(iv)", "Encryption and decryption")],
        terraform=terraform,
        filename="s3_bucket_default_encryption.tf",
        assumptions=[
            bucket_assumption,
            "The encryption algorithm, KMS key, bucket-key preference, existing object encryption, replication, application headers, and Terraform state ownership were not inferred.",
            "The KMS key input deliberately has no generated ARN; use a key in the correct Region with reviewed key and IAM policies.",
        ],
        steps=[
            "Confirm the bucket owner, Region, data classification, application encryption headers, replication, inventory, and current Terraform ownership.",
            "Choose AES256 or an approved customer-managed KMS key. For KMS, review key policy, IAM permissions, grants, quotas, cost, disaster recovery, and bucket-key behavior.",
            "If this encryption configuration is already managed, update it there. Import an existing configuration only after confirming the workspace owns the full setting.",
            "Plan and test representative writes, reads, copies, replication, and service integrations before applying through the customer's process.",
            "Inventory existing object versions separately, then rerun the Prowler check after the default configuration is effective.",
            f"AWS default encryption reference: {_AWS_DEFAULT_ENCRYPTION}",
            f"Terraform resource reference: {_TF_DEFAULT_ENCRYPTION}",
        ],
    )


def public_access(observation: Observation) -> Recommendation:
    name = bucket_name(observation)
    target = name if name else "the reported bucket"
    return Recommendation(
        status="needs_context",
        what=(
            f"Prowler classified {target} as public through an ACL or bucket policy while effective account and bucket public-access-block settings did not suppress that access."
        ),
        why=(
            "Public access can expose objects or bucket operations beyond intended principals. The finding does not show whether public delivery is deliberate or which individual policy or ACL grant should change."
        ),
        change=(
            "Confirm the intended delivery design and effective access. For a private bucket, remove public ACL and policy grants and enable appropriate bucket and account Block Public Access controls. For intentional public delivery, document scope and prefer a controlled delivery layer such as CloudFront where applicable."
        ),
        impact=(
            "Removing public grants or enabling Block Public Access can stop websites, downloads, cross-account integrations, or CloudFront origins that still rely on public bucket access. Account-level controls can affect every bucket."
        ),
        citations=[_citation("45 CFR 164.312(a)(1)", "Access control")],
        terraform=None,
        filename=None,
        assumptions=[
            "The report does not retain the full bucket policy, ACL, access-point policies, organization controls, website configuration, CloudFront origin design, or access logs.",
            "Public classification does not establish that protected data is present or that a disclosure occurred.",
            "No bucket policy is generated because replacing an unknown policy can remove required access or introduce a lockout.",
        ],
        steps=[
            "Confirm the bucket owner, data classification, intended public or cross-account delivery, website configuration, CloudFront origin access, access points, ACLs, and effective policies.",
            "For private use, remove public grants and enable reviewed bucket- and account-level Block Public Access settings in their owning configurations.",
            "For intentional public use, minimize exposed prefixes and actions, separate public from nonpublic data, and document monitoring and approval.",
            "Test every required consumer, apply through the customer's process, verify effective access with authorized tooling, and rerun the Prowler checks.",
            f"AWS S3 Block Public Access reference: {_AWS_PUBLIC_ACCESS}",
        ],
    )


def public_write_policy(observation: Observation) -> Recommendation:
    result = public_access(observation)
    result.what = "Prowler found a bucket-policy authorization path for public object writes or deletes, and effective account or bucket restrictions did not suppress it."
    result.why = "Public write or delete permission can allow unauthorized content changes, malware placement, destruction, or storage charges. The finding does not prove that the permission was exercised."
    result.change = "Identify the exact public statement and remove public PutObject, DeleteObject, s3:*, Put*, or Delete* authorization. Replace it only with the specific trusted principals, actions, resources, and conditions required by the workload."
    result.impact = "Removing the statement can break anonymous uploads or external publishers. Preserve legitimate ingestion through authenticated, narrowly scoped identities or presigned requests, and review object ownership and existing untrusted content."
    result.steps.insert(
        1,
        "Investigate recent writes and deletes, object ownership, version history, and downstream processing before treating the issue as configuration-only.",
    )
    return result


def secure_transport(observation: Observation) -> Recommendation:
    name = bucket_name(observation)
    target = name if name else "the reported bucket"
    return Recommendation(
        status="needs_context",
        what=(
            f"Prowler did not find a bucket-policy deny that covers insecure transport for object writes to {target}."
        ),
        why=(
            "An explicit aws:SecureTransport deny prevents covered S3 requests over HTTP even when another identity or resource policy would otherwise allow them."
        ),
        change=(
            "Merge a deny statement into the existing bucket policy for requests where aws:SecureTransport is false, covering the bucket and object ARNs and the actions required by the reviewed control. Preserve all legitimate existing statements."
        ),
        impact=(
            "HTTP clients will fail after the deny is active. Replacing rather than merging the existing policy can break delivery services, replication, logging, cross-account access, or administrative recovery."
        ),
        citations=[_citation("45 CFR 164.312(e)(1)", "Transmission security")],
        terraform=None,
        filename=None,
        assumptions=[
            "The complete current bucket policy, access points, clients, service integrations, ownership controls, and Terraform state were not available.",
            "No aws_s3_bucket_policy resource is emitted because it would take ownership of and replace an unknown complete policy.",
            "The pinned Prowler check specifically looks for a qualifying deny with aws:SecureTransport=false and PutObject, s3:*, or wildcard action coverage.",
        ],
        steps=[
            "Retrieve the complete current policy through an authorized path and identify its owning configuration and every service integration.",
            "Draft the secure-transport deny using the exact bucket and object ARNs, merge it with existing statements, and validate the complete policy.",
            "Test HTTPS clients and confirm expected HTTP denial in a safe environment, then deploy through the owning configuration.",
            "Monitor denied requests, repair obsolete clients without weakening the policy, and rerun the Prowler check.",
            f"AWS S3 policy-key reference: {_AWS_SECURE_TRANSPORT}",
        ],
    )


def server_access_logging(observation: Observation) -> Recommendation:
    bucket_variable, bucket_assumption = _bucket_input(
        observation, "Existing general-purpose S3 source bucket whose access logging is managed"
    )
    terraform = (
        "# Suggested Terraform — review and adapt before applying.\n"
        + bucket_variable
        + "\n"
        + _string_variable(
            "logging_target_bucket", "Existing S3 bucket approved to receive server access logs"
        )
        + "\n"
        + _string_variable(
            "logging_target_prefix", "Approved prefix for this source bucket's access logs"
        )
        + "\n"
        + 'resource "aws_s3_bucket_logging" "recommended" {\n'
        + "  bucket        = var.bucket_name\n"
        + "  target_bucket = var.logging_target_bucket\n"
        + "  target_prefix = var.logging_target_prefix\n"
        + "}\n"
    )
    return Recommendation(
        status="needs_context",
        what="Prowler observed that S3 server access logging is not enabled for this bucket.",
        why=(
            "Server access logs can support request investigation and usage analysis. They are delivered on a best-effort basis and are not a complete or real-time audit source."
        ),
        change=(
            "Choose an existing, protected destination bucket and unique prefix, grant the S3 logging service the required destination permission, and manage logging for the source bucket."
        ),
        impact=(
            "Logging creates additional objects, storage and lifecycle cost, and potentially sensitive request metadata. A wrong destination policy prevents delivery. Logging a destination bucket to itself creates recursive logs and must be avoided."
        ),
        citations=[_citation("45 CFR 164.312(b)", "Audit controls")],
        terraform=terraform,
        filename="s3_bucket_server_access_logging.tf",
        assumptions=[
            bucket_assumption,
            "The destination bucket and prefix are required inputs with no generated defaults.",
            "Destination Region, ownership, policy, Object Ownership mode, encryption, lifecycle, log-analysis path, and Terraform state were not inferred.",
        ],
        steps=[
            "Select a destination bucket in the same Region and account where appropriate; do not configure the destination bucket to log to itself.",
            "Review destination ownership, Block Public Access, encryption, retention, lifecycle, access, and the required logging-service bucket policy.",
            "Use a unique prefix for the source bucket and verify downstream tooling can distinguish sources and protect request metadata.",
            "Update or import the existing logging configuration only in its owning workspace, plan, apply, and verify delivery after the documented best-effort delay.",
            "Retain CloudTrail data events or other controls separately when durable API-level audit coverage is required, then rerun the Prowler check.",
            f"AWS server access logging reference: {_AWS_SERVER_LOGGING}",
            f"Terraform resource reference: {_TF_SERVER_LOGGING}",
        ],
    )


S3_BUILDERS: dict[str, Callable[[Observation], Recommendation]] = {
    "s3_bucket_default_encryption": default_encryption,
    "s3_bucket_policy_public_write_access": public_write_policy,
    "s3_bucket_public_access": public_access,
    "s3_bucket_secure_transport_policy": secure_transport,
    "s3_bucket_server_access_logging_enabled": server_access_logging,
}
