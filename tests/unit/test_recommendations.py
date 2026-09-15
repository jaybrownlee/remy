from datetime import UTC, datetime

import pytest

from remy.recommendations.catalog import SUPPORTED_CHECK_IDS, recommend
from remy.reports.schema import Observation


def observation(
    check_id: str,
    *,
    resource_name: str = "example-audit-bucket",
    resource_uid: str = "arn:aws:s3:::example-audit-bucket",
    account_id: str = "123456789012",
    service: str = "s3",
) -> Observation:
    return Observation(
        account_id=account_id,
        check_id=check_id,
        resource_uid=resource_uid,
        resource_name=resource_name,
        service=service,
        region="us-east-1",
        status="FAIL",
        severity="high",
        title="Representative failed check",
        detail="The scanner observed a failed configuration check.",
        observed_at=datetime(2026, 9, 14, tzinfo=UTC),
    )


def test_supported_check_ids_are_the_reviewed_bounded_catalog() -> None:
    assert {
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
        "s3_bucket_default_encryption",
        "s3_bucket_policy_public_write_access",
        "s3_bucket_public_access",
        "s3_bucket_secure_transport_policy",
        "s3_bucket_server_access_logging_enabled",
        "cloudtrail_bedrock_logging_enabled",
        "cloudtrail_cloudwatch_logging_enabled",
        "cloudtrail_kms_encryption_enabled",
        "cloudtrail_log_file_validation_enabled",
        "cloudtrail_s3_dataevents_read_enabled",
        "cloudtrail_s3_dataevents_write_enabled",
        "dynamodb_accelerator_cluster_encryption_enabled",
        "dynamodb_tables_kms_cmk_encryption_enabled",
        "dynamodb_tables_pitr_enabled",
        "opensearch_service_domains_encryption_at_rest_enabled",
        "opensearch_service_domains_node_to_node_encryption_enabled",
        "ec2_ebs_public_snapshot",
        "ec2_ebs_volume_encryption",
        "ec2_instance_managed_by_ssm",
        "ec2_instance_public_ip",
        "efs_encryption_at_rest_enabled",
        "efs_have_backup_enabled",
        "rds_instance_backup_enabled",
        "rds_instance_integration_cloudwatch_logs",
        "rds_instance_multi_az",
        "rds_instance_no_public_access",
        "rds_instance_storage_encrypted",
        "rds_snapshots_public_access",
        "iam_password_policy_lowercase",
        "iam_password_policy_minimum_length_14",
        "iam_password_policy_number",
        "iam_password_policy_reuse_24",
        "iam_password_policy_symbol",
        "iam_password_policy_uppercase",
    } == SUPPORTED_CHECK_IDS


def test_unknown_check_is_visible_and_actionable_without_guessed_code() -> None:
    result = recommend(observation("new_service_unreviewed_check"))

    assert result.status == "unsupported"
    assert result.terraform is None
    assert result.filename is None
    assert "no reviewed recommendation" in result.what
    assert "new_service_unreviewed_check" in result.what
    assert any(
        "hub.prowler.com/check/new_service_unreviewed_check" in step for step in result.steps
    )
    assert result.change and result.impact and result.assumptions


@pytest.mark.parametrize(
    ("resource_name", "resource_uid", "hostile_fragment"),
    [
        (
            'safe-bucket"\n}\nresource "aws_iam_user" "injected" {',
            'arn:aws:s3:::also-bad"\noutput "secret" { value = 1 }',
            "aws_iam_user",
        ),
        ("192.168.0.1", "not-an-arn", "192.168.0.1"),
    ],
)
def test_s3_bucket_name_cannot_inject_hcl(
    resource_name: str, resource_uid: str, hostile_fragment: str
) -> None:
    result = recommend(
        observation(
            "s3_bucket_level_public_access_block",
            resource_name=resource_name,
            resource_uid=resource_uid,
        )
    )

    assert result.status == "needs_context"
    assert result.terraform is not None
    assert hostile_fragment not in result.terraform
    assert 'variable "bucket_name"' in result.terraform
    assert "default" not in result.terraform
    assert any("set bucket_name explicitly" in assumption for assumption in result.assumptions)


def test_s3_bucket_guidance_uses_validated_default_and_all_four_flags() -> None:
    result = recommend(observation("s3_bucket_level_public_access_block"))

    assert result.status == "needs_context"
    assert result.filename == "s3_bucket_public_access_block.tf"
    assert result.terraform is not None
    assert 'default     = "example-audit-bucket"' in result.terraform
    for flag in (
        "block_public_acls",
        "block_public_policy",
        "ignore_public_acls",
        "restrict_public_buckets",
    ):
        assert f"{flag}" in result.terraform
    assert 'aws_s3_bucket"' not in result.terraform
    assert "CloudFront" in result.impact
    assert any("already managed" in step for step in result.steps)
    assert any("import" in step for step in result.steps)
    assert result.citations[0].section == "45 CFR 164.312(a)(1)"
    assert "does not establish HIPAA noncompliance" in result.citations[0].note


def test_s3_bucket_can_use_valid_name_from_resource_arn() -> None:
    result = recommend(
        observation(
            "s3_bucket_level_public_access_block",
            resource_name="not a bucket name",
            resource_uid="arn:aws:s3:::arn-derived-bucket",
        )
    )

    assert result.terraform is not None
    assert 'default     = "arn-derived-bucket"' in result.terraform


def test_account_public_access_guidance_preserves_account_wide_caveat() -> None:
    result = recommend(observation("s3_account_level_public_access_blocks"))

    assert result.status == "needs_context"
    assert result.terraform is not None
    assert 'resource "aws_s3_account_public_access_block" "recommended"' in result.terraform
    assert 'default     = "123456789012"' in result.terraform
    assert "account-wide" in result.impact
    assert "every AWS Region" in " ".join(result.assumptions)


def test_invalid_account_id_is_not_rendered_as_a_default() -> None:
    hostile = '123"\nresource "aws_iam_role" "injected" {'
    result = recommend(observation("s3_account_level_public_access_blocks", account_id=hostile))

    assert result.terraform is not None
    assert hostile not in result.terraform
    assert "default" not in result.terraform


def test_cloudtrail_guidance_requires_destination_and_calls_out_dependencies() -> None:
    result = recommend(
        observation(
            "cloudtrail_multi_region_enabled",
            resource_name="central-audit-trail",
            resource_uid=("arn:aws:cloudtrail:us-east-1:123456789012:trail/central-audit-trail"),
            service="cloudtrail",
        )
    )

    assert result.status == "needs_context"
    assert result.terraform is not None
    assert 'resource "aws_cloudtrail" "recommended"' in result.terraform
    assert 'default     = "central-audit-trail"' in result.terraform
    assert 'variable "cloudtrail_s3_bucket_name"' in result.terraform
    destination_block = result.terraform.split('variable "cloudtrail_s3_bucket_name"', maxsplit=1)[
        1
    ].split("}", maxsplit=1)[0]
    assert "default" not in destination_block
    assert "enable_logging                = true" in result.terraform
    assert "is_multi_region_trail         = true" in result.terraform
    context = " ".join(result.assumptions + result.steps)
    for dependency in ("Bucket policy", "KMS", "account", "Region", "Terraform state"):
        assert dependency.lower() in context.lower()
    assert result.citations[0].section == "45 CFR 164.312(b)"


def test_cloudtrail_can_use_valid_name_from_resource_arn() -> None:
    result = recommend(
        observation(
            "cloudtrail_multi_region_enabled",
            resource_name="not a valid trail name",
            resource_uid="arn:aws:cloudtrail:us-east-1:123456789012:trail/audit-trail",
            service="cloudtrail",
        )
    )

    assert result.terraform is not None
    assert 'default     = "audit-trail"' in result.terraform


def test_root_mfa_is_manual_and_never_emits_code() -> None:
    result = recommend(
        observation(
            "iam_root_mfa_enabled",
            resource_name="root",
            resource_uid="arn:aws:iam::123456789012:root",
            service="iam",
        )
    )

    assert result.status == "manual_action"
    assert result.terraform is None
    assert result.filename is None
    assert "MFA" in result.change
    assert any("Organizations" in step for step in result.steps)
    assert any("docs.aws.amazon.com/IAM" in step for step in result.steps)
    assert result.citations[0].section == "45 CFR 164.312(d)"


@pytest.mark.parametrize(
    ("check_id", "expected_text"),
    [
        ("iam_no_root_access_key", "cannot be recovered"),
        ("iam_root_hardware_mfa_enabled", "credential ceremony"),
        ("iam_user_mfa_enabled_console_access", "MFA seeds"),
    ],
)
def test_identity_credential_ceremonies_are_manual_without_secrets(
    check_id: str, expected_text: str
) -> None:
    result = recommend(
        observation(
            check_id,
            resource_name="identity",
            resource_uid="arn:aws:iam::123456789012:user/example",
            service="iam",
        )
    )

    assert result.status == "manual_action"
    assert result.terraform is None
    assert result.filename is None
    content = " ".join([result.what, result.why, result.change, result.impact, *result.assumptions])
    assert expected_text in content
    assert result.steps


def test_root_access_key_guidance_requires_dependency_migration_before_deletion() -> None:
    result = recommend(observation("iam_no_root_access_key", service="iam"))

    assert "least-privilege" in result.change
    assert "immediately breaks" in result.impact
    assert any("deactivate" in step and "delete" in step for step in result.steps)
    assert any("does not collect" in item for item in result.assumptions)


def test_iam_user_mfa_guidance_distinguishes_console_and_other_access() -> None:
    result = recommend(observation("iam_user_mfa_enabled_console_access", service="iam"))

    assert "Remove the login profile" in result.change
    assert "does not remove access keys" in result.impact
    assert any("federation or IAM Identity Center" in step for step in result.steps)


@pytest.mark.parametrize(
    "check_id",
    ["iam_rotate_access_key_90_days", "iam_user_accesskey_unused"],
)
def test_access_key_lifecycle_guidance_never_generates_credentials(check_id: str) -> None:
    result = recommend(observation(check_id, service="iam"))

    assert result.status == "manual_action"
    assert result.terraform is None
    assert result.filename is None
    assert "temporary-credential" in result.change
    assert "Terraform state" in result.impact
    assert any("Deactivate" in step for step in result.steps)
    assert any("does not generate" in item for item in result.assumptions)


def test_unused_console_guidance_separates_login_profile_from_other_credentials() -> None:
    result = recommend(observation("iam_user_console_access_unused", service="iam"))

    assert result.status == "manual_action"
    assert result.terraform is None
    assert "Remove the IAM login profile" in result.change
    assert "does not revoke access keys" in result.impact
    assert any("inactivity threshold" in item for item in result.assumptions)


@pytest.mark.parametrize(
    "check_id",
    [
        "iam_aws_attached_policy_no_administrative_privileges",
        "iam_customer_attached_policy_no_administrative_privileges",
        "iam_inline_policy_no_administrative_privileges",
    ],
)
def test_administrative_policy_guidance_requires_effective_access_context(
    check_id: str,
) -> None:
    result = recommend(observation(check_id, service="iam"))

    assert result.status == "needs_context"
    assert result.terraform is None
    assert result.filename is None
    assert "least-privilege replacement" in result.change
    assert "Organizations controls" in result.impact
    assert any("Policy JSON" in item for item in result.assumptions)
    assert any("IAM Access Analyzer" in step for step in result.steps)


@pytest.mark.parametrize(
    "check_id",
    [
        "iam_inline_policy_no_wildcard_marketplace_subscribe",
        "iam_policy_no_wildcard_marketplace_subscribe",
    ],
)
def test_marketplace_subscribe_guidance_does_not_invent_resource_scoping(
    check_id: str,
) -> None:
    result = recommend(observation(check_id, service="iam"))

    assert result.status == "needs_context"
    assert result.terraform is None
    assert result.filename is None
    assert "does not currently define a resource type" in result.what
    assert "do not invent a resource ARN" in result.change
    assert any("no resource type" in item for item in result.assumptions)


def test_guardduty_finding_requires_incident_triage_not_infrastructure_code() -> None:
    result = recommend(observation("guardduty_no_high_severity_findings", service="guardduty"))

    assert result.status == "manual_action"
    assert result.terraform is None
    assert "security signal" in result.why
    assert "does not remediate" in result.impact
    assert any("Preserve" in step for step in result.steps)


def test_instance_age_does_not_authorize_replacement() -> None:
    result = recommend(observation("ec2_instance_older_than_specific_days", service="ec2"))

    assert result.status == "needs_context"
    assert result.terraform is None
    assert "age alone does not prove" in result.why
    assert "data loss" in result.impact
    assert any("No stop, terminate" in item for item in result.assumptions)


def test_kms_rotation_requires_ownership_of_existing_key() -> None:
    result = recommend(observation("kms_cmk_rotation_enabled", service="kms"))

    assert result.status == "needs_context"
    assert result.terraform is None
    assert "existing key" in result.change
    assert "multi-Region" in result.impact
    assert any("No complete aws_kms_key block" in item for item in result.assumptions)


@pytest.mark.parametrize(
    "check_id",
    [
        "kms_key_enclave_attestation_bypassable_path",
        "kms_key_enclave_attestation_not_enforced",
        "kms_key_enclave_attestation_pcr_mismatch",
    ],
)
def test_enclave_policy_findings_require_customer_measurements_and_full_policy(
    check_id: str,
) -> None:
    result = recommend(observation(check_id, service="kms"))

    assert result.status == "needs_context"
    assert result.terraform is None
    assert "complete owning KMS policy" in result.change
    assert "unmanageable" in result.impact
    assert any("No policy JSON or PCR value" in item for item in result.assumptions)


@pytest.mark.parametrize(
    "check_id",
    [
        "kms_key_enclave_attestation_unknown_image",
        "kms_key_enclave_debug_attestation_detected",
    ],
)
def test_enclave_runtime_findings_require_incident_response(check_id: str) -> None:
    result = recommend(observation(check_id, service="kms"))

    assert result.status == "manual_action"
    assert result.terraform is None
    assert "security signals" in result.change
    assert any("contain unapproved or debug workloads" in step for step in result.steps)


def test_s3_default_encryption_requires_algorithm_and_key_decisions() -> None:
    result = recommend(observation("s3_bucket_default_encryption"))

    assert result.status == "needs_context"
    assert result.terraform is not None
    assert 'resource "aws_s3_bucket_server_side_encryption_configuration"' in result.terraform
    assert 'default     = "example-audit-bucket"' in result.terraform
    assert 'contains(["AES256", "aws:kms"], var.sse_algorithm)' in result.terraform
    algorithm = result.terraform.split('variable "sse_algorithm"', 1)[1].split("}", 1)[0]
    assert "  default     =" not in algorithm
    assert "does not prove" in result.why
    assert "existing object versions" in result.impact
    assert any("no generated ARN" in item for item in result.assumptions)


@pytest.mark.parametrize(
    "check_id",
    [
        "s3_bucket_policy_public_write_access",
        "s3_bucket_public_access",
        "s3_bucket_secure_transport_policy",
    ],
)
def test_s3_policy_and_public_access_findings_do_not_replace_unknown_policy(
    check_id: str,
) -> None:
    result = recommend(observation(check_id))

    assert result.status == "needs_context"
    assert result.terraform is None
    assert result.filename is None
    context = " ".join(result.assumptions + result.steps)
    assert "policy" in context.lower()
    assert "own" in context.lower()


def test_s3_public_write_guidance_requires_investigation_and_authenticated_replacement() -> None:
    result = recommend(observation("s3_bucket_policy_public_write_access"))

    assert "writes or deletes" in result.what
    assert "authenticated" in result.impact
    assert any("Investigate recent writes and deletes" in step for step in result.steps)


def test_s3_logging_requires_explicit_destination_without_recursive_logging() -> None:
    result = recommend(observation("s3_bucket_server_access_logging_enabled"))

    assert result.status == "needs_context"
    assert result.terraform is not None
    assert 'resource "aws_s3_bucket_logging" "recommended"' in result.terraform
    for name in ("logging_target_bucket", "logging_target_prefix"):
        block = result.terraform.split(f'variable "{name}"', 1)[1].split("}", 1)[0]
        assert "default" not in block
    assert "recursive" in result.impact
    assert "best-effort" in result.why


@pytest.mark.parametrize(
    "check_id",
    [
        "cloudtrail_bedrock_logging_enabled",
        "cloudtrail_cloudwatch_logging_enabled",
        "cloudtrail_kms_encryption_enabled",
        "cloudtrail_log_file_validation_enabled",
        "cloudtrail_s3_dataevents_read_enabled",
        "cloudtrail_s3_dataevents_write_enabled",
    ],
)
def test_cloudtrail_changes_require_complete_trail_reconciliation(check_id: str) -> None:
    result = recommend(observation(check_id, service="cloudtrail"))

    assert result.status == "needs_context"
    assert result.terraform is None
    assert result.filename is None
    assert any("reconciled" in item for item in result.assumptions)
    assert any("complete current trail" in step for step in result.steps)


def test_cloudtrail_cloudwatch_check_does_not_claim_s3_delivery_health() -> None:
    result = recommend(observation("cloudtrail_cloudwatch_logging_enabled", service="cloudtrail"))

    assert "does not by itself establish" in result.why
    assert "lack of recent qualifying events" in " ".join(result.assumptions)


@pytest.mark.parametrize(
    "check_id",
    ["cloudtrail_s3_dataevents_read_enabled", "cloudtrail_s3_dataevents_write_enabled"],
)
def test_cloudtrail_advanced_s3_selector_limit_is_visible(check_id: str) -> None:
    result = recommend(observation(check_id, service="cloudtrail"))

    caveats = " ".join(result.assumptions)
    assert "does not fully establish readOnly direction" in caveats
    assert "unused-service scanning" in caveats


def test_hostile_cloudtrail_name_is_not_interpolated() -> None:
    hostile = 'trail"\nresource "aws_s3_bucket" "injected" {'
    result = recommend(
        observation(
            "cloudtrail_multi_region_enabled",
            resource_name=hostile,
            resource_uid="not-an-arn",
            service="cloudtrail",
        )
    )

    assert result.terraform is not None
    assert hostile not in result.terraform
    trail_block = result.terraform.split('variable "trail_name"', maxsplit=1)[1].split(
        "}", maxsplit=1
    )[0]
    assert "default" not in trail_block


def test_access_analyzer_uses_account_scope_with_region_context() -> None:
    result = recommend(
        observation(
            "accessanalyzer_enabled",
            resource_name="Access Analyzer",
            resource_uid="accessanalyzer",
            service="accessanalyzer",
        )
    )

    assert result.status == "needs_context"
    assert result.terraform is not None
    assert 'resource "aws_accessanalyzer_analyzer" "recommended"' in result.terraform
    assert 'type          = "ACCOUNT"' in result.terraform
    assert 'variable "access_analyzer_name"' in result.terraform
    assert "default" not in result.terraform
    context = " ".join(result.assumptions + result.steps)
    assert "Region" in context
    assert "Organization" in context
    assert "service-linked role" in result.impact


def test_alternate_contacts_require_explicit_distinct_contact_inputs() -> None:
    result = recommend(
        observation(
            "account_maintain_different_contact_details_to_security_billing_and_operations",
            resource_name="AWS Account",
            resource_uid="123456789012",
            service="account",
        )
    )

    assert result.status == "needs_context"
    assert result.terraform is not None
    assert 'resource "aws_account_alternate_contact" "recommended"' in result.terraform
    assert 'variable "alternate_contacts"' in result.terraform
    assert "BILLING" in result.terraform
    assert "OPERATIONS" in result.terraform
    assert "SECURITY" in result.terraform
    assert "example.com" not in result.terraform
    assert "values(var.alternate_contacts)" in result.terraform
    assert any("primary account contact" in item for item in result.assumptions)
    assert result.citations[0].section == "45 CFR 164.308(a)(6)(ii)"


def test_ebs_default_encryption_is_region_scoped_and_does_not_invent_a_key() -> None:
    result = recommend(
        observation(
            "ec2_ebs_default_encryption",
            resource_name="123456789012",
            resource_uid="arn:aws:ec2:us-east-1:123456789012:volume/*",
            service="ec2",
        )
    )

    assert result.status == "needs_context"
    assert result.terraform is not None
    assert 'resource "aws_ebs_encryption_by_default" "recommended"' in result.terraform
    assert 'default     = "us-east-1"' in result.terraform
    assert "enabled = true" in result.terraform
    assert "kms_key" not in result.terraform
    assert "does not encrypt existing" in result.why
    assert "removing this Terraform resource disables" in result.impact
    assert result.citations[0].section == "45 CFR 164.312(a)(2)(iv)"


def test_invalid_region_is_not_rendered_into_ebs_guidance() -> None:
    hostile = 'us-east-1"\nresource "aws_iam_user" "injected" {'
    source = observation("ec2_ebs_default_encryption", service="ec2")
    source.region = hostile

    result = recommend(source)

    assert result.terraform is not None
    assert hostile not in result.terraform
    region_block = result.terraform.split('variable "aws_region"', maxsplit=1)[1].split(
        "}", maxsplit=1
    )[0]
    assert "  default     =" not in region_block


def test_s3_object_versioning_targets_existing_bucket_and_explains_retention() -> None:
    result = recommend(observation("s3_bucket_object_versioning"))

    assert result.status == "needs_context"
    assert result.terraform is not None
    assert result.filename == "s3_bucket_versioning.tf"
    assert 'resource "aws_s3_bucket_versioning" "recommended"' in result.terraform
    assert 'default     = "example-audit-bucket"' in result.terraform
    assert 'status = "Enabled"' in result.terraform
    assert 'resource "aws_s3_bucket"' not in result.terraform
    assert "15 minutes" in result.impact
    assert "lifecycle" in (result.impact + " " + " ".join(result.steps)).lower()
    assert "not a complete backup plan" in result.why
    assert result.citations[0].section == "45 CFR 164.308(a)(7)(ii)(A)"


def test_s3_versioning_rejects_hostile_bucket_default() -> None:
    hostile = 'bucket"\nresource "aws_iam_role" "injected" {'
    result = recommend(
        observation(
            "s3_bucket_object_versioning",
            resource_name=hostile,
            resource_uid="not-an-arn",
        )
    )

    assert result.terraform is not None
    assert hostile not in result.terraform
    assert "default" not in result.terraform


def test_guardduty_guidance_is_minimal_regional_and_preserves_ownership_context() -> None:
    result = recommend(
        observation(
            "guardduty_is_enabled",
            resource_name="GuardDuty",
            resource_uid="arn:aws:guardduty:us-east-1:123456789012:detector/unknown",
            service="guardduty",
        )
    )

    assert result.status == "needs_context"
    assert result.terraform is not None
    assert 'resource "aws_guardduty_detector" "recommended"' in result.terraform
    assert 'default     = "us-east-1"' in result.terraform
    assert "enable = true" in result.terraform
    assert "datasources" not in result.terraform
    assert "feature" not in result.terraform
    context = " ".join(result.assumptions + result.steps)
    assert "Organizations" in context
    assert "suspended" in result.what
    assert "removes existing findings" in result.impact
    assert result.citations[0].section == "45 CFR 164.308(a)(1)(ii)(D)"


@pytest.mark.parametrize(
    "check_id",
    [
        "iam_password_policy_lowercase",
        "iam_password_policy_minimum_length_14",
        "iam_password_policy_number",
        "iam_password_policy_reuse_24",
        "iam_password_policy_symbol",
        "iam_password_policy_uppercase",
    ],
)
def test_iam_password_policy_checks_share_one_complete_account_baseline(check_id: str) -> None:
    result = recommend(
        observation(
            check_id,
            resource_name="123456789012",
            resource_uid="arn:aws:iam::123456789012:password-policy",
            service="iam",
        )
    )

    assert result.status == "needs_context"
    assert result.filename == "iam_account_password_policy.tf"
    assert result.terraform is not None
    assert 'resource "aws_iam_account_password_policy" "recommended"' in result.terraform
    for setting in (
        "minimum_password_length        = 14",
        "password_reuse_prevention      = 24",
        "require_lowercase_characters   = true",
        "require_numbers                = true",
        "require_symbols                = true",
        "require_uppercase_characters   = true",
    ):
        assert setting in result.terraform
    for required_input in (
        "allow_users_to_change_password",
        "hard_expiry",
        "max_password_age",
    ):
        block = result.terraform.split(f'variable "{required_input}"', maxsplit=1)[1].split(
            "}", maxsplit=1
        )[0]
        assert "default" not in block
    assert "single IAM password policy" in result.change
    assert "does not govern the root user" in result.why
    assert "nonzero maximum age applies immediately" in result.impact
    assert any("not a claim that HIPAA prescribes" in item for item in result.assumptions)


@pytest.mark.parametrize(
    "check_id",
    [
        "rds_instance_backup_enabled",
        "rds_instance_integration_cloudwatch_logs",
        "rds_instance_multi_az",
        "rds_instance_no_public_access",
        "rds_instance_storage_encrypted",
    ],
)
def test_rds_instance_guidance_does_not_emit_incomplete_stateful_resources(
    check_id: str,
) -> None:
    result = recommend(
        observation(
            check_id,
            resource_name="patient-db",
            resource_uid="arn:aws:rds:us-east-1:123456789012:db:patient-db",
            service="rds",
        )
    )

    assert result.status == "needs_context"
    assert result.terraform is None
    assert result.filename is None
    assert any("stateful resource" in item for item in result.assumptions)
    assert "Terraform" in " ".join(result.assumptions + result.steps)


def test_rds_backup_guidance_preserves_outage_and_replica_caveats() -> None:
    result = recommend(observation("rds_instance_backup_enabled", service="rds"))

    assert "causes an outage" in result.impact
    context = " ".join(result.assumptions)
    assert "greater than zero" in context
    assert "read replicas" in context
    assert "check_rds_instance_replicas" in context


def test_rds_log_export_guidance_does_not_treat_any_log_as_complete_auditing() -> None:
    result = recommend(observation("rds_instance_integration_cloudwatch_logs", service="rds"))

    assert "any one export" in result.why
    context = " ".join(result.assumptions + result.steps)
    assert "required log types" in context
    assert "retention" in context


def test_rds_public_access_guidance_matches_pinned_compound_detection() -> None:
    result = recommend(observation("rds_instance_no_public_access", service="rds"))

    assert "publicly addressable" in result.what
    assert "public subnet" in result.what
    assert "internet CIDR" in result.what
    context = " ".join(result.assumptions)
    assert "all observed" in context
    assert "PASS" in context


def test_rds_storage_encryption_requires_migration_and_never_deletes_source() -> None:
    result = recommend(observation("rds_instance_storage_encrypted", service="rds"))

    assert "cannot be enabled in place" in result.impact
    assert "snapshot" in result.change
    assert "restore" in result.change
    context = " ".join(result.assumptions + result.steps)
    assert "does not authorize deleting" in context
    assert "rollback" in context


def test_public_rds_snapshot_is_a_manual_investigation_without_deletion() -> None:
    result = recommend(observation("rds_snapshots_public_access", service="rds"))

    assert result.status == "manual_action"
    assert result.terraform is None
    assert "any AWS account" in result.why
    assert "cannot revoke copies" in result.impact
    context = " ".join(result.assumptions + result.steps)
    assert "No deletion" in context
    assert "incident or privacy review" in context


def test_public_ebs_snapshot_requires_investigation_without_deletion() -> None:
    result = recommend(observation("ec2_ebs_public_snapshot", service="ec2"))

    assert result.status == "manual_action"
    assert result.terraform is None
    assert "all group" in result.what
    assert "cannot revoke" in result.impact
    context = " ".join(result.assumptions + result.steps)
    assert "No snapshot deletion" in context
    assert "incident or privacy review" in context


def test_unencrypted_ebs_volume_requires_application_aware_migration() -> None:
    result = recommend(observation("ec2_ebs_volume_encryption", service="ec2"))

    assert result.status == "needs_context"
    assert result.terraform is None
    assert "not changed in place" in result.impact
    context = " ".join(result.assumptions + result.steps)
    for term in ("filesystem", "KMS", "rollback", "retirement"):
        assert term in context


def test_public_ip_guidance_does_not_equate_address_with_reachable_port() -> None:
    result = recommend(observation("ec2_instance_public_ip", service="ec2"))

    assert result.status == "needs_context"
    assert result.terraform is None
    assert "routing potential" in result.why
    assert "does not prove" in " ".join(result.assumptions)
    assert "No address disassociation" in " ".join(result.assumptions)


def test_ssm_guidance_preserves_check_state_and_registration_limits() -> None:
    result = recommend(observation("ec2_instance_managed_by_ssm", service="ec2"))

    assert result.status == "needs_context"
    assert result.terraform is None
    context = " ".join(result.assumptions + result.steps)
    assert "pending, stopped, and terminated" in context
    assert "does not prove patch compliance" in context
    assert "VPC endpoints" in context


def test_efs_encryption_guidance_requires_new_validated_file_system() -> None:
    result = recommend(observation("efs_encryption_at_rest_enabled", service="efs"))

    assert result.status == "needs_context"
    assert result.terraform is None
    assert "cannot be enabled" in result.impact
    context = " ".join(result.assumptions + result.steps)
    assert "No destination file system" in context
    assert "client" in context
    assert "rollback" in context
    assert "deletion approvals" in context


def test_efs_backup_guidance_requires_policy_and_restore_validation() -> None:
    result = recommend(observation("efs_have_backup_enabled", service="efs"))

    assert result.status == "needs_context"
    assert result.terraform is None
    assert "DISABLED or DISABLING" in result.what
    context = " ".join(result.assumptions + result.steps)
    assert "35-day" in context
    assert "customer policy" in context
    assert "restore" in context
    assert "vault" in context


def test_dax_encryption_requires_replacement_and_client_cutover() -> None:
    result = recommend(
        observation("dynamodb_accelerator_cluster_encryption_enabled", service="dynamodb")
    )

    assert result.status == "needs_context"
    assert result.terraform is None
    assert "cannot be changed" in result.impact
    context = " ".join(result.assumptions + result.steps)
    assert "No replacement cluster" in context
    assert "cache warm-up" in context
    assert "rollback" in context


def test_dynamodb_kms_guidance_exposes_pinned_cmk_detection_limit() -> None:
    result = recommend(
        observation("dynamodb_tables_kms_cmk_encryption_enabled", service="dynamodb")
    )

    assert result.status == "needs_context"
    assert result.terraform is None
    assert "All DynamoDB tables are encrypted" in result.why
    caveats = " ".join(result.assumptions)
    assert "check name containing kms_cmk" in caveats
    assert "AWS managed" in caveats
    assert "customer-managed" in caveats


def test_dynamodb_pitr_guidance_accounts_for_new_table_restore_gaps() -> None:
    result = recommend(observation("dynamodb_tables_pitr_enabled", service="dynamodb"))

    assert result.status == "needs_context"
    assert result.terraform is None
    assert "new table" in result.impact
    context = " ".join(result.assumptions + result.steps)
    for setting in ("auto scaling", "IAM policies", "streams", "TTL", "deletion protection"):
        assert setting in context
    assert "application recovery" in context
