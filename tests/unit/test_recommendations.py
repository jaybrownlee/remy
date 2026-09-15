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
        "accessanalyzer_enabled",
        "account_maintain_different_contact_details_to_security_billing_and_operations",
        "ec2_ebs_default_encryption",
        "s3_bucket_object_versioning",
        "guardduty_is_enabled",
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
