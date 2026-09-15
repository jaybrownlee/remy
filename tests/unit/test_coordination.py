import io
import json
from copy import deepcopy
from pathlib import Path
from uuid import uuid4
from zipfile import ZipFile

from fastapi.testclient import TestClient

from remy.api.app import DEMO_ORG, create_app
from remy.reports.compose import compose_report
from remy.reports.export import json_export, terraform_export
from remy.reports.schema import Report

BASE = json.loads(Path("remy/data/prowler-aws-example.json").read_bytes())[0]


def row(check, uid, *, region="us-east-1", account="123456789012", name="example-bucket"):
    record = deepcopy(BASE)
    record["metadata"]["event_code"] = check
    record["cloud"]["account"]["uid"] = account
    record["status_code"] = "FAIL"
    record["resources"] = [{"uid": uid, "name": name, "region": region}]
    return record


def report(*records):
    return compose_report(json.dumps(records).encode(), DEMO_ORG, "Synthetic test observations")


def test_account_setting_overlaps_across_regions_without_merging_findings():
    result = report(
        row("s3_account_level_public_access_blocks", "account-observation-east"),
        row(
            "s3_account_level_public_access_blocks", "account-observation-west", region="us-west-2"
        ),
    )
    assert len(result.items) == 2
    assert len(result.shared_changes) == 1
    assert result.shared_changes[0].target.region is None
    ids = {item.item_id for item in result.items}
    assert set(result.shared_changes[0].item_ids) == ids
    for item in result.items:
        assert set(item.related_item_ids) == ids - {item.item_id}
        assert item.recommendation.terraform
    with ZipFile(io.BytesIO(terraform_export(result))) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        assert manifest["coordination_assessed"] is True
        assert len(manifest["shared_changes"]) == 1
        assert len([p for p in archive.namelist() if p.endswith(".tf")]) == 2
        assert all(item["related_item_ids"] for item in manifest["items"])


def test_regional_and_account_boundaries_do_not_create_false_overlaps():
    result = report(
        row("ec2_ebs_default_encryption", "east"),
        row("ec2_ebs_default_encryption", "west", region="us-west-2"),
        row("ec2_ebs_default_encryption", "other-account", account="999999999999"),
    )
    assert result.shared_changes == []
    assert all(item.change_target for item in result.items)


def test_regional_singletons_flag_multiple_suggestions_in_same_region():
    result = report(row("guardduty_is_enabled", "one"), row("guardduty_is_enabled", "two"))
    assert len(result.shared_changes) == 1


def test_password_policy_findings_share_one_account_setting():
    result = report(
        row("iam_password_policy_lowercase", "account-password-policy", name="account"),
        row("iam_password_policy_reuse_24", "account-password-policy", name="account"),
        row("iam_password_policy_symbol", "account-password-policy", name="account"),
    )

    assert len(result.items) == 3
    assert len(result.shared_changes) == 1
    shared = result.shared_changes[0]
    assert shared.target.setting == "IAM account password policy"
    assert shared.target.region is None
    assert set(shared.item_ids) == {item.item_id for item in result.items}


def test_distinct_settings_on_same_bucket_do_not_overlap():
    result = report(
        row("s3_bucket_level_public_access_block", "arn:aws:s3:::example-bucket"),
        row("s3_bucket_object_versioning", "arn:aws:s3:::example-bucket"),
    )
    assert result.shared_changes == []
    assert len({item.change_target.setting for item in result.items}) == 2


def test_bucket_identity_normalizes_arn_and_name_observations():
    result = report(
        row("s3_bucket_object_versioning", "arn:aws:s3:::example-bucket"),
        row("s3_bucket_object_versioning", "example-bucket"),
    )
    assert len(result.shared_changes) == 1
    assert result.shared_changes[0].target.resource == "example-bucket"


def test_missing_target_and_unsupported_items_are_not_guessed():
    result = report(
        row("guardduty_is_enabled", "one", account="<account>"),
        row("guardduty_is_enabled", "two", region="<region>"),
        row("s3_bucket_object_versioning", "unknown", name="<bucket>"),
        row("unknown_check", "other"),
    )
    assert result.shared_changes == []
    for item in result.items:
        assert item.change_target is None
        assert bool(item.coordination_notes) == bool(item.recommendation.terraform)


def test_cloudtrail_uses_home_region_and_requires_confirmable_identity():
    uid = "arn:aws:cloudtrail:us-east-1:123456789012:trail/audit-trail"
    # Different record UIDs cannot represent the same ARN under import deduplication;
    # test normalization directly using the stable report item contract.
    from remy.reports.coordination import assess_shared_changes

    original = report(row("cloudtrail_multi_region_enabled", uid, name="audit-trail")).items[0]
    replica = original.model_copy(deep=True)
    replica.item_id = uuid4()
    replica.observation.region = "us-west-2"
    assert len(assess_shared_changes([original, replica])) == 1
    replica.observation.resource_uid = "unconfirmed"
    assert assess_shared_changes([original, replica]) == []
    assert replica.change_target is None


def test_saved_legacy_report_renders_review_label_and_overlap_links(tmp_path):
    result = report(
        row("s3_account_level_public_access_blocks", "east"),
        row("s3_account_level_public_access_blocks", "west", region="us-west-2"),
    )
    app = create_app(f"sqlite:///{tmp_path / 'reports.db'}", demo_mode=True)
    app.state.store.save(result)
    with TestClient(app, base_url="http://localhost") as client:
        page = client.get(f"/reports/{result.report_id}")
        assert "HIPAA mapping — needs review" in page.text
        assert "low confidence" not in page.text.lower()
        assert "Shared-setting review" in page.text
        assert f'href="#item-{result.items[1].item_id}"' in page.text
    legacy = result.model_dump(mode="json")
    legacy.pop("shared_changes")
    legacy.pop("coordination_assessed")
    for item in legacy["items"]:
        for key in ("change_target", "coordination_notes", "related_item_ids"):
            item.pop(key)
    restored = Report.model_validate(legacy)
    assert restored.coordination_assessed is False
    assert restored.shared_changes == []


def test_legacy_json_export_does_not_add_unassessed_fields():
    result = report(row("guardduty_is_enabled", "one"))
    payload = json.loads(json_export(result))
    payload["schema_version"] = "1.0"
    for key in ("shared_changes", "coordination_assessed"):
        payload.pop(key)
    for item in payload["items"]:
        for key in ("change_target", "coordination_notes", "related_item_ids"):
            item.pop(key)
    restored = Report.model_validate(payload)
    assert json.loads(json_export(restored)) == payload
