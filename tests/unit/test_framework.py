from pathlib import Path
from uuid import uuid4

from remy.recommendations.framework import SOURCE_URL, check_ids, citations_for, framework
from remy.reports.compose import compose_report


def test_pinned_framework_membership_and_multi_requirement_mapping() -> None:
    assert len(framework().requirements) == 32
    assert len(check_ids()) == 95
    assert "ec2_ebs_default_encryption" in check_ids()
    assert "accessanalyzer_enabled" not in check_ids()
    assert citations_for("unknown") == []
    references = citations_for("s3_bucket_object_versioning")
    assert len(references) > 1
    assert all(c.confidence == "low" and c.source_url == SOURCE_URL for c in references)
    assert all(c.url.startswith("https://www.ecfr.gov/") for c in references)


def test_unsupported_framework_finding_keeps_mapping_and_no_invented_code() -> None:
    import json

    rows = json.loads(Path("remy/data/prowler-aws-example.json").read_bytes())
    row = rows[0]
    row["metadata"]["event_code"] = "rds_instance_storage_encrypted"
    row["status_code"] = "FAIL"
    report = compose_report(json.dumps([row]).encode(), uuid4(), "test.json")
    recommendation = report.items[0].recommendation
    assert recommendation.status == "unsupported"
    assert recommendation.terraform is None
    assert recommendation.citations == citations_for("rds_instance_storage_encrypted")
    assert any("1 of 95" in warning for warning in report.warnings)
