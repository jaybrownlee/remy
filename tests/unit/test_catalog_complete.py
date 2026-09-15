"""All framework checks survive report generation and downloadable manifests."""

import io
import json
from copy import deepcopy
from pathlib import Path
from uuid import uuid4
from zipfile import ZipFile

from remy.recommendations.catalog import SUPPORTED_CHECK_IDS
from remy.recommendations.framework import check_ids
from remy.reports.compose import compose_report
from remy.reports.export import terraform_export


def test_full_framework_report_has_no_gaps_and_keeps_unknown_findings() -> None:
    assert check_ids() <= SUPPORTED_CHECK_IDS
    base = json.loads(Path("remy/data/prowler-aws-example.json").read_bytes())[0]
    records = []
    requested = check_ids() | {"future_unknown_check"}
    for check in sorted(requested):
        row = deepcopy(base)
        row["metadata"]["event_code"] = check
        row["status_code"] = "FAIL"
        records.append(row)
    report = compose_report(json.dumps(records).encode(), uuid4(), "full-framework.json")
    assert len(report.items) == 96
    unknown = [i for i in report.items if i.recommendation.status == "unsupported"]
    assert [i.observation.check_id for i in unknown] == ["future_unknown_check"]
    with ZipFile(io.BytesIO(terraform_export(report))) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        saved = json.loads(archive.read("report.json"))
        assert {i["check_id"] for i in manifest["items"]} == requested
        assert {i["item_id"] for i in manifest["items"]} == {i["item_id"] for i in saved["items"]}
        for item in saved["items"]:
            recommendation = item["recommendation"]
            if item["observation"]["check_id"] in check_ids():
                assert recommendation["citations"]
                assert recommendation["change"] and recommendation["impact"]
                assert recommendation["assumptions"] and recommendation["steps"]
        # Every file remains tied to an item; no phantom deployment is implied.
        for entry in manifest["items"]:
            if entry["path"]:
                assert entry["path"] in archive.namelist()
            else:
                assert entry["sha256"] is None
