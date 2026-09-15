"""Check domain ownership boundaries and report/export integration."""

import json
from copy import deepcopy
from pathlib import Path
from uuid import uuid4

from remy.reports.compose import compose_report
from remy.reports.export import json_export

AT_REST = "opensearch_service_domains_encryption_at_rest_enabled"
INTERNAL = "opensearch_service_domains_node_to_node_encryption_enabled"


def test_domain_encryption_findings_share_owner_in_report_and_export() -> None:
    base = json.loads(Path("remy/data/prowler-aws-example.json").read_bytes())[0]
    rows = []
    for check, domain, arn_account in [
        (AT_REST, "search-one", "123456789012"),
        (INTERNAL, "search-one", "123456789012"),
        (INTERNAL, "search-two", "123456789012"),
        (AT_REST, "wrong-account", "999999999999"),
    ]:
        row = deepcopy(base)
        row["metadata"]["event_code"] = check
        row["cloud"]["account"]["uid"] = "123456789012"
        row["status_code"] = "FAIL"
        row["resources"] = [
            {
                "uid": f"arn:aws:es:us-east-1:{arn_account}:domain/{domain}",
                "name": domain,
                "region": "us-east-1",
            }
        ]
        rows.append(row)
    report = compose_report(json.dumps(rows).encode(), uuid4(), "domain-test.json")
    assert len(report.items) == 4
    assert len(report.shared_changes) == 1
    assert len(report.shared_changes[0].item_ids) == 2
    assert report.shared_changes[0].target.resource == "search-one"
    assert all(item.recommendation.terraform is None for item in report.items)
    wrong = next(i for i in report.items if i.observation.resource_name == "wrong-account")
    assert wrong.change_target is None
    exported = json.loads(json_export(report))
    assert len(exported["shared_changes"]) == 1
    assert len(exported["items"]) == 4
