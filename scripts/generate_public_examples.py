"""Regenerate with: uv run python -m scripts.generate_public_examples

All observations below are invented for this public example. No AWS data is read.
"""

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from remy.reports.compose import compose_report
from remy.reports.export import html_export, json_export, pdf_export

ACCOUNT = "123456789012"
REGION = "us-west-2"


def finding(check, service, resource, title, detail, severity="High", status="FAIL"):
    return {
        "metadata": {"event_code": check},
        "cloud": {"provider": "aws", "account": {"uid": ACCOUNT}, "region": REGION},
        "finding_info": {"title": title},
        "status_code": status,
        "status_detail": "Fictional example: " + detail,
        "severity": severity,
        "time_dt": "2026-09-23T09:00:00+00:00",
        "resources": [
            {
                "uid": resource,
                "name": resource.rsplit("/", 1)[-1],
                "region": REGION,
                "group": {"name": service},
            }
        ],
    }


records = [
    finding(
        "s3_bucket_level_public_access_block",
        "s3",
        "arn:aws:s3:::northstar-demo-invoices",
        "Invoice archive is missing bucket-level public access blocks",
        "The northstar-demo-invoices bucket stores generated invoice exports. "
        "BlockPublicAcls and IgnorePublicAcls are disabled. "
        "This finding alone does not establish that any objects are publicly accessible.",
    ),
    finding(
        "cloudtrail_multi_region_enabled",
        "cloudtrail",
        f"arn:aws:cloudtrail:{REGION}:{ACCOUNT}:trail/northstar-demo-audit",
        "Audit trail only covers one AWS region",
        "The northstar-demo-audit trail is configured for us-west-2 only. "
        "The fictional team also deploys services in us-east-1.",
        "Medium",
    ),
    finding(
        "iam_root_mfa_enabled",
        "iam",
        f"arn:aws:iam::{ACCOUNT}:root",
        "Root account has no MFA device",
        "No MFA device is registered for the fictional account root user. "
        "An authorized account owner must review and complete enrollment.",
    ),
    finding(
        "s3_bucket_level_public_access_block",
        "s3",
        "arn:aws:s3:::northstar-demo-audit-logs",
        "Audit log bucket has all public access blocks enabled",
        "All four bucket-level public access block settings are enabled.",
        "Informational",
        "PASS",
    ),
]
raw = json.dumps(records, indent=2).encode()
os.environ["SOURCE_DATE_EPOCH"] = str(int(datetime(2026, 9, 23, 10, tzinfo=UTC).timestamp()))
report = compose_report(
    raw,
    UUID("ee0b36c0-a39a-4db1-9d85-000000000001"),
    "Northstar Demo - fictional AWS security review",
    report_id=UUID("ee0b36c0-a39a-4db1-9d85-000000000002"),
    created_at=datetime(2026, 9, 23, 10, 0, tzinfo=UTC),
)
report.source_kind = (
    "Synthetic demonstration data in Prowler AWS JSON-OCSF format. Not a real scan."
)
report.warnings.insert(
    0,
    "FICTIONAL EXAMPLE: Northstar Demo, all account IDs, resource names, "
    "and findings are invented. No customer or live AWS data is included.",
)
report.content_sha256 = ""
report.content_sha256 = hashlib.sha256(report.model_dump_json().encode()).hexdigest()
out = Path(__file__).resolve().parents[1] / "examples/northstar"
out.mkdir(parents=True, exist_ok=True)
for name, exporter in [
    ("report.html", html_export),
    ("report.json", json_export),
    ("report.pdf", pdf_export),
]:
    (out / name).write_bytes(exporter(report))
(out / "scan.json").write_bytes(raw)
print(
    f"Generated matching examples: {len(report.items)} failed findings, {report.pass_count} passed."
)
