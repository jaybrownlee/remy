import hashlib
import io
import json
from pathlib import Path
from uuid import uuid4
from zipfile import ZipFile

import pytest
from fastapi.testclient import TestClient

from remy.api.app import DEMO_ORG, create_app
from remy.ingest.ocsf import MAX_BYTES, ImportError, parse_ocsf
from remy.reports.compose import compose_report, stable_item_id
from remy.reports.export import json_export, pdf_export, terraform_export

SAMPLE = Path("remy/data/prowler-aws-example.json").read_bytes()


@pytest.fixture
def client(database_url):
    app = create_app(database_url, demo_mode=True)
    with TestClient(app, base_url="http://localhost") as test_client:
        yield test_client


def test_upstream_example_complete_accounting_and_stable_ids():
    report = compose_report(SAMPLE, DEMO_ORG, "sample", sample=True)
    repeated = compose_report(SAMPLE, DEMO_ORG, "renamed")
    assert report.observation_count == 5
    assert len(report.items) == 2
    assert report.manual_count == 3
    assert report.pass_count == 0
    assert report.report_id != repeated.report_id
    assert [i.item_id for i in report.items] == [i.item_id for i in repeated.items]
    assert all(i.recommendation.status == "needs_context" for i in report.items)
    assert report.source_sha256 == hashlib.sha256(SAMPLE).hexdigest()
    original = report.model_copy(update={"content_sha256": ""})
    assert hashlib.sha256(original.model_dump_json().encode()).hexdigest() == report.content_sha256
    assert stable_item_id(uuid4(), report.items[0].observation) != report.items[0].item_id


@pytest.mark.parametrize("raw", [b"[]", b"{}", b"not json", b"\xff", b"[1]", b"null"])
def test_invalid_input_never_creates_partial_report(raw):
    with pytest.raises(ImportError):
        parse_ocsf(raw)


@pytest.mark.parametrize("field", ["status_code", "metadata", "resources", "cloud"])
def test_required_fields_stop_entire_import(field):
    records = json.loads(SAMPLE)
    del records[-1][field]
    with pytest.raises(ImportError, match="Record 5"):
        parse_ocsf(json.dumps(records).encode())


def test_duplicates_conflicting_status_and_non_aws_rejected():
    records = json.loads(SAMPLE)
    records.append(records[0])
    with pytest.raises(ImportError, match="Duplicate"):
        parse_ocsf(json.dumps(records).encode())
    records = json.loads(SAMPLE)
    records[0]["cloud"]["provider"] = "azure"
    with pytest.raises(ImportError, match="Only AWS"):
        parse_ocsf(json.dumps(records).encode())


def test_multi_resource_expansion_preserves_every_failure():
    records = json.loads(SAMPLE)
    second = dict(records[0]["resources"][0], uid="another-resource")
    records[0]["resources"].append(second)
    report = compose_report(json.dumps(records).encode(), DEMO_ORG, "multi-resource")
    assert report.observation_count == 6
    assert len(report.items) == 3
    assert len({i.item_id for i in report.items}) == 3


def test_unknown_check_is_visible_without_invented_code():
    records = json.loads(SAMPLE)
    records[0]["metadata"]["event_code"] = "unrecognized_check"
    report = compose_report(json.dumps(records).encode(), DEMO_ORG, "unknown")
    unknown = next(i for i in report.items if i.observation.check_id == "unrecognized_check")
    assert unknown.recommendation.status == "unsupported"
    assert unknown.recommendation.terraform is None
    assert any("no reviewed recommendation" in w for w in report.warnings)


def test_nested_payloads_are_not_persisted_and_known_credentials_redacted():
    records = json.loads(SAMPLE)
    records[0]["resources"][0]["data"] = {"Body": "private-object", "secret": "nested-secret"}
    records[0]["status_detail"] = "password=supersecret token:private-token"
    report = compose_report(json.dumps(records).encode(), DEMO_ORG, "redaction")
    result = json_export(report)
    for hidden in [b"private-object", b"nested-secret", b"supersecret", b"private-token"]:
        assert hidden not in result
    assert b"[REDACTED]" in result


def test_exports_have_item_identity_and_safe_paths():
    report = compose_report(SAMPLE, DEMO_ORG, "sample", sample=True)
    assert json.loads(json_export(report))["report_id"] == str(report.report_id)
    assert pdf_export(report).startswith(b"%PDF-")
    report.items[0].recommendation.filename = "../../unsafe.tf"
    with ZipFile(io.BytesIO(terraform_export(report))) as archive:
        assert all(".." not in name and not name.startswith("/") for name in archive.namelist())
        manifest = json.loads(archive.read("manifest.json"))
        assert len(manifest["items"]) == len(report.items)
        for entry in manifest["items"]:
            if entry["path"]:
                assert hashlib.sha256(archive.read(entry["path"])).hexdigest() == entry["sha256"]
        assert "report.json" in archive.namelist()
        assert b"not a single deployable" in archive.read("README.md")


def test_browser_workflow_and_downloads(client):
    assert client.get("/").status_code == 200
    assert client.get("/healthz").json()["mode"] == "local-prototype"
    response = client.post("/reports/sample", follow_redirects=False)
    assert response.status_code == 303
    path = response.headers["location"]
    page = client.get(path)
    assert page.status_code == 200
    assert "placeholder identifiers" in page.text
    assert "Suggested Terraform" in page.text
    for kind, media in [
        ("json", "application/json"),
        ("pdf", "application/pdf"),
        ("terraform", "application/zip"),
    ]:
        download = client.get(f"{path}/download/{kind}")
        assert download.status_code == 200
        assert download.headers["content-type"] == media
        assert "attachment" in download.headers["content-disposition"]
    assert client.get(f"{path}/download/nope").status_code == 404


def test_import_escapes_untrusted_text_and_errors(client):
    records = json.loads(SAMPLE)
    records[0]["finding_info"]["title"] = "<script>alert('x')</script>"
    response = client.post(
        "/reports/import",
        files={"file": ("../../scan.json", json.dumps(records).encode(), "application/json")},
    )
    assert response.status_code == 200
    assert "<script>" not in response.text
    assert "&lt;script&gt;" in response.text
    assert client.post("/reports/import", files={"file": ("bad.json", b"[]")}).status_code == 400
    assert len(client.app.state.store.list(DEMO_ORG)) == 1


def test_cross_origin_and_host_boundaries(client):
    assert (
        client.post("/reports/sample", headers={"origin": "https://evil.example"}).status_code
        == 403
    )
    assert client.post("/reports/sample", headers={"origin": "null"}).status_code == 403
    assert (
        client.post("/reports/sample", headers={"sec-fetch-site": "cross-site"}).status_code == 403
    )
    assert client.get("/", headers={"host": "evil.example"}).status_code == 400
    assert client.post("/reports/sample", headers={"origin": "http://localhost"}).status_code == 200


def test_known_other_tenant_report_not_exposed(client):
    report = compose_report(SAMPLE, uuid4(), "other tenant")
    client.app.state.store.save(report)
    for suffix in ["", "/download/json", "/download/pdf", "/download/terraform"]:
        assert client.get(f"/reports/{report.report_id}{suffix}").status_code == 404


def test_oversized_upload_rejected(client):
    response = client.post(
        "/reports/import",
        content=b"x" * (MAX_BYTES + 65537),
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 413
    assert client.app.state.store.list(DEMO_ORG) == []
