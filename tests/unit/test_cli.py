import io
import json
from pathlib import Path
from zipfile import ZipFile

from remy.cli import EXIT_INPUT, EXIT_OK, EXIT_OUTPUT, EXIT_PARTIAL, main

SAMPLE = Path(__file__).resolve().parents[2] / "remy/data/prowler-aws-example.json"


def test_validate_reports_scan_accounting_without_writes(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = main(["validate", str(SAMPLE.resolve())])
    captured = capsys.readouterr()
    assert result == EXIT_OK
    assert "Observations: 5 (FAIL 2, PASS 0, MANUAL 3)" in captured.out
    assert "Distinct checks: 5" in captured.out
    assert "Source SHA-256:" in captured.out
    assert captured.err == ""
    assert list(tmp_path.iterdir()) == []


def test_standard_input_validation(capsys, monkeypatch):
    class Input:
        buffer = io.BytesIO(SAMPLE.read_bytes())

    monkeypatch.setattr("remy.cli.sys.stdin", Input())
    assert main(["validate", "-"]) == EXIT_OK
    assert "stdin.json" in capsys.readouterr().out


def test_invalid_input_uses_stderr_and_does_not_create_output(tmp_path, capsys):
    invalid = tmp_path / "invalid.json"
    invalid.write_text("[]")
    output = tmp_path / "output"
    result = main(["report", str(invalid), "--output", str(output)])
    captured = capsys.readouterr()
    assert result == EXIT_INPUT
    assert captured.out == ""
    assert "remy: invalid input:" in captured.err
    assert not output.exists()


def test_report_writes_all_standalone_artifacts(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1770000000")
    output = tmp_path / "report"
    assert main(["report", str(SAMPLE), "--output", str(output)]) == EXIT_OK
    captured = capsys.readouterr()
    assert "Findings: 2 failed, 0 passed, 3 manual" in captured.out
    assert set(path.name for path in output.iterdir()) == {
        "report.html",
        "report.json",
        "report.pdf",
        "terraform.zip",
    }
    assert output.joinpath("report.html").read_text().startswith("<!doctype html>")
    assert output.joinpath("report.pdf").read_bytes().startswith(b"%PDF-")
    payload = json.loads(output.joinpath("report.json").read_bytes())
    assert payload["source_name"] == SAMPLE.name
    assert payload["created_at"].startswith("2026-")
    with ZipFile(output / "terraform.zip") as archive:
        assert {"report.json", "README.md", "manifest.json"} <= set(archive.namelist())


def test_reproducible_mode_produces_identical_artifacts(tmp_path, monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1770000000")
    first, second = tmp_path / "first", tmp_path / "second"
    assert main(["report", str(SAMPLE), "-o", str(first)]) == EXIT_OK
    assert main(["report", str(SAMPLE), "-o", str(second)]) == EXIT_OK
    for name in ("report.html", "report.json", "report.pdf", "terraform.zip"):
        assert (first / name).read_bytes() == (second / name).read_bytes()


def test_format_selection_and_overwrite_protection(tmp_path, capsys):
    output = tmp_path / "report"
    args = ["report", str(SAMPLE), "-o", str(output), "--format", "json"]
    assert main(args) == EXIT_OK
    assert set(path.name for path in output.iterdir()) == {"report.json"}
    assert main(args) == EXIT_OUTPUT
    assert "already exists" in capsys.readouterr().err
    marker = output / "customer-note.txt"
    marker.write_text("preserve")
    assert main([*args, "--force"]) == EXIT_OK
    assert marker.read_text() == "preserve"
    assert set(path.name for path in output.iterdir()) == {"report.json", marker.name}


def test_unknown_guidance_generates_report_with_partial_exit(tmp_path, capsys):
    records = json.loads(SAMPLE.read_text())
    records[0]["metadata"]["event_code"] = "unknown_customer_check"
    scan = tmp_path / "unknown.json"
    scan.write_text(json.dumps(records))
    output = tmp_path / "report"
    assert main(["report", str(scan), "-o", str(output)]) == EXIT_PARTIAL
    captured = capsys.readouterr()
    assert "unsupported guidance" in captured.err
    assert (output / "report.html").exists()
    assert "unknown_customer_check" in (output / "report.html").read_text()


def test_html_escapes_untrusted_scan_text(tmp_path):
    records = json.loads(SAMPLE.read_text())
    records[0]["finding_info"]["title"] = "<script>alert('x')</script>"
    scan = tmp_path / "unsafe.json"
    scan.write_text(json.dumps(records))
    output = tmp_path / "report"
    assert main(["report", str(scan), "-o", str(output), "-f", "html"]) == EXIT_OK
    html = (output / "report.html").read_text()
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html


def test_invalid_reproducible_timestamp_fails_before_writes(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "not-a-time")
    output = tmp_path / "report"
    assert main(["report", str(SAMPLE), "-o", str(output)]) == EXIT_OUTPUT
    assert "SOURCE_DATE_EPOCH" in capsys.readouterr().err
    assert not output.exists()
