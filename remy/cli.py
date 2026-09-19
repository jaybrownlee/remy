"""Database-free command-line workflows for saved Prowler scan files."""

import argparse
import hashlib
import os
import sys
from collections import Counter
from collections.abc import Sequence
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4, uuid5

from remy.ingest.ocsf import MAX_BYTES, ImportError, parse_ocsf
from remy.reports.compose import compose_report
from remy.reports.export import html_export, json_export, pdf_export, terraform_export

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_INPUT = 3
EXIT_OUTPUT = 4
EXIT_PARTIAL = 10
STANDALONE_ORG_ID = UUID("55d8f6ab-2184-5f00-9f98-67871ca1fd21")
FORMATS = ("html", "pdf", "json", "terraform")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="remy",
        description="Generate reviewable remediation reports from Prowler AWS JSON-OCSF files.",
    )
    parser.add_argument("--version", action="version", version="Remy 0.1.0")
    commands = parser.add_subparsers(dest="command", required=True)

    validate = commands.add_parser("validate", help="Validate a scan without writing a report.")
    validate.add_argument("scan", help="Prowler JSON-OCSF file, or - for standard input.")

    report = commands.add_parser("report", help="Generate standalone report artifacts.")
    report.add_argument("scan", help="Prowler JSON-OCSF file, or - for standard input.")
    report.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Output directory (default: <scan>-remy-report).",
    )
    report.add_argument(
        "-f",
        "--format",
        action="append",
        choices=(*FORMATS, "all"),
        dest="formats",
        help="Artifact to write; repeat for several. The default is all.",
    )
    report.add_argument(
        "--organization-id",
        type=UUID,
        default=STANDALONE_ORG_ID,
        help="UUID namespace for stable item IDs (default: Remy's standalone namespace).",
    )
    report.add_argument(
        "--force",
        action="store_true",
        help="Replace Remy artifact files in an existing directory; preserve other files.",
    )
    return parser


def _read_scan(value: str) -> tuple[bytes, str]:
    if value == "-":
        raw = sys.stdin.buffer.read(MAX_BYTES + 1)
        name = "stdin.json"
    else:
        path = Path(value)
        name = path.name
        try:
            with path.open("rb") as stream:
                raw = stream.read(MAX_BYTES + 1)
        except OSError as error:
            raise ImportError(f"Cannot read {path}: {error.strerror or 'read failed'}.") from None
    if len(raw) > MAX_BYTES:
        raise ImportError("File exceeds the 10 MiB input limit.")
    return raw, name


def _created_at() -> datetime | None:
    value = os.environ.get("SOURCE_DATE_EPOCH")
    if value is None:
        return None
    try:
        epoch = int(value)
        if epoch < 0:
            raise ValueError
        return datetime.fromtimestamp(epoch, UTC)
    except (OSError, OverflowError, ValueError):
        raise ValueError("SOURCE_DATE_EPOCH must be a non-negative Unix timestamp.") from None


def _formats(values: list[str] | None) -> tuple[str, ...]:
    if not values or "all" in values:
        return FORMATS
    requested = set(values)
    return tuple(value for value in FORMATS if value in requested)


def _default_output(scan: str) -> Path:
    if scan == "-":
        return Path("remy-report")
    stem = Path(scan).stem or "scan"
    return Path(f"{stem}-remy-report")


def _write_artifacts(output: Path, artifacts: dict[str, bytes], force: bool) -> None:
    if output.exists():
        if not output.is_dir():
            raise OSError(f"Output path exists and is not a directory: {output}")
        if not force:
            raise OSError(
                f"Output directory already exists: {output} (use --force to replace artifacts)"
            )
    else:
        output.mkdir(parents=True)

    for name in artifacts:
        target = output / name
        if target.exists() and not target.is_file():
            raise OSError(f"Artifact path exists and is not a file: {target}")

    temporary: list[tuple[Path, Path]] = []
    try:
        for name, content in artifacts.items():
            target = output / name
            temp = output / f".{name}.{uuid4().hex}.tmp"
            with temp.open("xb") as stream:
                stream.write(content)
            temporary.append((temp, target))
        for temp, target in temporary:
            os.replace(temp, target)
    finally:
        for temp, _target in temporary:
            with suppress(OSError):
                temp.unlink(missing_ok=True)


def _validate(scan: str) -> int:
    raw, name = _read_scan(scan)
    observations = parse_ocsf(raw)
    statuses = Counter(observation.status for observation in observations)
    checks = {observation.check_id for observation in observations}
    print(
        f"Valid Prowler AWS JSON-OCSF: {name}\n"
        f"Observations: {len(observations)} "
        f"(FAIL {statuses['FAIL']}, PASS {statuses['PASS']}, MANUAL {statuses['MANUAL']})\n"
        f"Distinct checks: {len(checks)}\n"
        f"Source SHA-256: {hashlib.sha256(raw).hexdigest()}"
    )
    return EXIT_OK


def _report(args: argparse.Namespace) -> int:
    raw, name = _read_scan(args.scan)
    source_hash = hashlib.sha256(raw).hexdigest()
    report = compose_report(
        raw,
        args.organization_id,
        name,
        report_id=uuid5(args.organization_id, "report:" + source_hash),
        created_at=_created_at(),
    )
    exporters = {
        "html": ("report.html", html_export),
        "pdf": ("report.pdf", pdf_export),
        "json": ("report.json", json_export),
        "terraform": ("terraform.zip", terraform_export),
    }
    artifacts = {
        exporters[format_name][0]: exporters[format_name][1](report)
        for format_name in _formats(args.formats)
    }
    output = args.output or _default_output(args.scan)
    _write_artifacts(output, artifacts, args.force)

    unsupported = sum(item.recommendation.status == "unsupported" for item in report.items)
    print(
        f"Generated Remy report {report.report_id}\n"
        f"Findings: {len(report.items)} failed, {report.pass_count} passed, "
        f"{report.manual_count} manual\n"
        f"Output: {output.resolve()}"
    )
    for name in artifacts:
        print(f"  {name}")
    if unsupported:
        print(
            f"Warning: {unsupported} failed finding(s) have unsupported guidance; "
            "the report was generated.",
            file=sys.stderr,
        )
        return EXIT_PARTIAL
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "validate":
            return _validate(args.scan)
        return _report(args)
    except ImportError as error:
        print(f"remy: invalid input: {error}", file=sys.stderr)
        return EXIT_INPUT
    except (OSError, ValueError) as error:
        print(f"remy: {error}", file=sys.stderr)
        return EXIT_OUTPUT


if __name__ == "__main__":
    raise SystemExit(main())
