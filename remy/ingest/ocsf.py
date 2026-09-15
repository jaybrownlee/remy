"""Strict, all-or-nothing import of AWS Prowler JSON-OCSF saved output.

Reference: https://docs.prowler.com/user-guide/cli/tutorials/reporting
Only selected scalar metadata survives. Raw payloads are never persisted.
"""

import json
import re
from datetime import datetime
from typing import Literal, cast

from remy.reports.schema import Observation

MAX_BYTES = 10 * 1024 * 1024
MAX_RECORDS = 5000


class ImportError(ValueError):
    """A saved scan could not be imported without losing information."""


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ImportError(f"Expected {label} to be an object.")
    return cast(dict[str, object], value)


def _text(value: object, label: str, default: str | None = None) -> str:
    if value is None and default is not None:
        return default
    if not isinstance(value, str) or not value.strip():
        raise ImportError(f"Missing or invalid {label}.")
    if len(value) > 20000 or any(ord(c) < 32 and c not in "\n\r\t" for c in value):
        raise ImportError(f"Invalid or oversized {label}.")
    return value.strip()


def _detail(value: str) -> str:
    # Do not copy credentials that a scanner may echo into a free-text detail.
    value = re.sub(r"AKIA[A-Z0-9]{16}|ASIA[A-Z0-9]{16}", "[REDACTED]", value)
    return re.sub(
        r"(?i)\b(password|secret|token|access[_ -]?key)\s*[:=]\s*[^\s,;]+",
        r"\1=[REDACTED]",
        value,
    )


def parse_ocsf(raw: bytes) -> list[Observation]:
    if len(raw) > MAX_BYTES:
        raise ImportError("File exceeds the 10 MiB upload limit.")
    try:
        records = json.loads(raw)
    except (ValueError, UnicodeDecodeError, RecursionError) as error:
        raise ImportError("Upload a valid UTF-8 Prowler JSON-OCSF array.") from error
    if not isinstance(records, list) or not records:
        raise ImportError("Upload a non-empty Prowler JSON-OCSF array.")
    if len(records) > MAX_RECORDS:
        raise ImportError("This prototype accepts at most 5,000 source records.")
    observations: list[Observation] = []
    identities: set[tuple[str, str, str]] = set()
    for index, raw_record in enumerate(records, 1):
        try:
            record = _object(raw_record, "record")
            metadata = _object(record.get("metadata"), "metadata")
            cloud = _object(record.get("cloud"), "cloud")
            if cloud.get("provider") != "aws":
                raise ImportError("Only AWS Prowler output is supported in this prototype.")
            account = _object(cloud.get("account"), "cloud.account")
            info = _object(record.get("finding_info"), "finding_info")
            status = _text(record.get("status_code"), "status_code").upper()
            if status not in {"PASS", "FAIL", "MANUAL"}:
                raise ImportError("status_code must be PASS, FAIL, or MANUAL.")
            resources = record.get("resources")
            if not isinstance(resources, list) or not resources:
                raise ImportError("resources must contain at least one resource.")
            timestamp = record.get("time_dt")
            observed_at = None
            if timestamp is not None:
                try:
                    observed_at = datetime.fromisoformat(_text(timestamp, "time_dt"))
                except ValueError as error:
                    raise ImportError("time_dt must be an ISO datetime.") from error
            for raw_resource in resources:
                resource = _object(raw_resource, "resource")
                account_id = _text(account.get("uid"), "account uid")
                check_id = _text(metadata.get("event_code"), "check ID")
                resource_uid = _text(resource.get("uid"), "resource UID")
                identity = (account_id, check_id, resource_uid)
                if identity in identities:
                    raise ImportError(
                        "Duplicate check/resource observations; use one scan per file."
                    )
                identities.add(identity)
                group = _object(resource.get("group", {}), "resource group")
                observations.append(
                    Observation(
                        account_id=account_id,
                        check_id=check_id,
                        resource_uid=resource_uid,
                        resource_name=_text(resource.get("name"), "resource name", resource_uid),
                        service=_text(group.get("name"), "service", "unknown"),
                        region=_text(
                            resource.get("region", cloud.get("region")), "region", "unknown"
                        ),
                        status=cast(Literal["FAIL", "PASS", "MANUAL"], status),
                        severity=_text(record.get("severity"), "severity", "Unknown"),
                        title=_text(info.get("title"), "finding title", check_id),
                        detail=_detail(
                            _text(record.get("status_detail"), "detail", "No detail supplied.")
                        ),
                        observed_at=observed_at,
                    )
                )
                if len(observations) > MAX_RECORDS:
                    raise ImportError("Expanded observations exceed the 5,000-item limit.")
        except ImportError as error:
            raise ImportError(f"Record {index}: {error}") from error
    return observations
