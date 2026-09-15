"""Build immutable reports; generation never resolves a finding."""

import hashlib
import json
from datetime import UTC, datetime
from uuid import UUID, uuid4, uuid5

from remy.ingest.ocsf import parse_ocsf
from remy.recommendations.catalog import recommend
from remy.recommendations.framework import SOURCE_URL, check_ids, citations_for
from remy.reports.coordination import assess_shared_changes
from remy.reports.schema import Observation, Report, ReportItem


def stable_item_id(org_id: UUID, observation: Observation) -> UUID:
    # JSON framing avoids collisions if a source field contains a separator.
    identity = json.dumps(
        [observation.account_id, observation.check_id, observation.resource_uid],
        separators=(",", ":"),
    )
    return uuid5(org_id, identity)


def priority(observation: Observation) -> tuple[int, list[str]]:
    # Limited catalog: unknown checks get an explicit fallback, not invented exposure.
    check = observation.check_id
    if check.startswith("s3_") and "public" in check:
        return 60, ["Potential direct data exposure", "Reachability not independently verified"]
    if check == "iam_root_mfa_enabled":
        return 65, ["Account credential protection", "Affects whole account"]
    if check in {"cloudtrail_multi_region_enabled", "cloudtrail_enabled", "accessanalyzer_enabled"}:
        return 46, ["Account visibility", "Affects whole account"]
    return 15, ["Provisional priority: exposure classification requires review"]


def compose_report(raw: bytes, org_id: UUID, source_name: str, *, sample: bool = False) -> Report:
    observations = parse_ocsf(raw)
    items = []
    for observation in observations:
        if observation.status != "FAIL":
            continue
        score, reasons = priority(observation)
        recommendation = recommend(observation)
        mapped = citations_for(observation.check_id)
        if mapped:
            recommendation.citations = mapped
        items.append(
            ReportItem(
                item_id=stable_item_id(org_id, observation),
                line_number=1,
                observation=observation,
                priority_score=score,
                priority_reasons=reasons,
                recommendation=recommendation,
            )
        )
    items.sort(key=lambda item: (-item.priority_score, str(item.item_id)))
    for number, item in enumerate(items, 1):
        item.line_number = number
    shared_changes = assess_shared_changes(items)
    warnings = [
        "Local prototype: recommendation coverage and HIPAA mappings are incomplete and draft.",
        "An uploaded JSON file does not prove a complete HIPAA scan. "
        "No finding is marked resolved.",
        "Priority is provisional; full mapping, reachability and recency scoring "
        "are not yet implemented.",
        "Terraform is suggested guidance, not an executable deployment bundle. Review every input.",
    ]
    warnings.append(
        f"Shared-setting review: {len(shared_changes)} possible overlap group(s) identified. "
        "Only known template targets are compared. Missing inputs, shared dependencies, "
        "and existing Terraform ownership still require review."
    )
    observed_framework_checks = {o.check_id for o in observations} & check_ids()
    warnings.append(
        f"The upload contains {len(observed_framework_checks)} of {len(check_ids())} distinct "
        "check IDs in the pinned HIPAA framework. This is a membership count, not proof of "
        "scan completeness or compliance. Framework source: " + SOURCE_URL
    )
    unsupported = sum(item.recommendation.status == "unsupported" for item in items)
    if unsupported:
        warnings.append(
            f"{unsupported} failed finding(s) have no reviewed recommendation template."
        )
    if sample:
        warnings.insert(
            0, "Public Prowler example with placeholder IDs; not a live scan or full HIPAA scan."
        )
    report = Report(
        report_id=uuid4(),
        org_id=org_id,
        created_at=datetime.now(UTC),
        source_name=source_name,
        source_sha256=hashlib.sha256(raw).hexdigest(),
        source_kind=(
            "Prowler 5.42.0 public AWS example (placeholder identifiers)."
            if sample
            else "Imported Prowler AWS output; completeness and provenance unverified."
        ),
        items=items,
        observation_count=len(observations),
        pass_count=sum(o.status == "PASS" for o in observations),
        manual_count=sum(o.status == "MANUAL" for o in observations),
        warnings=warnings,
        shared_changes=shared_changes,
        coordination_assessed=True,
    )
    # Freeze defaults in new snapshots; legacy snapshots keep their original field set.
    report = Report.model_validate(report.model_dump())
    report.content_sha256 = hashlib.sha256(report.model_dump_json().encode()).hexdigest()
    return report
