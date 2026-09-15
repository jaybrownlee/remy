from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4, uuid5

import pytest

from remy.db.store import Store
from remy.reports.schema import Observation, Recommendation, Report, ReportItem


def make_report(
    *, org_id: UUID, created_at: datetime, report_id: UUID | None = None, identity: str = "finding"
) -> Report:
    observation = Observation(
        account_id="123456789012",
        check_id="s3_bucket_public_access_block",
        resource_uid=f"arn:aws:s3:::{identity}",
        resource_name=identity,
        service="s3",
        region="us-east-1",
        status="FAIL",
        severity="high",
        title="Public access block is incomplete",
        detail="One or more public access block settings are disabled.",
        observed_at=created_at,
    )
    recommendation = Recommendation(
        status="terraform_guidance",
        what="Enable the S3 public access block settings.",
        why="This reduces accidental public exposure.",
        change="Set all four public access block options after review.",
        impact="Intentional public access may stop working.",
    )
    item_id = uuid5(org_id, f"{observation.account_id}|{observation.check_id}|{identity}")
    return Report(
        report_id=report_id or uuid4(),
        org_id=org_id,
        created_at=created_at,
        source_name="scan.json",
        source_sha256="a" * 64,
        items=[
            ReportItem(
                item_id=item_id,
                line_number=1,
                observation=observation,
                priority_score=90,
                priority_reasons=["Direct safeguard"],
                recommendation=recommendation,
            )
        ],
        observation_count=1,
        pass_count=0,
        manual_count=0,
    )


@pytest.fixture
def store(database_url) -> Store:
    return Store(database_url)


def test_save_get_and_list_newest_first(store: Store) -> None:
    org_id = uuid4()
    older = make_report(org_id=org_id, created_at=datetime(2026, 9, 13, tzinfo=UTC), identity="a")
    newer = make_report(
        org_id=org_id, created_at=older.created_at + timedelta(days=1), identity="b"
    )

    store.save(older)
    store.save(newer)

    assert store.get(org_id, older.report_id) == older
    assert store.list(org_id) == [newer, older]


def test_reports_are_tenant_scoped(store: Store) -> None:
    owner_org = uuid4()
    other_org = uuid4()
    report = make_report(org_id=owner_org, created_at=datetime.now(UTC))
    store.save(report)

    assert store.get(other_org, report.report_id) is None
    assert store.list(other_org) == []


def test_report_id_is_immutable_even_across_tenants(store: Store) -> None:
    report_id = uuid4()
    first = make_report(
        org_id=uuid4(), created_at=datetime(2026, 9, 13, tzinfo=UTC), report_id=report_id
    )
    replacement = make_report(
        org_id=uuid4(), created_at=datetime(2026, 9, 14, tzinfo=UTC), report_id=report_id
    )
    store.save(first)

    with pytest.raises(ValueError, match="already exists"):
        store.save(replacement)

    assert store.get(first.org_id, report_id) == first


def test_item_ids_are_stable_per_org_and_finding_identity() -> None:
    org_id = uuid4()
    first = make_report(org_id=org_id, created_at=datetime(2026, 9, 13, tzinfo=UTC))
    later = make_report(org_id=org_id, created_at=datetime(2026, 9, 14, tzinfo=UTC))
    other_org = make_report(org_id=uuid4(), created_at=datetime(2026, 9, 14, tzinfo=UTC))

    assert first.items[0].item_id == later.items[0].item_id
    assert first.items[0].item_id != other_org.items[0].item_id
