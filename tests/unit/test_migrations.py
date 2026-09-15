from importlib import import_module
from pathlib import Path
from uuid import uuid4

import pytest
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy import create_engine, insert, inspect, select
from sqlalchemy.exc import DatabaseError

from remy.auth import (
    AuthStore,
    audit,
    digest,
    links,
    memberships,
    metadata,
    organizations,
    sessions,
    users,
)
from remy.db.migrate import require_current, upgrade
from remy.db.store import Base, Store, StoredReport
from remy.reports.compose import compose_report


def test_empty_database_requires_explicit_migration(empty_database_url):
    url = empty_database_url
    with pytest.raises(RuntimeError, match="make migrate"):
        Store(url)
    with pytest.raises(RuntimeError, match="make migrate"):
        AuthStore(url)
    engine = create_engine(url)
    assert inspect(engine).get_table_names() == []
    upgrade(engine)
    require_current(engine)
    engine.dispose()


@pytest.mark.parametrize("with_auth", [False, True])
def test_legacy_adoption_preserves_existing_rows(empty_database_url, with_auth):
    url = empty_database_url
    engine = create_engine(url)
    Base.metadata.create_all(engine)
    org_id = uuid4()
    report = compose_report(
        Path("remy/data/prowler-aws-example.json").read_bytes(), org_id, "legacy", sample=True
    )
    with engine.begin() as conn:
        conn.execute(
            insert(StoredReport).values(
                report_id=str(report.report_id),
                org_id=str(org_id),
                created_at=report.created_at,
                payload=report.model_dump(mode="json"),
            )
        )
    if with_auth:
        import_module("remy.db.migrations.versions.0001_baseline").baseline().create_all(engine)
        user_id = str(uuid4())
        with engine.begin() as conn:
            conn.execute(insert(organizations).values(id=str(org_id), name="Legacy"))
            conn.execute(insert(users).values(id=user_id, email="legacy@example.com"))
            conn.execute(
                insert(memberships).values(user_id=user_id, org_id=str(org_id), role="owner")
            )
            conn.execute(
                insert(links).values(
                    digest=digest("legacy-link"),
                    user_id=user_id,
                    browser_digest=digest("browser"),
                    expires=1000,
                )
            )
            conn.execute(
                insert(sessions).values(
                    digest=digest("legacy-session"),
                    user_id=user_id,
                    org_id=str(org_id),
                    csrf="csrf",
                    expires=1000,
                )
            )
            conn.execute(
                insert(audit).values(
                    id=str(uuid4()),
                    user_id="operator",
                    org_id=str(org_id),
                    action="legacy",
                    target="",
                    created=1,
                )
            )
    upgrade(engine)
    upgrade(engine)
    restored = Store(url).get(org_id, report.report_id)
    assert restored.model_dump(mode="json") == report.model_dump(mode="json")
    if with_auth:
        with engine.connect() as conn:
            assert conn.scalar(select(users.c.email)) == "legacy@example.com"
            assert conn.scalar(select(audit.c.action)) == "legacy"
        auth = AuthStore(url)
        assert auth.identify("legacy-session", now=100).org_id == org_id
        assert auth.consume("legacy-link", "browser", now=100)
    engine.dispose()


def test_drift_is_not_silently_stamped(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'drift.db'}")
    with engine.begin() as conn:
        conn.exec_driver_sql("CREATE TABLE reports (report_id TEXT PRIMARY KEY)")
        conn.exec_driver_sql("INSERT INTO reports VALUES ('keep-me')")
    with pytest.raises(RuntimeError, match="differs"):
        upgrade(engine)
    with pytest.raises(RuntimeError, match="make migrate"):
        require_current(engine)
    with engine.connect() as conn:
        assert conn.exec_driver_sql("SELECT report_id FROM reports").scalar() == "keep-me"
    engine.dispose()


def test_migrated_schema_matches_models_and_upgrade_is_idempotent(database_url):
    engine = create_engine(database_url)
    upgrade(engine)
    require_current(engine)
    with engine.connect() as conn:
        assert compare_metadata(MigrationContext.configure(conn), [Base.metadata, metadata]) == []
    if engine.dialect.name == "postgresql":
        with pytest.raises(DatabaseError), engine.begin() as conn:
            conn.exec_driver_sql("TRUNCATE auth_audit")
    engine.dispose()
