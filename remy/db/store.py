"""Small SQLAlchemy store for immutable, organization-scoped reports."""

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, String, create_engine, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from sqlalchemy.types import JSON

from remy.reports.schema import Report


class Base(DeclarativeBase):
    """Declarative base for the prototype persistence schema."""


class StoredReport(Base):
    """An immutable report snapshot."""

    __tablename__ = "reports"

    report_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    org_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    payload: Mapped[dict[str, object]] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"), nullable=False
    )


class Store:
    """Persist and retrieve immutable reports with mandatory tenant scoping."""

    def __init__(self, database_url: str) -> None:
        self._engine: Engine = create_engine(database_url)
        self._sessions = sessionmaker(bind=self._engine, expire_on_commit=False)
        Base.metadata.create_all(self._engine)

    @contextmanager
    def _session(self) -> Iterator[Session]:
        session = self._sessions()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def save(self, report: Report) -> None:
        """Save one immutable report, rejecting a report UUID already in use."""
        row = StoredReport(
            report_id=str(report.report_id),
            org_id=str(report.org_id),
            created_at=report.created_at,
            payload=report.model_dump(mode="json"),
        )
        try:
            with self._session() as session:
                session.add(row)
        except IntegrityError as error:
            raise ValueError(f"report {report.report_id} already exists") from error

    def get(self, org_id: UUID, report_id: UUID) -> Report | None:
        """Return a report only when it belongs to the requested organization."""
        statement = select(StoredReport.payload).where(
            StoredReport.org_id == str(org_id), StoredReport.report_id == str(report_id)
        )
        with self._session() as session:
            payload = session.scalar(statement)
        return Report.model_validate(payload) if payload is not None else None

    def list(self, org_id: UUID) -> list[Report]:
        """List an organization's reports from newest to oldest."""
        statement = (
            select(StoredReport.payload)
            .where(StoredReport.org_id == str(org_id))
            .order_by(StoredReport.created_at.desc(), StoredReport.report_id.desc())
        )
        with self._session() as session:
            payloads = session.scalars(statement).all()
        return [Report.model_validate(payload) for payload in payloads]
