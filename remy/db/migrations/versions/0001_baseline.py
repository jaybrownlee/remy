"""Adopt the prototype schema without replacing stored reports or credentials.

This schema is frozen. Future model changes require a new revision.
"""

import sqlalchemy as sa
from alembic import op
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy.dialects.postgresql import JSONB

revision = "0001_baseline"
down_revision = None
branch_labels = None
depends_on = None


def baseline() -> sa.MetaData:
    schema = sa.MetaData()
    sa.Table(
        "reports",
        schema,
        sa.Column("report_id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), nullable=False, index=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column("payload", sa.JSON().with_variant(JSONB(), "postgresql"), nullable=False),
    )
    sa.Table(
        "auth_organizations",
        schema,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(120), nullable=False),
    )
    sa.Table(
        "auth_users",
        schema,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("email", sa.String(254), nullable=False, unique=True),
    )
    sa.Table(
        "auth_memberships",
        schema,
        sa.Column("user_id", sa.ForeignKey("auth_users.id"), primary_key=True),
        sa.Column("org_id", sa.ForeignKey("auth_organizations.id"), primary_key=True),
        sa.Column("role", sa.String(10), nullable=False),
        sa.CheckConstraint("role IN ('owner', 'member')"),
    )
    sa.Table(
        "auth_links",
        schema,
        sa.Column("digest", sa.String(64), primary_key=True),
        sa.Column("user_id", sa.ForeignKey("auth_users.id"), nullable=False),
        sa.Column("browser_digest", sa.String(64), nullable=False),
        sa.Column("expires", sa.Integer, nullable=False),
    )
    sa.Table(
        "auth_sessions",
        schema,
        sa.Column("digest", sa.String(64), primary_key=True),
        sa.Column("user_id", sa.ForeignKey("auth_users.id"), nullable=False),
        sa.Column("org_id", sa.ForeignKey("auth_organizations.id"), nullable=False),
        sa.Column("csrf", sa.String(64), nullable=False),
        sa.Column("expires", sa.Integer, nullable=False),
    )
    sa.Table(
        "auth_rate_limits",
        schema,
        sa.Column("key", sa.String(100), primary_key=True),
        sa.Column("count", sa.Integer, nullable=False),
    )
    sa.Table(
        "auth_audit",
        schema,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36), nullable=False),
        sa.Column("org_id", sa.String(36), nullable=False),
        sa.Column("action", sa.String(40), nullable=False),
        sa.Column("target", sa.String(100), nullable=False),
        sa.Column("created", sa.Integer, nullable=False),
    )
    return schema


def upgrade() -> None:
    connection = op.get_bind()
    schema = baseline()
    existing = set(sa.inspect(connection).get_table_names())
    # Validate existing tables before creating anything. Do not silently stamp drift.
    subset = sa.MetaData()
    for table in schema.sorted_tables:
        table.to_metadata(subset)
    comparison = MigrationContext.configure(
        connection,
        opts={
            "include_object": lambda obj, name, kind, reflected, compare_to: kind != "table"
            or name in existing,
            "compare_type": True,
        },
    )
    if compare_metadata(comparison, subset):
        raise RuntimeError(
            "Existing schema differs from the prototype. Restore or review it before migrating."
        )
    for name in existing & set(schema.tables):
        inspector = sa.inspect(connection)
        expected = [column.name for column in schema.tables[name].primary_key.columns]
        if inspector.get_pk_constraint(name)["constrained_columns"] != expected:
            raise RuntimeError("Existing primary key differs from the prototype.")
    schema.create_all(connection, checkfirst=True)
    if connection.dialect.name == "sqlite":
        for operation in ("UPDATE", "DELETE"):
            connection.exec_driver_sql(
                f"CREATE TRIGGER IF NOT EXISTS auth_audit_no_{operation.lower()} "
                f"BEFORE {operation} ON auth_audit BEGIN "
                "SELECT RAISE(ABORT, 'audit records are immutable'); END"
            )
    elif connection.dialect.name == "postgresql":
        connection.exec_driver_sql(
            "CREATE OR REPLACE FUNCTION remy_auth_audit_immutable() RETURNS trigger "
            "LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit records are immutable'; END $$"
        )
        connection.exec_driver_sql("DROP TRIGGER IF EXISTS auth_audit_immutable ON auth_audit")
        connection.exec_driver_sql(
            "CREATE TRIGGER auth_audit_immutable BEFORE UPDATE OR DELETE ON auth_audit "
            "FOR EACH ROW EXECUTE FUNCTION remy_auth_audit_immutable()"
        )
        connection.exec_driver_sql(
            "CREATE TRIGGER auth_audit_no_truncate BEFORE TRUNCATE ON auth_audit "
            "FOR EACH STATEMENT EXECUTE FUNCTION remy_auth_audit_immutable()"
        )


def downgrade() -> None:
    raise RuntimeError(
        "Destructive baseline downgrade is disabled. Restore a verified backup instead."
    )
