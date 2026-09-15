"""Add explicit rate-limit expiry for bounded retention cleanup."""

import sqlalchemy as sa
from alembic import op

revision = "0002_auth_retention"
down_revision = "0001_baseline"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # A default allows portable non-null addition without rebuilding SQLite tables.
    op.add_column(
        "auth_rate_limits", sa.Column("expires", sa.Integer(), nullable=False, server_default="0")
    )
    connection = op.get_bind()
    if connection.dialect.name == "postgresql":
        connection.exec_driver_sql(
            "UPDATE auth_rate_limits SET expires = "
            "(CAST(split_part(key, ':', 1) AS INTEGER) + 1) * 3600"
        )
    else:
        connection.exec_driver_sql(
            "UPDATE auth_rate_limits SET expires = "
            "(CAST(substr(key, 1, instr(key, ':') - 1) AS INTEGER) + 1) * 3600"
        )
    op.create_index("ix_auth_rate_limits_expires", "auth_rate_limits", ["expires"])
    op.create_index("ix_auth_links_expires", "auth_links", ["expires"])
    op.create_index("ix_auth_sessions_expires", "auth_sessions", ["expires"])


def downgrade() -> None:
    raise RuntimeError("Restore a verified backup instead of downgrading authentication retention.")
