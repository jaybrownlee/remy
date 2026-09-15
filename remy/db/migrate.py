"""Explicit versioned schema upgrades; application connections never perform DDL."""

import os
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from sqlalchemy import create_engine
from sqlalchemy.engine import Engine

HEAD = "0002_auth_retention"


def upgrade(engine: Engine) -> None:
    config = Config()
    config.set_main_option("script_location", str(Path(__file__).with_name("migrations")))
    with engine.begin() as connection:
        if engine.dialect.name == "postgresql":
            # Serialize migration operators, not application requests.
            connection.exec_driver_sql("SELECT pg_advisory_xact_lock(726369, 1)")
        config.attributes["connection"] = connection
        command.upgrade(config, "head")


def require_current(engine: Engine) -> None:
    with engine.connect() as connection:
        current = MigrationContext.configure(connection).get_current_heads()
    if current != (HEAD,):
        raise RuntimeError(
            "Database migration required. Back up the database, then run make migrate."
        )


def main() -> None:
    directory = Path(os.environ.get("REMY_DATA_DIR", ".remy"))
    directory.mkdir(parents=True, exist_ok=True)
    url = os.environ.get("REMY_DATABASE_URL", f"sqlite:///{directory / 'reports.db'}")
    engine = create_engine(url)
    try:
        upgrade(engine)
        require_current(engine)
        print(f"Database schema ready: {HEAD}")
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
