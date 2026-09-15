"""Run one bounded expired-authentication cleanup batch. Safe to repeat."""

import os
from pathlib import Path

from remy.auth import AuthStore


def main() -> None:
    directory = Path(os.environ.get("REMY_DATA_DIR", ".remy"))
    url = os.environ.get("REMY_DATABASE_URL", f"sqlite:///{directory / 'reports.db'}")
    auth = AuthStore(url)
    try:
        for table, count in auth.cleanup().items():
            print(f"{table}: {count} expired records removed")
    finally:
        auth.engine.dispose()


if __name__ == "__main__":
    main()
