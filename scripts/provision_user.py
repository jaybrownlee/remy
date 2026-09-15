"""Provision a local user and organization; run only as the database operator."""

import argparse
import os
from pathlib import Path
from uuid import UUID

from remy.auth import AuthStore


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("email")
    parser.add_argument("organization")
    parser.add_argument("--org-id", type=UUID)
    parser.add_argument("--role", choices=["owner", "member"], default="owner")
    args = parser.parse_args()
    directory = Path(os.environ.get("REMY_DATA_DIR", ".remy"))
    directory.mkdir(parents=True, exist_ok=True)
    url = os.environ.get("REMY_DATABASE_URL", f"sqlite:///{directory / 'reports.db'}")
    org = AuthStore(url).provision(args.email, args.organization, args.org_id, args.role)
    print(f"Provisioned organization membership: {org}")


if __name__ == "__main__":
    main()
