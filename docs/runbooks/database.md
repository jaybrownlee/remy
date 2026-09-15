# Database upgrades and verification

## Local SQLite

1. Stop Remy and any provisioning commands. Protect database backups as sensitive data.
2. Create a SQLite-consistent backup with the SQLite CLI, using a new destination:

   ```sh
   sqlite3 .remy/reports.db ".backup '.remy/reports-before-0001.db'"
   sqlite3 .remy/reports-before-0001.db 'PRAGMA integrity_check;'
   ```

   Do not reuse or overwrite a prior backup filename. Confirm that integrity checking returns `ok`. If the CLI is unavailable, use SQLite's backup API; copying only the main file while a writer is active can lose WAL data.

3. Run `uv sync --frozen`, then `make migrate`. Use the same `REMY_DATABASE_URL` for migrations and the server. For a fresh database, no backup is needed.
4. Start `make dev`; verify sign-in, report history, and a download. Existing demo reports remain accessible only through explicit demo mode. Store the backup until acceptance is complete.

The baseline revision creates missing prototype tables, adopts compatible existing tables, and installs audit guards. It compares columns, types, nullability, indexes, foreign keys, unique constraints, and primary keys before adoption. Alembic comparison is not a comprehensive audit of custom CHECK constraints or trigger bodies: customized schemas require operator review. Detected drift aborts without stamping the version. No report or credential rows are replaced. SQLite can retain newly created empty schema objects after an interrupted upgrade; retry only after investigating the failure and verifying the backup.

Application startup and provisioning require the current version and do not issue schema DDL. Migration operators need DDL permissions; the eventual production runtime role must not. The migration connection is supplied directly through Alembic's [programmatic command API](https://alembic.sqlalchemy.org/en/latest/api/commands.html), so database passwords are not interpolated into a config file.

The baseline has no destructive downgrade. Recovery means stopping the application and restoring a verified backup to a separate location, checking it, then deliberately selecting that database and the matching application version. Never bypass a migration failure by stamping a database manually.

## PostgreSQL tests

CI provisions PostgreSQL 16 and supplies `REMY_TEST_POSTGRES_URL`. When this variable is present, database-backed tests run once on SQLite and once on PostgreSQL. Each PostgreSQL test creates a random `remy_test_<uuid>` schema and drops only that schema on completion. Use a dedicated disposable database and a test role with schema-creation privileges; never supply a customer or production database.

For an already running disposable PostgreSQL instance:

```sh
REMY_TEST_POSTGRES_URL='postgresql+psycopg://TEST_USER:TEST_PASSWORD@127.0.0.1:5432/TEST_DATABASE' uv run pytest -q
```

Tests exercise schema/model agreement, idempotent upgrades, concurrent token consumption, tenant-scoped reports/downloads, CSRF, session revocation, and database audit guards. PostgreSQL additionally checks TRUNCATE rejection. PostgreSQL migration operators serialize upgrades with a transaction-scoped advisory lock. Run SQLite upgrades with all application writers stopped.

Local PostgreSQL verification is pending: the Docker engine did not answer a bounded availability check. CI configuration alone is not evidence of a passing PostgreSQL run. Least-privilege PostgreSQL role tests, production backup/restore drills, and deployment readiness remain future work.
