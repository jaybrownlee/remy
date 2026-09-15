# ADR 0001: Prototype application stack

- Status: Accepted
- Date: 2026-09-14

## Context

Remy needs a small, reviewable implementation of the saved-report workflow before the full
scanner, worker, authentication, and production infrastructure are built. The workflow stores
immutable report snapshots and always retrieves them within an organization boundary. It does
not connect to customer source repositories or mutate customer AWS resources.

## Decision

Use Python 3.12 managed by uv. Build the HTTP application with FastAPI, Pydantic 2, Jinja2,
python-multipart, and Uvicorn. Use ReportLab for PDF output. Use synchronous SQLAlchemy 2 for
persistence, with SQLite as the zero-configuration local database and psycopg/PostgreSQL 16 as
the compatible deployment path.

The prototype `Store` creates its report table explicitly when initialized. This is convenient
for the local saved-report workflow, but it is not a migration strategy. Introduce and document
schema migrations before operating a shared or production database.

PostgreSQL 16 and Redis 7 are available through Docker Compose for development. Redis is present
for the later background-job architecture and is not required by the local saved-report path.
No production authentication, live AWS access, Celery worker, or deployment infrastructure is
part of this prototype.

Reports are stored as immutable JSON snapshots. Their UUID is globally unique in the report
table, `org_id` is required, and every read includes `org_id`. Stable report-item UUIDs are
derived by the composition layer from the organization and finding identity; persistence keeps
those IDs unchanged.

Ruff supplies formatting and lint checks, mypy runs in strict mode over the application package,
and pytest exercises behavior. GitHub Actions installs the locked uv environment and runs the
same lint and test targets as local development.

## Consequences

Local development can run entirely on SQLite. JSON queries and other PostgreSQL-specific
behavior will need dedicated integration coverage when introduced. Automatic table creation is
intentionally limited to this prototype and must be replaced with versioned migrations before
production use.
