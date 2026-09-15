# Decision: begin with a saved-scan local checkpoint

Status: implemented, September 14, 2026.

The first checkpoint exercises the report contract and customer-visible output before connecting customer accounts. It uses FastAPI, server-rendered Jinja2, local CSS, synchronous report generation, and SQLite by default. SQLAlchemy storage also supports PostgreSQL, but PostgreSQL integration has not been exercised here. There is one fixed local demo organization and no authentication. The server refuses non-loopback peers.

These are temporary scope reductions from PLAN.md, not replacements for the MVP requirements. Authentication, Alembic migrations, Redis/Celery, live read-only AWS onboarding, pinned scanner invocation, complete HIPAA mappings, full priority scoring, Terraform validation, and deployment remain open.

Report generation preserves failed observations and never marks them fixed. Stable item IDs use organization, account, check, and resource identity. Recommendation handlers are deterministic; this checkpoint makes no runtime model calls.

## Verification

39 tests pass, plus Ruff and strict mypy. The in-app browser successfully generated and displayed the public Prowler sample. Visual inspection covered the browser report and all six sample PDF pages. Browser testing found that a no-referrer policy suppressed the Origin needed for POST forms; using same-origin preserves that signal without sending referrers off-site.

The included public fixture has two failed and three manual observations with placeholder identifiers. It does not establish live AWS behavior, full framework coverage, regulatory correctness, or deployable Terraform. Terraform CLI was unavailable; suggestions remain explicitly unvalidated.
