# Remy

Remy turns saved Prowler AWS findings into a remediation report with stable item IDs, explanations, draft HIPAA references, and suggested Terraform. Customers review and implement the recommendations themselves.

## Example reports

Explore the same fictional Northstar Demo security review in three formats:

- [HTML report](examples/northstar/report.html) ([open in browser](https://jaybrownlee.com/remy/examples/report.html))
- [PDF report](examples/northstar/report.pdf)
- [JSON report](examples/northstar/report.json)

All account IDs, resource names, and findings are invented. These examples contain
three failed findings (S3 public access blocks, a single-region CloudTrail trail,
and root-account MFA) and one passed observation. They are not a real scan or a
compliance assessment. HTML, PDF, and JSON share the same report and finding IDs.

The [synthetic source scan](examples/northstar/scan.json) is included. To regenerate
the examples with the current report engine, run from this repository:

```sh
uv run python -m scripts.generate_public_examples
```

The generator uses fixed report IDs and timestamps and reads no AWS or customer
data. The files at [jaybrownlee.com/remy](https://jaybrownlee.com/remy) are copies
of these exports.

## Command-line reports

The CLI is the simplest way to use Remy. It does not require a database, account, authentication, or running server. Requires Python 3.12 and uv.

```sh
uv sync --frozen
uv run remy validate prowler-output.json
uv run remy report prowler-output.json --output ./remy-report
```

`remy report` writes four standalone artifacts by default:

- `report.html` — self-contained report for a browser.
- `report.pdf` — portable review copy.
- `report.json` — complete structured report snapshot.
- `terraform.zip` — per-finding Terraform suggestions, manifest, hashes, and report JSON.

Select one or more outputs by repeating `--format`, for example:

```sh
uv run remy report scan.json --format html --format json --output ./review
```

The output directory must not already exist unless `--force` is supplied. Forced generation replaces only Remy's named artifacts and preserves unrelated files. Remy generates all requested artifacts before writing them and never modifies the source scan.

Successful validation and complete report generation return exit code 0. CLI usage errors return 2, invalid scan input returns 3, output/configuration failures return 4, and a successfully generated report containing unsupported guidance returns 10. That last result allows CI to retain artifacts while detecting a recommendation-coverage gap.

Report and item IDs are stable for the same input and organization namespace. Supply `--organization-id UUID` when IDs should match a particular organization. Set [`SOURCE_DATE_EPOCH`](https://reproducible-builds.org/docs/source-date-epoch/) to a non-negative Unix timestamp for byte-identical HTML, JSON, PDF, and ZIP artifacts from identical inputs:

```sh
SOURCE_DATE_EPOCH=1770000000 uv run remy report scan.json --output ./remy-report
```

Remy currently consumes Prowler AWS JSON-OCSF files; it does not invoke Prowler or AWS. Inputs are limited to 10 MiB, 5,000 source records, and 5,000 expanded observations. Every malformed or duplicate observation rejects the whole input rather than producing a partial report.

## Optional web workspace

The web interface adds saved report history, organization membership, authentication, and audit records. Set it up separately:

```sh
make migrate
uv run python -m scripts.provision_user you@example.com "Your organization"
make dev
```

Open http://127.0.0.1:8000 and request a sign-in link for the provisioned address. Delivery is local-only: open the newest `.remy/mail/*.txt` file and paste its link into the same browser within 15 minutes. Confirm sign-in, then select **Generate sample report** or import a Prowler AWS JSON-OCSF array (up to 10 MiB and 5,000 resource observations). The bundled public Prowler example contains placeholders; it is not a live or complete HIPAA scan.

Authenticated SMTP delivery is also available with verified TLS, timeouts, and failed-link revocation. See [email setup and acceptance](docs/runbooks/email.md). It stays off until you explicitly select SMTP and provide credentials; no external provider has been activated.

To add another person to an existing organization, run the provisioning command with `--org-id <UUID> --role member`, using the organization UUID printed by the first command. Provisioning requires trusted operator access to the database; there is no public signup or membership-management page. An email may belong to multiple organizations; use **Switch organization** in the header. Switching rotates the session and form token without extending the original expiry. Reload forms opened before switching.

Use the same hostname when requesting and opening links: cookies distinguish `localhost` from `127.0.0.1`. Set `REMY_PUBLIC_URL` if using another loopback origin. HTTPS origins use Secure cookies; plain HTTP is allowed only for this local checkpoint. `make dev` disables access logging, and confirmation queries are removed from the ASGI scope before responses. Do not enable request-body logging or proxy logs containing sign-in URLs.

For the previous unauthenticated sample workspace, run `REMY_DEMO_MODE=1 make dev`. Old demo reports remain in the demo organization; authenticated users do not inherit them. Demo mode must never be used for customer access.

Reports persist in `.remy/reports.db`. Set `REMY_DATABASE_URL` consistently for migrations, provisioning, and the server to use another SQLAlchemy database URL. For direct Python/Uvicorn launches without that variable, `REMY_DATA_DIR` changes the default SQLite directory; Makefile commands default to `.remy/reports.db`.

`make migrate` runs versioned Alembic upgrades. Stop the server and back up an existing database before upgrading. The first revision adopts compatible prototype tables without replacing reports, users, sessions, or audit records. Startup and provisioning refuse an unversioned or outdated database; they no longer create tables or replace audit triggers. Direct server launches use `uvicorn remy.api.app:create_app --factory --host 127.0.0.1 --no-access-log`. See the [database upgrade runbook](docs/runbooks/database.md) for backup, verification, and PostgreSQL testing.

## Implemented checkpoint

- Strict saved-scan parsing, stable organization/account/check/resource item IDs, provisional prioritization, and immutable report snapshots through the storage API.
- Every FAIL is represented, including unsupported checks. PASS and MANUAL counts are shown separately.
- Ninety-eight recommendation check mappings cover all 95 pinned HIPAA framework checks plus three additional checks. Guidance includes Terraform examples, change plans requiring customer context, and manual actions. Unknown checks remain visible.
- Shared-setting warnings link related findings while preserving every item and Terraform suggestion. Older snapshots are not retroactively assessed.
- First-class, database-free `remy validate` and `remy report` commands with standalone HTML, PDF, JSON, and Terraform ZIP output, stable identities, overwrite protection, meaningful exit codes, and reproducible-build support.
- Optional server-rendered report history and detail pages with the same PDF, JSON, and ZIP exports.
- Operator-provisioned organizations and owner/member memberships, browser-bound single-use magic links, hashed session credentials, CSRF checks, and database-backed login-request limits.
- Tenant-scoped history, reports, imports, and exports. Membership is checked on every authenticated request. Login, logout, provisioning, and downloads produce audit records protected against UPDATE/DELETE by database triggers.
- Loopback-only HTTP boundary, same-origin form protection, bounded uploads, and escaped report content.

This is a local prototype, not a customer-facing service. Provider-specific email acceptance and production security boundaries remain unfinished. Database-backed tests pass on SQLite and PostgreSQL 16.15. Both membership roles currently have the same report permissions; membership administration remains operator-only. Raw uploaded files are not retained, but selected metadata and finding descriptions are persisted; heuristic redaction is not a comprehensive secret scanner.

Run `make cleanup-auth` periodically to delete up to 1,000 expired links, sessions, and rate-limit buckets per table. Repeat until counts reach zero for a backlog. Active credentials, current rate limits, reports, memberships, and audit history are retained. No background schedule is installed automatically; local mailbox files are not deleted by this command.

HIPAA mappings now come from the pinned Prowler framework where available, with source links; applicability still needs review. Generated Terraform examples are checked with Terraform 1.14.0 and AWS provider 6.0.0, but not against customer state. Known template targets are compared for possible shared-setting overlaps. Related items and unknown targets are flagged in new reports and downloads; changes are not merged automatically. The ZIP is a collection of suggestions, not a combined deployment module.

## Verification

```sh
make lint
make test
make test-terraform  # Requires Terraform 1.14.0; downloads the pinned AWS provider
make coverage       # Prints framework handler coverage
```

The Terraform harness runs formatting and provider-schema validation on known, missing, and malformed identifier cases, without AWS credentials, backends, plan, or apply.

Tests cover CLI stdout/stderr and exit codes, deterministic artifacts, overwrite protection, standalone HTML escaping, normalization, malformed and duplicate records, stable identities, unsupported findings, tenant isolation, exports, HTTP upload/origin boundaries, token expiry/replay/concurrent consumption, session revocation, CSRF, audit immutability, secure cookies, and sign-in query redaction.

## Next milestones

1. Coverage handlers now exist for every pinned framework check. Remaining recommendation work includes customer-specific Terraform generation, broader dependency/conflict handling, and regulatory applicability review.
2. Finish authentication operations: provider-specific email acceptance, membership administration, least-privilege database roles, and production security boundaries.
3. Read-only AWS onboarding, pinned Prowler execution, queued scans, completeness tracking, and explicit PASS-based finding updates.
4. Operational readiness, customer acceptance tests, and deployment.

The complete target remains in [PLAN.md](PLAN.md). GitHub integration, pull requests, and direct remediation are outside version 1.

Detailed framework gaps: [HIPAA_COVERAGE.md](docs/HIPAA_COVERAGE.md). Run `uv run python -m scripts.coverage > docs/HIPAA_COVERAGE.md` after changing handlers.
