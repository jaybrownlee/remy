# Remy

Remy turns saved Prowler AWS findings into a remediation report with stable item IDs, explanations, draft HIPAA references, and suggested Terraform. Customers review and implement the recommendations themselves.

## Run locally

Requires Python 3.12 and uv.

```sh
uv sync --frozen
uv run python -m scripts.provision_user you@example.com "Your organization"
make dev
```

Open http://127.0.0.1:8000 and request a sign-in link for the provisioned address. Delivery is local-only: open the newest `.remy/mail/*.txt` file and paste its link into the same browser within 15 minutes. Confirm sign-in, then select **Generate sample report** or import a Prowler AWS JSON-OCSF array (up to 10 MiB and 5,000 resource observations). The bundled public Prowler example contains placeholders; it is not a live or complete HIPAA scan.

To add another person to an existing organization, run the provisioning command with `--org-id <UUID> --role member`, using the organization UUID printed by the first command. Provisioning requires trusted operator access to the database; there is no public signup or membership-management page. Use one organization per email for now; organization switching is not implemented.

Use the same hostname when requesting and opening links: cookies distinguish `localhost` from `127.0.0.1`. Set `REMY_PUBLIC_URL` if using another loopback origin. HTTPS origins use Secure cookies; plain HTTP is allowed only for this local checkpoint. `make dev` disables access logging, and confirmation queries are removed from the ASGI scope before responses. Do not enable request-body logging or proxy logs containing sign-in URLs.

For the previous unauthenticated sample workspace, run `REMY_DEMO_MODE=1 make dev`. Old demo reports remain in the demo organization; authenticated users do not inherit them. Demo mode must never be used for customer access.

Reports persist in `.remy/reports.db`. Set `REMY_DATABASE_URL` to use another SQLAlchemy database URL. For direct Uvicorn launches without that variable, `REMY_DATA_DIR` changes the default SQLite directory. `make migrate` creates the prototype table; versioned migrations remain future work.

## Implemented checkpoint

- Strict saved-scan parsing, stable organization/account/check/resource item IDs, provisional prioritization, and immutable report snapshots through the storage API.
- Every FAIL is represented, including unsupported checks. PASS and MANUAL counts are shown separately.
- Ninety-eight recommendation check mappings cover all 95 pinned HIPAA framework checks plus three additional checks. Guidance includes Terraform examples, change plans requiring customer context, and manual actions. Unknown checks remain visible.
- Shared-setting warnings link related findings while preserving every item and Terraform suggestion. Older snapshots are not retroactively assessed.
- Server-rendered report history and detail pages; PDF, JSON, and ZIP downloads containing suggestions and a hash manifest.
- Operator-provisioned organizations and owner/member memberships, browser-bound single-use magic links, hashed session credentials, CSRF checks, and database-backed login-request limits.
- Tenant-scoped history, reports, imports, and exports. Membership is checked on every authenticated request. Login, logout, provisioning, and downloads produce audit records protected against UPDATE/DELETE by database triggers.
- Loopback-only HTTP boundary, same-origin form protection, bounded uploads, and escaped report content.

This is a local prototype with development-only link delivery, not a customer-facing service. Production email, versioned migrations, PostgreSQL integration verification, session cleanup, organization switching, and production security boundaries remain unfinished. Both membership roles currently have the same report permissions; membership administration remains operator-only. Raw uploaded files are not retained, but selected metadata and finding descriptions are persisted; heuristic redaction is not a comprehensive secret scanner.

HIPAA mappings now come from the pinned Prowler framework where available, with source links; applicability still needs review. Generated Terraform examples are checked with Terraform 1.14.0 and AWS provider 6.0.0, but not against customer state. Known template targets are compared for possible shared-setting overlaps. Related items and unknown targets are flagged in new reports and downloads; changes are not merged automatically. The ZIP is a collection of suggestions, not a combined deployment module.

## Verification

```sh
make lint
make test
make test-terraform  # Requires Terraform 1.14.0; downloads the pinned AWS provider
make coverage       # Prints framework handler coverage
```

The Terraform harness runs formatting and provider-schema validation on known, missing, and malformed identifier cases, without AWS credentials, backends, plan, or apply.

Tests cover normalization, malformed and duplicate records, stable identities, unsupported findings, tenant isolation, exports, escaping, HTTP upload/origin boundaries, token expiry/replay/concurrent consumption, session revocation, CSRF, audit immutability, secure cookies, and sign-in query redaction.

## Next milestones

1. Coverage handlers now exist for every pinned framework check. Remaining recommendation work includes customer-specific Terraform generation, broader dependency/conflict handling, and regulatory applicability review.
2. Finish authentication operations: versioned database migrations, PostgreSQL verification, expired-credential cleanup, organization switching, production mail delivery, and production security boundaries.
3. Read-only AWS onboarding, pinned Prowler execution, queued scans, completeness tracking, and explicit PASS-based finding updates.
4. Operational readiness, customer acceptance tests, and deployment.

The complete target remains in [PLAN.md](PLAN.md). GitHub integration, pull requests, and direct remediation are outside version 1.

Detailed framework gaps: [HIPAA_COVERAGE.md](docs/HIPAA_COVERAGE.md). Run `uv run python -m scripts.coverage > docs/HIPAA_COVERAGE.md` after changing handlers.
