# Remy

Remy turns saved Prowler AWS findings into a remediation report with stable item IDs, explanations, draft HIPAA references, and suggested Terraform. Customers review and implement the recommendations themselves.

## Run locally

Requires Python 3.12 and uv.

```sh
uv sync --frozen
make dev
```

Open http://127.0.0.1:8000 and select **Generate sample report**, or import a Prowler AWS JSON-OCSF array (up to 10 MiB and 5,000 resource observations). The bundled public Prowler example contains placeholders; it is not a live or complete HIPAA scan.

Reports persist in `.remy/reports.db`. Set `REMY_DATABASE_URL` to use another SQLAlchemy database URL. For direct Uvicorn launches without that variable, `REMY_DATA_DIR` changes the default SQLite directory. `make migrate` creates the prototype table; versioned migrations remain future work.

## Implemented checkpoint

- Strict saved-scan parsing, stable organization/account/check/resource item IDs, provisional prioritization, and immutable report snapshots through the storage API.
- Every FAIL is represented, including unsupported checks. PASS and MANUAL counts are shown separately.
- Sixty recommendation check mappings (57 of the 95 pinned HIPAA framework checks); missing context is explicit. Unknown checks retain their findings without invented Terraform.
- Shared-setting warnings link related findings while preserving every item and Terraform suggestion. Older snapshots are not retroactively assessed.
- Server-rendered report history and detail pages; PDF, JSON, and ZIP downloads containing suggestions and a hash manifest.
- Loopback-only HTTP boundary, same-origin form protection, bounded uploads, escaped report content, and organization-scoped storage queries.

This is a local prototype with one fixed demo organization and no authentication. Do not deploy it as a customer-facing service. Raw uploaded files are not retained, but selected metadata and finding descriptions are persisted; heuristic redaction is not a comprehensive secret scanner.

HIPAA mappings now come from the pinned Prowler framework where available, with source links; applicability still needs review. Generated Terraform examples are checked with Terraform 1.14.0 and AWS provider 6.0.0, but not against customer state. Known template targets are compared for possible shared-setting overlaps. Related items and unknown targets are flagged in new reports and downloads; changes are not merged automatically. The ZIP is a collection of suggestions, not a combined deployment module.

## Verification

```sh
make lint
make test
make test-terraform  # Requires Terraform 1.14.0; downloads the pinned AWS provider
make coverage       # Prints framework handler coverage
```

The Terraform harness runs formatting and provider-schema validation on known, missing, and malformed identifier cases, without AWS credentials, backends, plan, or apply.

Tests cover normalization, malformed and duplicate records, stable identities, unsupported findings, tenant isolation, exports, escaping, and HTTP upload/origin boundaries.

## Next milestones

1. Reviewed HIPAA mappings and templates covering the pinned framework; broader Terraform validation scenarios and dependency/conflict handling.
2. Authentication, real organization membership, database migrations, and production security boundaries.
3. Read-only AWS onboarding, pinned Prowler execution, queued scans, completeness tracking, and explicit PASS-based finding updates.
4. Operational readiness, customer acceptance tests, and deployment.

The complete target remains in [PLAN.md](PLAN.md). GitHub integration, pull requests, and direct remediation are outside version 1.

Detailed framework gaps: [HIPAA_COVERAGE.md](docs/HIPAA_COVERAGE.md). Run `uv run python -m scripts.coverage > docs/HIPAA_COVERAGE.md` after changing handlers.
