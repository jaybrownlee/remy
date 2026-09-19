# ADR 0017: A database-free CLI is a first-class report interface

- Status: Accepted
- Date: 2026-09-19

## Decision

Remy provides a packaged `remy` console command alongside the optional web workspace. `remy validate` checks a saved Prowler AWS JSON-OCSF file without writing state. `remy report` runs the same strict parser, recommendation catalog, prioritization, coordination, and export code used by the web application.

One-shot CLI reporting does not require a database, user, organization membership, authentication, network access, or server process. It writes a self-contained HTML report, PDF, structured JSON snapshot, and Terraform guidance ZIP by default. Users may select formats individually. The source scan is read but never changed.

The CLI uses a documented standalone UUID namespace unless an organization UUID is supplied. A report ID derives from the organization namespace and source SHA-256; item IDs continue to derive from the organization and finding identity. Normal CLI generation records the current time. When `SOURCE_DATE_EPOCH` is supplied, Remy uses that timestamp and deterministic PDF and ZIP metadata, making every artifact byte-identical for the same source, organization, timestamp, and Remy version.

An existing output directory is rejected by default. `--force` replaces only the requested Remy artifact names and preserves unrelated files. Requested artifact bytes are generated before filesystem writes and staged as temporary sibling files before replacement. This avoids publishing an artifact that failed during rendering, though filesystem or power failures during the final series of replacements can still leave a mixed prior/new set. CI should generate into a new directory.

## Exit status contract

- 0: validation succeeded, or a report was generated without unsupported guidance.
- 2: command-line syntax or option error.
- 3: unreadable, oversized, malformed, unsupported-provider, duplicate, or otherwise invalid scan input.
- 4: output or reproducibility-configuration failure.
- 10: report artifacts were generated, but at least one failed finding has unsupported guidance.

`needs_context` and `manual_action` are handled recommendations and do not cause status 10. They remain visible in all report formats.

## Scope

The CLI consumes Prowler output; it does not invoke Prowler, select AWS credentials, or claim that the input represents a complete scan. A later `remy scan` command may wrap a pinned Prowler execution only after AWS profile/role selection, coverage capture, timeouts, subprocess isolation, and failure semantics are designed and tested.

The web workspace remains useful for durable history, organization isolation, authentication, and audit logging. Neither interface applies Terraform or changes AWS resources.
