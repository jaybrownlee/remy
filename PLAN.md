# Remy Version 1 Development Plan
Remediation reports with suggested Terraform
Version 1.2 • September 14, 2026 • Owner Jay Brownlee

Remy Version 1 produces a remediation report for AWS resources that fail the selected HIPAA scan checks. Each report item explains the finding, identifies the applicable HIPAA provisions, and provides a close approximation of the Terraform configuration needed to address it. The customer can read, download, adapt, and use the report without connecting a source-code repository.
The customer decides how to implement the recommendations. Remy reads configuration and generates guidance. It does not create pull requests, require GitHub, apply Terraform, or change customer AWS resources in this MVP.
This revision replaces the prior Version 1.1 plan. It retains task identifiers T0–T13 while changing the delivery model from approved S3 pull requests to a report covering every failed check in the selected Prowler hipaa_aws framework. A finding is a failed technical check; it is not by itself a determination of overall HIPAA noncompliance.
## What each report item contains
- A stable item ID, affected account and resource, check name, severity, and priority reasons.
- A plain-language explanation of the observed configuration and why it matters.
- Applicable HIPAA citations with source links, mapping confidence, and a clear distinction between current requirements and any proposed rule.
- Suggested Terraform, including known resource values, explicit placeholders, assumptions, dependencies, and potential impacts.
- Customer review and verification steps. When Terraform cannot perform the fix, the item explains the manual action or missing information rather than inventing code.
## Changes from the previous plan
| Area | Revised MVP requirement |
| --- | --- |
| Delivery | In-app remediation report and PDF/JSON/Terraform downloads. No repository connection or pull request. |
| Coverage | Every failed check gets a report item; Terraform guidance extends beyond the former S3-only scope. |
| Customer workflow | No per-resource approval flow is required to generate a report. Customers review and implement recommendations externally. |
| Report engine | Compose, version, and export reports. Remove approval, branch, merge, and PR publication states. |
| Status | Report generation does not mark findings fixed. A subsequent explicit scan PASS records the observed improvement. |
| Future CLI | Preserve stable item IDs for a later command that requests automatic remediation of a specified item. Execution is deferred. |
## MVP completion
The MVP is complete when a customer can connect an AWS account read-only, run a scan, obtain the report with every failed check represented, and download its recommendations without GitHub or Terraform expertise being required to use Remy itself. The generated Terraform is reviewable guidance, not a guaranteed deployment-ready patch or a claim of full regulatory compliance.
---
# 1 Architecture and customer access
## Product boundaries
Prowler supplies scanner results. Remy normalizes them, relates them to reviewed HIPAA mappings, prioritizes them, and assembles actionable report items. The report must remain useful to a reader who has no GitHub account and no existing Terraform repository. Explain technical terms and include instructions that can be handed to an administrator.
| Layer | MVP choice |
| --- | --- |
| Language and API | Python 3.12; FastAPI; Pydantic v2; sync SQLAlchemy 2.x; Alembic. |
| Data and workers | PostgreSQL 16; Redis 7; Celery by default. Scans and report generation run as background jobs. |
| Scanner | Pin a compatible Prowler 5.x release. Verify invocation and output behavior for that version. |
| AWS integration | boto3 sessions and customer metadata reads centralized under remy/aws/. |
| Recommendation output | Reviewed Jinja2 Terraform templates, parameter schemas, and explanation templates. No runtime LLM dependency is required for MVP. |
| Frontend | Server-rendered Jinja2, HTMX, and Tailwind, with production CSS built locally. |
| Authentication | Email magic links by default; own implementation unless Jay chooses the alternative. |
| Hosting | Single-region us-east-1 ECS Fargate, RDS, ElastiCache, ALB, S3, KMS, and Secrets Manager. |
| Export | PDF report, versioned JSON report, and ZIP containing suggested .tf files plus a README and item manifest. |
## Read role and onboarding
Provide Terraform and CloudFormation templates for RemyReadRole only. The customer can choose either onboarding method. Explain how to install the role and verify the connection; there is no repository prerequisite. Trust is restricted to Remy's AWS account with a per-customer ExternalId.
Use the original SecurityAudit and job-function/ViewOnlyAccess policy baseline, verifying effective permissions against the pinned scanner and metadata-only requirements before release. Any additional read permission requires a documented reason, IAM changelog entry, and policy test. Customer mutation permissions are excluded.
Expose read_session(account). Validate sts:GetCallerIdentity and account binding; retain last_verified_at. Protect ExternalId and account selection against cross-tenant substitution. Do not implement remediate_session, remediate_role_arn, customer write-session approval tags, or a write-role onboarding path.
## Remy operational access
Remy's own workload identity may write raw scan output and generated reports to Remy's storage and use its supporting services. Keep these operational sessions separate from assumed customer sessions. Neither Prowler nor report-generation subprocesses receive customer write credentials. Never read customer object contents or retain PHI.
Keep remy/api, core, aws, ingest, mapping, prioritize, reports, recommendations, evidence, db, and workers; tests/unit, tests/integration, tests/fixtures; infra; customer-iam; and docs. Replace the prior PR-oriented engine and iac package design with reports and recommendations. GitHub Actions may still host Remy's own CI; it is not a customer product integration.
---
# 2 Report contract and item identity
## Required item fields
Every failed check/resource pair in a successfully ingested scan must appear in the report. Several findings on the same resource remain individually identifiable. Shared Terraform changes can be referenced from multiple items, but no finding may disappear through grouping.
| Field group | Required information |
| --- | --- |
| Identity | Stable item_id, report_id and revision, organization/account, check_id, resource UID/name, service, and region. |
| Observation | Source scan ID/time/version, FAIL status, scanner detail, and metadata evidence with sensitive fields excluded. |
| Explanation | What failed, why it matters, what the recommendation changes, and what could be affected. |
| Regulation | Current HIPAA citations, source links/date, required/addressable designation when verified, and mapping confidence. |
| Terraform | Recommendation status, template/version, suggested configuration or an explicit reason code cannot be supplied. |
| Inputs | Known values, required placeholders, assumptions, dependencies, resource ownership/state caveats, and missing metadata. |
| Customer action | Review/adaptation steps, manual prerequisites, impact notes, and post-change verification instructions. |
## Coverage and recommendation status
Use terraform_guidance when a reviewed template can express the technical change with explicit inputs. Use needs_context when resource ownership or essential configuration is unknown; provide a useful partial template only when its limits can be stated accurately. Use manual_action when Terraform cannot perform the required action. Use unsupported only for an actual template coverage gap, with the reason visible.
Before MVP acceptance, every check in the pinned hipaa_aws inventory must be reviewed and assigned a recommendation strategy. An unsupported gap on a Terraform-addressable check blocks coverage acceptance. Manual and context-dependent cases are legitimate outcomes, but must contain actionable guidance; they cannot be used to hide unimplemented templates.
## Stable item IDs
Assign an opaque UUID item_id to each organization-scoped finding identity, backed by a unique key on org_id, aws_account_id, check_id, and resource_uid. Retain the ID across repeated scans, reports, resolution, and recurrence. Do not use the report row number as identity. IDs are never reused for a different finding or resource.
A report has its own UUID and immutable revision. Store each item version with its scan inputs, mapping/template versions, and content hash. Display a friendly line number for readability alongside the full copyable item ID. Downloads include both. An item ID identifies a record; it grants no authority to access or change it.
## Delivery and lifecycle
Report lifecycle: queued → generating → ready or failed. A report with source-data limitations must display them prominently. Failed or incomplete scans do not produce an apparently complete report. Retrying generation is idempotent for its job key; regenerating with new inputs creates a new revision, preserving earlier output.
“Ready” means the report was generated. Recommendation status describes the guidance. Finding status describes observed scan results. Keep these concepts separate. No approval, publishing, PR-open, merged, applied, or rolled-back states belong to the MVP report workflow.
---
# 3 Terraform guidance and regulatory mapping
## Terraform quality contract
Produce a close approximation of the desired resource configuration using reviewed, versioned templates and structured metadata. Fill values confirmed by the scan; mark unknown IDs, regions, resource references, keys, networks, and policy inputs as named variables or explicit placeholders. Never invent an ARN or silently choose a destructive replacement.
Label code “Suggested Terraform — review and adapt before applying.” Explain that fmt/validate results do not prove a safe deployment or compatibility with existing Terraform state. Do not claim that the customer can copy every snippet into a workspace and apply it unchanged.
Each item identifies the intended Terraform resource or argument change, potential disruption, ordering dependencies, and manual prerequisites. Describe how to adapt the guidance for an already-managed resource versus existing infrastructure outside Terraform. Import guidance is conditional on existence and ownership; do not emit unconditional imports for unknown or nonexistent targets.
Check for duplicate and conflicting recommendations within a report. Share one configuration asset for identical changes and list all related item IDs. For incompatible suggestions, explain the conflict and require customer review. The ZIP presents separate item/shared directories, not one root configuration that implies every suggestion can be applied together.
Run terraform fmt and validate representative rendered configurations in an isolated harness using a pinned provider, stub references, no customer credentials, and no remote backend. Validate actual downloadable files where feasible. Record exactly what was checked and distinguish example validation from customer-environment validation. Invalid code is never labeled validated.
## Coverage beyond S3
Start the template library with S3 as a tested pattern, then cover the pinned framework's Terraform-addressable checks across services. Build the inventory from that framework rather than a guessed check count. Examples of likely groups include storage configuration, network exposure, logging, encryption, and identity settings; actual scope follows the inventory.
Safety concerns such as intentional public website hosting appear as context and impact notes in the report. They may prevent a confident automated recommendation, but they do not remove the finding from the report. For S3, describe applicable public-access-block flags, policy/ACL context, and account-level impact without reading objects or assuming every public bucket should be made private.
## HIPAA interpretation and copy
Vendor the pinned Prowler mapping, then curate it against primary government sources. Every item includes applicable provisions or an explicit low-confidence mapping that needs review. Record source links, retrieval dates, and reviewer decisions. Do not assert that a failed scanner check alone proves a reportable breach or legal violation.
Provide complete explanations for all reportable failures, expanding the former “S3 plus top 25” requirement. Separate current_rule from proposed_rule information and verify rulemaking status before publication. Tests catch copy that presents proposals as enforceable requirements; Jay reviews the mapping before merge. Unknown interpretations are visible rather than replaced with fabricated certainty.
Scoring retains the original weights: base direct 60, credential 50, visibility 35, hygiene 15; internet reachability ×1.5; account-wide impact ×1.3; new failure within seven days +5; final score capped at 100. Document rounding, derive reachability only from available finding metadata, and show the actual priority reasons.
---
# 4 Data model and scan history
## Persistent records
Use UUID keys, explicit tenant scoping, timestamps, and database constraints. All API routes, background jobs, exports, and item lookups enforce org_id; no user may retrieve another organization's report through an item ID.
| Entity | Required information |
| --- | --- |
| orgs and users | Organization, informational baa_signed_at, user email, and owner/member role. |
| aws_accounts | Account ID, read role ARN, ExternalId, regions, connection status, last_verified_at. |
| scans | Account, framework and coverage, Prowler version, status, start/end times, raw output key, summary, sanitized errors. |
| findings | Immutable per-scan check/resource observations, scanner status, severity, service, region, and allowlisted metadata. |
| finding_states | Stable item_id, identity key/fingerprint, current status, first/last failure, resolution, whitelist/reason, score/reasons, last scan. |
| reports | Report UUID, revision, source scan, generation status, generation time, mapping/template versions, and export references. |
| report_items | Report/revision, stable item_id, observation reference, explanation, regulation mapping, guidance status, inputs, warnings, content hash. |
| recommendation_assets | Suggested .tf files, README/manifest, related item IDs, template version, validation scope/result, and content hash. |
| audit_log | Actor, org_id, action, target, timestamp, request/job ID, and redacted metadata. Database rejects UPDATE and DELETE. |
## Observation and resolution rules
Fingerprint remains sha256(account_id|check_id|resource_uid), with every lookup also scoped to the organization. Preserve first/last failure and historical resolution events. A recurring FAIL reopens the same item; earlier reports remain immutable snapshots of their generation-time observations.
An explicit PASS in a successful, comparably scoped later scan resolves the observed finding with resolved_by=scan. Report generation, download, or a user saying they applied the guidance cannot resolve it. Missing, MANUAL, partial, or failed scan results leave the item unverified. Absence alone is not proof of a fix or deletion; confirmed resource deletion is recorded separately.
A later PASS does not prove the customer used Remy's suggestion. Display “Passed on scan <date>” and link the scan; avoid claims that Remy performed or caused the fix. No customer application timestamp exists unless introduced as a clearly labeled self-report in a later product decision.
## Metadata and evidence
Retain scanner configuration metadata and generation-time evidence sufficient to explain the recommendation. Exclude object contents, secrets, and content-bearing payloads. Use allowlists and recursive checks; do not rely only on denying a few field names. Protect policy documents in storage and redact them from ordinary logs.
Store report outputs with tenant authorization, encryption, and immutable revision references. Evidence in the MVP is the observed finding, reviewed guidance, validation scope, and subsequent scan history. There is no approval signature, deployment transaction, rollback snapshot, or PR merge record.
Whitelisting requires an audit-logged reason and never means technically compliant. Reports include whitelisted failed items clearly labeled so the full set of failures remains accounted for; filters may hide them in the UI without deleting them from the complete export.
---
# 5 Tasks T0 through T4
Implement T0–T13 in order, with one internal development PR per task where the development repository uses PRs. This does not create a GitHub dependency for Remy's customers. Every task requires passing CI, a plain-language CHANGELOG.md entry, no new # type: ignore, and an IAM entry for every permission change.
## T0 Repo scaffold and CI
Create pyproject.toml using uv by default, packages, docker-compose.yml for Postgres/Redis, Makefile, CI, and docs/decisions/0001-stack.md. Use reports and recommendations packages in place of the PR delivery engine.
Acceptance: make dev starts the API on port 8000 and /healthz returns ok, db, redis as true. Provide make test/lint/migrate; CI runs ruff, mypy, pytest, and Terraform formatting/validation for template fixtures. Pin dependencies and provider/tool versions. No customer GitHub setup or credential is required to start the app.
## T1 Tenancy users and audit log
Implement organizations, users, and expiring single-use magic-link login. Login is audit-logged. Reject audit-log UPDATE/DELETE at the database boundary and carry org_id into workers.
Acceptance: tests cover token expiry/replay, account access, report/item retrieval, downloads, and attempted cross-tenant access by guessed or known IDs. Document the authentication choice in docs/decisions/0002-auth.md.
## T2 Read role templates and connection
Provide Terraform and CloudFormation templates for RemyReadRole, with customer-specific ExternalId, and /app/accounts/new. Centralize sessions in remy/aws/session.py.
Acceptance: Verify connection calls sts:GetCallerIdentity, checks account binding, and stores last_verified_at. Golden tests cover role trust and read policies. No customer write role, remediate_session, repository connection, or GitHub token is requested. Record all policy attachments and trust permissions in the IAM changelog.
## T3 Prowler runner
Run Prowler as a Celery task with a 30-minute timeout. Verify exact hipaa_aws/json-ocsf, role, ExternalId, region, and output flags and exit-code meanings against the pinned release; record them in docs/decisions/0003-prowler-invocation.md.
Acceptance: retain scan version and coverage; store raw configuration output in Remy's SSE-KMS bucket using its operational identity; sanitize failure tails. Mock subprocess tests cover complete scans with findings, errors, timeouts, and partial coverage. Use authentic redacted Prowler fixtures from a sandbox, not invented OCSF.
## T4 Normalizer and stable item identity
Parse observations into findings and maintain finding_states and item_id according to section 4. Tolerate unknown fields; fail explicitly on missing check/resource/status. Optional-field omissions cannot silently turn a partial scan into a complete one.
Acceptance: test FAIL → FAIL → PASS and recurrence, MANUAL, missing records, changed coverage, failed scans, and duplicate ingestion. The same finding keeps the same item ID across reports and scans; different tenants cannot collide or read each other's records. Neither report generation nor absence produces a false resolution.
---
# 6 Tasks T5 through T8
## T5 HIPAA mapping and explanations
Build remy/mapping/hipaa.yaml, its schema/loader, and the vendored pinned hipaa_aws mapping. Provide all four explanation fields for every reportable check, including non-S3 findings. Preserve source links, dates, confidence, and current-versus-proposed distinctions.
Acceptance: inventory coverage tests require a reviewed mapping and explanation for every check. Unknown interpretations are visibly low-confidence. Tests reject promises that Remy applies fixes, statements that proposals are current law, and blanket declarations of breach or full compliance. Leave the mapping change for Jay's review before merge; record source verification decisions.
## T6 Prioritization
Implement a pure score function returning an integer and human-readable reasons using section 3's weights. Derive internet reachability only from available Prowler fields; distinguish unknown from known private.
Acceptance: table-driven tests cover each factor, cap, documented rounding, the seven-day boundary, and missing metadata. Reports order by priority with a deterministic tie-breaker and preserve item identity independently of displayed position.
## T7 Findings and report UI
Provide the findings list/detail plus /app/reports and /app/reports/<id>. Users select a completed scan, choose “Generate remediation report,” view generation progress, read the report, and download PDF, JSON, or Terraform guidance ZIP.
Acceptance: every failed finding appears with item ID, plain-language explanation, regulation mapping, guidance status, and suggested code or an actionable reason no code is available. Provide service/status/priority filters, copyable IDs and Terraform, clear placeholders, and understandable impact notes. Full exports retain all failed items, including explicitly whitelisted items.
There is no GitHub connection, approval, PR creation, apply, or rollback control. A nontechnical user can obtain the complete report without a repository. Reuse tenant/account/priority indexes; paginated findings render in under 500 ms with 2,000 findings in the documented test environment. Large report generation runs in the worker rather than blocking the request.
## T8 Report composition and versioning
Implement remy/reports/{schema,compose,service}.py and worker jobs. Compose each item from a specific scan observation, reviewed mapping, recommendation strategy, and template inputs. Capture input and content hashes; preserve immutable revisions and generation-time evidence.
Acceptance: test queued/generating/ready/failed transitions, idempotent retry, regeneration into a new revision, every-failure coverage, missing-data labeling, and tenant isolation. A mocked recommendation provider supports tests before T9. Generation errors are visible and cannot produce an apparently complete ready report with silently missing items.
Separate guidance status from report status and observed finding status. Report or download events never mark a finding resolved. A user-triggered later scan updates current history without rewriting old reports. Add audit events for generation, view/download where appropriate, and errors. No approval or PR state machine survives this task.
---
# 7 Tasks T9 and T10
## T9 Recommendation catalog and suggested Terraform
Replace the former S3 direct-remediation task with remy/recommendations/{catalog,inputs,render,validate}.py, versioned templates, and test fixtures. Inventory all checks in the pinned hipaa_aws framework and map each to Terraform guidance, context-dependent guidance, or a justified manual action.
Start with S3 to establish template conventions, then complete coverage for the remaining Terraform-addressable checks. Map known metadata into code; expose unknowns as explicit inputs. Every item must explain its intended effect, applicability, dependencies, and potential disruption. Never fabricate a complete configuration from insufficient evidence.
Acceptance: a coverage manifest accounts for every check. Golden tests exercise representative known-input, missing-input, manual-action, and context-dependent cases for each template family. Real scan fixtures demonstrate resource identifiers are mapped correctly. All complete examples pass the documented Terraform validation harness. Unsupported Terraform-addressable checks remain an explicit release blocker rather than being mislabeled manual.
S3 tests cover deliberate public websites, CloudFront-related context, bucket versus account-wide impact, missing/denied public-access configuration, and existing-versus-new resource guidance. These conditions must produce explanatory report items, even when the right change cannot be determined. No object reads or customer mutation occurs.
Do not clone a repository, infer existing Terraform ownership from GitHub, or generate deployment-ready patches against customer files. Provide adaptation instructions for importing or updating resources and make state/ownership assumptions visible.
## T10 Report downloads and Terraform bundle
Replace the prior GitHub integration task with export generation. Provide PDF and versioned JSON reports plus a ZIP of suggested .tf assets, a README, and a machine-readable manifest linking assets to report revisions and stable item IDs.
Acceptance: every exported report item retains explanation, citation/source, recommendation status, known values/placeholders, impact notes, and verification steps. Each asset has a safe path and content hash. Shared changes reference all related items. Conflicting suggestions are flagged and are not combined into an apparently executable root module.
The README explains how to identify an item, review the Terraform, substitute inputs, reconcile existing state, run the customer's own Terraform plan, and validate the resulting change. Explain that code snippets may require adaptation and that some actions remain manual. Customers can hand the PDF or ZIP to their administrator without using GitHub.
Test JSON schema/versioning, ZIP traversal protection, missing inputs, duplicate/shared assets, conflicts, large reports, and tenant authorization. Escape untrusted scanner text in HTML/PDF. Render and inspect representative PDFs including long resource names, long code, and manual-action items. Downloads are audit-logged; exports contain only allowlisted metadata.
No GitHub App, repository token, PyGithub client, branch creation, pull request, merge tracking, or customer pipeline integration is implemented.
---
# 8 Tasks T11 through T13
## T11 Report evidence and scan comparison
Provide /app/items/<item_id> with the observed finding timeline, report revisions that include the item, guidance versions, and later scan results. The report remains an immutable historical snapshot; the item page shows the latest observed state.
Acceptance: demonstrate pending/FAIL, later PASS, MANUAL, missing/partial scan, and recurrence. Only eligible explicit PASS resolves the finding with resolved_by=scan. Show when it passed without claiming Remy executed or caused a change. An item ID remains stable and copyable; cross-tenant access is denied. There is no approver, deployment timestamp, rollback event, or PR reference in required evidence.
## T12 Remy infrastructure
Provision ECS Fargate API/worker, encrypted private RDS with 35-day backups, ElastiCache TLS/authentication, ALB/ACM, Secrets Manager, KMS, CloudTrail, CloudWatch, and required endpoints/egress. Remy's runtime assumes only customer read roles; keep operational storage writes separate.
Retain the original raw-output bucket target of SSE-KMS, versioning, blocked public access, and a 400-day lifecycle. Protect report downloads and revision storage similarly. Preserve the six-year audit retention target as a product requirement pending verification of its legal basis; select a supported retention setting meeting that target.
Acceptance: Terraform checks and safe CI planning pass, tfsec/checkov report no HIGH findings, and docs/runbooks/deploy.md covers secrets, migrations, backup/restore, storage, and job failures. A manual scan of Remy's deployment has no direct or credential class failures under the reviewed mapping. Remove GitHub App secrets and customer repository integration from infrastructure requirements.
## T13 MVP acceptance
Jay executes docs/runbooks/m1-acceptance.md using a sandbox with representative findings across multiple services and authentic fixtures for conditions unsuitable to create live. All coverage claims must reconcile to the pinned framework inventory.
1. Connect with only RemyReadRole; run a manual scan. No GitHub account, repository, or customer write credential is requested.
2. Generate a report. Every failed check/resource pair is represented, prioritized, and assigned a stable item ID.
3. Inspect S3 and non-S3 items for clear explanations, source-backed HIPAA mapping, and appropriate suggested Terraform or justified manual/context-dependent guidance.
4. Confirm intentional public delivery, unknown inputs, and incomplete metadata are visibly explained rather than silently omitted or filled with invented values.
5. Download PDF, JSON, and Terraform ZIP. Verify completeness, readable layout, safe files, item/asset links, and validation labels. Use the outputs without GitHub.
6. An administrator adapts and applies one suitable suggestion in the sandbox using their own workflow. Rescan and observe PASS on the same item ID; Remy records scan evidence only.
7. Verify failed/partial scans, missing observations, downloads, and report generation cannot mark findings fixed. Test recurrence and immutable historical reports.
8. Check cross-tenant access denial and audit events. Confirm Remy made no customer AWS mutation and exposes no apply, approval, rollback, or PR interface.
MVP acceptance requires all checks to pass and Jay's sign-off. Any unimplemented Terraform-addressable check must be resolved or explicitly removed from the selected scan scope by a separate product decision.
---
# 9 Future CLI and implementation controls
## Later automatic remediation by item ID
Preserve item identity now so a later Remy CLI can accept an item ID and a command requesting automatic remediation of that specific item. Illustrative future syntax is remy remediate <item-id>; command naming and execution behavior remain a later design decision. No CLI executor ships in the MVP.
The future implementation must authenticate the user, enforce tenant/account ownership, fetch the current item and recommendation revision, reread live configuration, and validate support and impact before execution. An old report or item ID alone cannot authorize a write. Approval, customer write-role design, stale-input checks, execution verification, audit attribution, and recovery require a separate design before that feature is enabled.
Do not reserve operational credentials or add a dormant apply path in Version 1. Store stable IDs and recommendation versions without pretending a suggested Terraform snippet is a safe automatic executor. Not every report item will necessarily become automatically remediable.
## Quality and implementation discipline
Use pytest, moto, SDK stubs, and authentic redacted scanner fixtures. Apply strict typing and at least 90 percent line coverage to report composition and recommendation rendering, with branch coverage on missing inputs, coverage checks, template selection, validation labels, and status transitions.
Guardrails enforce centralized customer sessions, no customer mutations, no object content collection, no Terraform apply subprocess, and no customer repository/PR integration. Test session capabilities and side effects in addition to source checks. Separate operational AWS writes to Remy's storage from customer reads.
Use structured JSON logs with organization and request/job IDs; redact secrets and policy documents. Keep IAM golden files, template versions, and mapping provenance under review. Every task has an understandable changelog entry; permission changes are explicitly recorded under IAM.
## Deferred and retained decisions
Direct remediation and the item-based CLI are future work. Also defer scheduled scans/alerts, bulk execution, Security Hub ingestion, multi-region deployment, SSO/SAML, Marketplace, GitLab/Bitbucket/GitHub product integrations, PHI discovery, host agents, non-HIPAA frameworks, Azure/GCP, and a Prowler SDK migration.
The report-first boundary, GitHub independence, and coverage beyond S3 are settled by this revision. Retain the existing defaults for Celery and own magic-link authentication unless Jay chooses alternatives. Account-level findings remain reportable; warnings and guidance reflect their wider impact. There is no separate decision needed to permit an account-level write in the MVP because Remy performs none.
## Source verification during implementation
This revision incorporates Jay's annotation on the September 14 Version 1.1 plan. The original September 13 plan remains background for stack defaults and Prowler integration, with PR and direct-execution requirements superseded here.
Verify Prowler package compatibility and CLI behavior at pypi.org/project/prowler/ and docs.prowler.com; vendor hipaa_aws.json from the pinned Prowler release. Verify regulatory mappings against current eCFR Part 164 Subpart C and primary HHS/OCR and Federal Register sources. Verify each Terraform template and import instruction against its pinned provider documentation and tests. Record source dates and decisions before publishing claims to customers.
