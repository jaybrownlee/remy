# ADR 0015: Reconcile OpenSearch encryption changes by domain

- Status: Accepted
- Date: 2026-09-15

## Decision

Both pinned OpenSearch encryption checks receive guidance to update the existing domain's owning configuration. The report does not contain enough domain state to generate a complete resource. Related encryption findings are linked when a validated domain ARN matches the observation's account and Region, including when no Terraform file is emitted.

Existing domains running OpenSearch or Elasticsearch 6.7 or later support enablement. Both settings are irreversible on that domain. At-rest enablement also requires review of instance types, KMS access, and UltraWarm/cold storage. Client HTTPS, manual snapshot storage, and exported logs need separate assessment.

## Sources

- [AWS storage encryption](https://docs.aws.amazon.com/opensearch-service/latest/developerguide/encryption-at-rest.html)
- [AWS node-to-node encryption](https://docs.aws.amazon.com/opensearch-service/latest/developerguide/ntn.html)
- Prowler check implementations reviewed at commit `73ae2eb1947a0912a05010a296f469bfa55ebe76`; both evaluate their collected encryption boolean.

## Validation

Report/export integration checks preserve both findings, group the shared domain, and reject account-mismatched ARNs. No new Terraform is emitted.
