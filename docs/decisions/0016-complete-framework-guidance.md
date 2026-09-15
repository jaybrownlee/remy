# ADR 0016: Complete pinned framework guidance with explicit change plans

- Status: Accepted
- Date: 2026-09-15

## Decision

Every one of the 95 checks in the pinned Prowler HIPAA framework now has a guidance handler. The remaining 36 checks use structured, immutable change-plan definitions grouped into monitoring, network, and service modules. The shared builder preserves each check's explanation, intended configuration change, impact, missing inputs, verification procedure, AWS reference, and pinned implementation link.

These plans describe the specific Terraform resource or operational procedure to change. They do not reconstruct a full resource from a scanner row that lacks its configuration. Certificate renewal and patch execution are manual operational workflows. Other new plans require customer context before executable Terraform can be produced.

## Review findings

- EKS encryptionConfig presence is not a reliable test for the absence of encryption on newer EKS clusters.
- SageMaker notebook key-ID absence does not establish plaintext storage.
- CloudFront's pinned HTTPS check inspects the default behavior, not every ordered behavior or the origin connection.
- Classic ELB TCP listeners may carry TLS pass-through; protocol names alone cannot establish plaintext traffic.
- CloudWatch filter/alarm presence does not prove notification delivery. Review filters, metrics, alarms, actions, and confirmed destinations together.
- EC2 enclave proxy-port detection is heuristic. The host network checks do not audit the enclave itself.
- Redshift's public-access check tests any world-facing TCP rule, not only the database port, and relies on collected network inventory.
- Config, Security Hub, and unused-resource scan settings can limit or mute observed coverage.

Each plan records the exact source at Prowler commit `73ae2eb1947a0912a05010a296f469bfa55ebe76`. AWS references were reviewed on 2026-09-15.

## Validation and remaining scope

A complete-framework report/export test verifies that all 95 findings receive guidance, remain individually identifiable, retain citations, and appear in the ZIP manifest. An additional unknown check remains unsupported. Existing Terraform examples are unchanged.

Handler coverage is complete; customer-environment validation, fuller executable templates, comprehensive shared-resource reconciliation, and regulatory applicability review remain separate work. This decision does not declare the MVP or compliance assessment complete. Authentication and organization membership are the next implementation milestone.
