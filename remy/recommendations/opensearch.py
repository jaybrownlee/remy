"""OpenSearch encryption guidance based on the pinned Prowler checks."""

# Keep report prose readable in source.
# ruff: noqa: E501

from collections.abc import Callable

from remy.reports.schema import Citation, Observation, Recommendation

_AWS_BASE = "https://docs.aws.amazon.com/opensearch-service/latest/developerguide/"


def encryption(observation: Observation) -> Recommendation:
    at_rest = observation.check_id == "opensearch_service_domains_encryption_at_rest_enabled"
    setting = "encryption at rest" if at_rest else "node-to-node encryption"
    argument = "encrypt_at_rest" if at_rest else "node_to_node_encryption"
    reference = _AWS_BASE + ("encryption-at-rest.html" if at_rest else "ntn.html")
    return Recommendation(
        status="needs_context",
        what=f"Prowler observed that {setting} is disabled on the reported OpenSearch domain.",
        why=(
            "Encryption at rest protects domain storage. Manual snapshot repositories and exported CloudWatch logs need separate encryption settings."
            if at_rest
            else "Node-to-node encryption protects communications within the domain. Client HTTPS enforcement is a separate setting and must also be reviewed."
        ),
        change=f"In the existing owning aws_opensearch_domain configuration, set {argument}.enabled to true after confirming engine and deployment compatibility. Reconcile both encryption findings into one complete domain update.",
        impact=(
            "The setting cannot be disabled after enablement. Review update capacity, performance, recovery, and engine compatibility before scheduling the change."
            + (
                " Choose the KMS key carefully: loss of key access can make the domain inaccessible. Existing UltraWarm or cold data requires a storage-tier migration before enablement."
                if at_rest
                else " Review client HTTPS and fine-grained access control alongside internal transport protection."
            )
        ),
        citations=[
            Citation(
                section="45 CFR 164.312(a)(2)(iv)" if at_rest else "45 CFR 164.312(e)(1)",
                title="Encryption and decryption" if at_rest else "Transmission security",
                url="https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.312",
                confidence="low",
                note="Draft safeguard mapping for reviewer assessment; this finding alone does not establish HIPAA noncompliance.",
            )
        ],
        terraform=None,
        filename=None,
        assumptions=[
            "The saved observation does not contain the full domain configuration, engine version, storage tiers, capacity, policies, snapshots, clients, or Terraform state. No partial aws_opensearch_domain resource is emitted.",
            f"Prowler 5.42.0 tests the collected {setting} boolean; it does not establish migration readiness or complete encryption coverage.",
            "Existing-domain enablement requires OpenSearch or Elasticsearch 6.7 or later; assess upgrades or migration for unsupported deployments.",
        ],
        steps=[
            "Retrieve the complete domain configuration and identify its owning workspace, engine, node types, storage tiers, indexes, clients, snapshots, and recovery requirements.",
            *(
                [
                    "Select a supported symmetric KMS key and review permissions, grants, monitoring, and recovery. Preserve warm and cold indexes by moving them to adequately sized hot storage before disabling those tiers; re-enable tiers after encryption is enabled.",
                    "Protect manual snapshot repositories and exported log groups separately, and configure KMSKeyError and KMSKeyInaccessible alarms.",
                ]
                if at_rest
                else [
                    "Review domain endpoint HTTPS enforcement and fine-grained access control; internal encryption alone does not require clients to use HTTPS.",
                ]
            ),
            f"Update {argument}.enabled in the complete owning resource. For an unmanaged existing domain, import only after confirming ownership and reconstructing its full configuration.",
            "Review the proposed update and test on a representative domain. Verify snapshots and a recovery path before scheduling production enablement; do not assume toggling the flag back provides rollback.",
            "Monitor domain health, application queries and indexing, verify the effective encryption settings, and rerun both checks.",
            f"AWS reference: {reference}",
        ],
    )


OPENSEARCH_BUILDERS: dict[str, Callable[[Observation], Recommendation]] = {
    "opensearch_service_domains_encryption_at_rest_enabled": encryption,
    "opensearch_service_domains_node_to_node_encryption_enabled": encryption,
}
