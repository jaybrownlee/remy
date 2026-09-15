"""Reviewed guidance for EC2 and EBS findings that require live topology."""

# The guidance remains readable as complete prose in source.
# ruff: noqa: E501

from collections.abc import Callable

from remy.reports.schema import Citation, Observation, Recommendation

_ECFR_308 = (
    "https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/"
    "subpart-C/section-164.308"
)
_ECFR_312 = (
    "https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/"
    "subpart-C/section-164.312"
)
_AWS_EBS_SHARING = (
    "https://docs.aws.amazon.com/ebs/latest/userguide/ebs-modifying-snapshot-permissions.html"
)
_AWS_EBS_COPY = "https://docs.aws.amazon.com/ebs/latest/userguide/ebs-copying-volume.html"
_AWS_PUBLIC_IP = (
    "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/working-with-ip-addresses.html"
)
_AWS_SSM_NODES = (
    "https://docs.aws.amazon.com/systems-manager/latest/userguide/"
    "systems-manager-setting-up-nodes.html"
)
_AWS_SSM_ENDPOINTS = (
    "https://docs.aws.amazon.com/systems-manager/latest/userguide/setup-create-vpc.html"
)


def _citation(section: str, title: str, url: str) -> Citation:
    return Citation(
        section=section,
        title=title,
        url=url,
        confidence="low",
        note=(
            "Draft safeguard mapping for reviewer assessment; this finding alone does not "
            "establish HIPAA noncompliance."
        ),
    )


def _resource(observation: Observation, kind: str) -> str:
    return observation.resource_name.strip() or f"the reported {kind}"


def ebs_public_snapshot(observation: Observation) -> Recommendation:
    name = _resource(observation, "EBS snapshot")
    return Recommendation(
        status="manual_action",
        what=f"Prowler observed that {name} grants createVolumePermission to the all group.",
        why=(
            "A public EBS snapshot can be used by any AWS account to create volumes containing its data. The finding establishes public visibility, not whether another account copied it."
        ),
        change=(
            "Confirm the owner and intended recipients, investigate the exposure window, remove the all-group create-volume permission, and retain only explicitly approved account sharing."
        ),
        impact=(
            "Removing public sharing prevents new public use but cannot revoke volumes or snapshot copies already created by other accounts. Deleting or replacing recovery snapshots can violate retention needs, so no deletion is proposed."
        ),
        citations=[_citation("45 CFR 164.312(a)(1)", "Access control", _ECFR_312)],
        terraform=None,
        filename=None,
        assumptions=[
            "The report does not establish the snapshot contents, sharing history, creator, intended recipients, dependent AMIs, or whether another account copied it.",
            "The pinned Prowler check fails when its collected snapshot.public value is true; it does not perform an exposure-impact investigation.",
            "No snapshot deletion, replacement, or guessed Terraform ownership is generated.",
        ],
        steps=[
            "Confirm the account, Region, snapshot ID, createVolumePermission attribute, source volume and instance, AMI dependencies, tags, data classification, and CloudTrail history.",
            "Initiate the applicable incident or privacy review and assess whether another account created a volume or copy during the exposure window.",
            "Remove the all-group permission through the authoritative operational path and preserve only approved account IDs if sharing is required.",
            "Verify private visibility, review other snapshots and Regional EBS block-public-access settings, and rerun the check.",
            f"AWS EBS snapshot-sharing reference: {_AWS_EBS_SHARING}",
        ],
    )


def ebs_volume_encryption(observation: Observation) -> Recommendation:
    name = _resource(observation, "EBS volume")
    return Recommendation(
        status="needs_context",
        what=f"Prowler observed that {name} is an unencrypted EBS volume.",
        why=(
            "EBS encryption protects volume data, snapshots, and disk I/O at the storage layer. Enabling encryption by default does not retroactively encrypt this volume."
        ),
        change=(
            "Create and validate an encrypted replacement volume using an approved KMS key, then plan an application-aware detach, attach, mount, and cutover or instance-replacement workflow."
        ),
        impact=(
            "EBS volume encryption is not changed in place. Migration can require an application-consistent snapshot and downtime; device mappings, Availability Zone, boot behavior, filesystems, RAID or LVM, performance, KMS access, and rollback all affect safety."
        ),
        citations=[
            _citation(
                "45 CFR 164.312(a)(2)(iv)",
                "Encryption and decryption",
                _ECFR_312,
            )
        ],
        terraform=None,
        filename=None,
        assumptions=[
            "The report does not retain attachment, root-device, filesystem, application-consistency, Availability Zone, performance, snapshot, AMI, KMS, or Terraform ownership details.",
            "The pinned Prowler check tests the collected volume encrypted flag; it does not test key policy, application encryption, or migration readiness.",
            "No KMS key, snapshot, replacement volume, detach, attachment, instance stop, or deletion is generated.",
        ],
        steps=[
            "Inventory attachments, root and boot dependencies, filesystems, RAID or LVM, application write behavior, performance settings, backups, snapshots, AMIs, and owning configuration.",
            "Choose and review a KMS key and permissions, and enable Regional EBS encryption by default separately to protect future compatible volume creation.",
            "Select a crash-consistent or application-consistent migration method; create an encrypted copy or encrypted volume from a snapshot and validate data, boot, mount, performance, monitoring, and backups.",
            "Rehearse cutover and rollback, perform the approved change, and keep the source until recovery and retention approvals explicitly permit retirement.",
            f"AWS EBS volume-copy reference: {_AWS_EBS_COPY}",
        ],
    )


def instance_public_ip(observation: Observation) -> Recommendation:
    name = _resource(observation, "EC2 instance")
    return Recommendation(
        status="needs_context",
        what=f"Prowler observed a public IP address on nonterminated EC2 instance {name}.",
        why=(
            "A public IP creates internet routing potential, but actual exposure also depends on routes, network ACLs, security groups, host controls, and listening services. Some approved public-facing workloads intentionally require one."
        ),
        change=(
            "Confirm the workload's ingress and egress requirements. For a private workload, migrate access and outbound traffic to approved private paths, disable automatic public IPv4 assignment or disassociate the Elastic IP as applicable, and tighten surrounding network controls."
        ),
        impact=(
            "Removing or changing an address can break DNS, allowlists, monitoring, administration, callbacks, package access, and customer traffic. A stop/start used to change an auto-assigned address causes downtime and can change other ephemeral host state."
        ),
        citations=[_citation("45 CFR 164.312(a)(1)", "Access control", _ECFR_312)],
        terraform=None,
        filename=None,
        assumptions=[
            "The report does not retain ENIs, Elastic IP associations, subnet address defaults, routes, network ACLs, security groups, load balancers, DNS, host firewall, listening services, or Terraform ownership.",
            "The pinned Prowler check fails solely when a collected nonterminated instance has a public IP; it does not prove that an inbound port is reachable.",
            "No address disassociation, stop/start, subnet migration, or instance replacement is generated.",
        ],
        steps=[
            "Classify the workload and map each ENI, public or Elastic IP, subnet route, network ACL, security group, load balancer, DNS record, allowlist, client, and required outbound path.",
            "Investigate unexpected exposure using network and host telemetry, then design load-balancer, NAT, proxy, VPN, Session Manager, or private-connectivity replacements as appropriate.",
            "Test replacement paths and DNS or allowlist changes before removing the public address through the owning network and compute configurations.",
            "Verify intended reachability from inside and outside the network, monitor failures, and rerun the check.",
            f"AWS EC2 public-address reference: {_AWS_PUBLIC_IP}",
        ],
    )


def instance_managed_by_ssm(observation: Observation) -> Recommendation:
    name = _resource(observation, "EC2 instance")
    return Recommendation(
        status="needs_context",
        what=f"Prowler did not find running EC2 instance {name} in the Systems Manager managed-instance inventory.",
        why=(
            "A managed node enables centralized inventory and approved operational workflows. Missing registration can result from the agent, permissions, network path, Region, proxy, clock, or service configuration and should be diagnosed before changing IAM."
        ),
        change=(
            "Diagnose the missing registration, then provide the approved account-level Default Host Management Configuration or least-privilege instance profile, a supported and running SSM Agent, and required service connectivity."
        ),
        impact=(
            "Attaching or broadening an instance role changes workload credentials. Account-level host management affects eligible instances across the account and Region. Agent installation, updates, proxies, endpoints, logging, and Session Manager access add operational and security dependencies."
        ),
        citations=[
            _citation(
                "45 CFR 164.308(a)(5)(ii)(B)",
                "Protection from malicious software",
                _ECFR_308,
            )
        ],
        terraform=None,
        filename=None,
        assumptions=[
            "The report does not retain SSM Agent version or logs, instance profile, Default Host Management Configuration, IMDS behavior, network path, VPC endpoints, DNS, proxy, clock, OS support, or Terraform ownership.",
            "The pinned Prowler check treats pending, stopped, and terminated instances as nonfailing and fails other instances absent from its collected SSM managed-instance map.",
            "Being registered with Systems Manager does not prove patch compliance, inventory freshness, Session Manager restrictions, or logging coverage.",
        ],
        steps=[
            "Confirm instance state, account and Region, OS support, agent installation and health, agent logs, clock, metadata access, current instance profile, and Default Host Management Configuration.",
            "Validate outbound HTTPS or the required VPC endpoints, endpoint security groups and policies, DNS, proxies, and access to required AWS-managed S3 buckets.",
            "Choose account-level or instance-level permissions, review the exact policy and blast radius, and test registration on a representative instance.",
            "After registration, verify inventory freshness and the separately approved patch, Session Manager, command, logging, and access policies; rerun the check.",
            f"AWS managed-node setup reference: {_AWS_SSM_NODES}",
            f"AWS Systems Manager VPC-endpoint reference: {_AWS_SSM_ENDPOINTS}",
        ],
    )


EC2_BUILDERS: dict[str, Callable[[Observation], Recommendation]] = {
    "ec2_ebs_public_snapshot": ebs_public_snapshot,
    "ec2_ebs_volume_encryption": ebs_volume_encryption,
    "ec2_instance_managed_by_ssm": instance_managed_by_ssm,
    "ec2_instance_public_ip": instance_public_ip,
}
