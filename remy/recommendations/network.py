"""Reviewed network and invocation-access change plans."""

# ruff: noqa: E501

from remy.recommendations.plans import ChangePlan

_HOST_CONTEXT = "enclave enablement, parent instance and launch-template ownership, IAM role, ENIs, routes, security groups, host services, proxy configuration, and application dependencies."
_SG_REFERENCE = "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html"

NETWORK_PLANS = {
    "ec2_confidential_workload_host_imdsv2_not_enforced": ChangePlan(
        what="Prowler observed an enclave-enabled parent host without HttpTokens=required.",
        why="Requiring metadata session tokens reduces credential exposure through applications that could be induced to request instance metadata.",
        change="Test IMDSv2 support in all host software, then set metadata_options.http_tokens to required on the owning aws_instance and future aws_launch_template configuration. Choose hop limits from the actual container topology.",
        impact="Older SDKs or metadata clients can lose credentials and stop working. Launch-template edits alone do not update existing instances.",
        context=_HOST_CONTEXT
        + " Also review metadata request metrics, agents, containers, SDK versions, and hop limits.",
        verify="Confirm existing hosts require tokens, application credential refresh succeeds, and replacement hosts inherit the setting.",
        reference="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-transition-to-version-2.html",
        caveat="This is a parent-host check, not an audit of enclave code, attestation, or confidentiality. Only enclave-enabled hosts are assessed.",
    ),
    "ec2_confidential_workload_host_public_ip": ChangePlan(
        what="Prowler observed public IPv4, IPv6, or a public-subnet routing signal on an enclave parent host.",
        why="Public network paths increase the parent's attack surface and need review alongside enclave isolation and attestation.",
        change="Provide approved private ingress and egress, remove unnecessary public addresses, and update the owning subnet, route, instance, and launch-template configurations. Plan a replacement if moving the workload requires it.",
        impact="Address and route changes can interrupt administration, KMS access, downloads, or clients. A route or address alone does not prove an open listening port.",
        context=_HOST_CONTEXT + " Also confirm IPv6 routes and private service endpoints.",
        verify="Test private administration, application traffic, KMS access, and effective IPv4 and IPv6 reachability on existing and replacement hosts.",
        reference="https://docs.aws.amazon.com/enclaves/latest/user/connect-enclave-kms.html",
        caveat="The pinned check considers addresses and public subnet routes; missing ENI/subnet inventory can yield MANUAL. This assesses the host network, not enclave compromise.",
    ),
    "ec2_confidential_workload_host_unrestricted_ingress": ChangePlan(
        what="Prowler observed world-facing parent-host security-group ports outside the scanner allow-list.",
        why="Restricting unnecessary ingress reduces paths to host services and credentials used by confidential workloads.",
        change="Identify the exact ingress rule IDs and their owners, then narrow or remove world-facing rules using the existing aws_vpc_security_group_ingress_rule or owning security-group configuration. Preserve verified private service paths.",
        impact="Security groups are shared and their permissions combine; removing a rule can affect other workloads, while another group can preserve exposure.",
        context=_HOST_CONTEXT
        + " Also confirm the scan's enclave_sg_allow_ports and every resource sharing each group.",
        verify="Test required flows and blocked internet ingress across all attached groups and both address families.",
        reference=_SG_REFERENCE,
        caveat="The default scanner allow-list is 22, 80, and 443; it is not an endorsement of public access on those ports. Missing group inventory can yield MANUAL.",
    ),
    "ec2_confidential_workload_host_vsock_proxy_exposed": ChangePlan(
        what="Prowler observed world-facing TCP ports commonly used by host-side vsock proxies.",
        why="A public TCP bridge could expose a host-to-enclave communication path, but port numbers alone cannot identify a proxy.",
        change="Identify the listening process, bind address, proxy destinations, and intended callers. Restrict the actual TCP bridge and its security-group rules to approved callers; retain only the required local vsock communication and KMS path.",
        impact="Closing a port without identifying its service can break unrelated applications or enclave communication. AF_VSOCK itself is not directly reachable over TCP/IP.",
        context=_HOST_CONTEXT
        + " Also review enclave_vsock_ports, process listeners, proxy allow-lists, and host firewall rules.",
        verify="Confirm which process owns each flagged port, test required enclave requests and denied external requests, and verify proxy destinations.",
        reference="https://docs.aws.amazon.com/enclaves/latest/user/enclave-networking.html",
        caveat="This heuristic defaults to ports 5000, 8000–8090, and 9000. It can flag non-vsock services and does not establish enclave compromise; missing groups can yield MANUAL.",
    ),
    "ec2_networkacl_allow_ingress_any_port": ChangePlan(
        what="Prowler classified a network ACL as allowing internet ingress across all ports.",
        why="Subnet ACLs can constrain traffic beyond security groups, but their ordered stateless rules require a complete flow design.",
        change="Review the full numbered ACL and subnet associations, then replace broad ingress with the approved protocol, port, and CIDR rules in the existing aws_network_acl or aws_network_acl_rule ownership model. Include return traffic explicitly.",
        impact="ACL rules are evaluated by order and affect all associated subnet resources. Missing ephemeral return ports or an early deny can break otherwise permitted connections.",
        context="all inbound and outbound rules, rule numbers, subnet associations, IPv4/IPv6 paths, client ephemeral ports, security groups, and the full Terraform ownership model.",
        verify="Test bidirectional application and administrative flows and expected denials for each associated subnet before and after rollout.",
        reference="https://docs.aws.amazon.com/vpc/latest/userguide/custom-network-acl.html",
        caveat="The pinned helper classifies ACL entries; it does not model every effective route and endpoint. Unused-resource scan settings affect coverage.",
    ),
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22": ChangePlan(
        what="Prowler observed a security-group rule allowing internet ingress to SSH port 22.",
        why="Unrestricted SSH expands the remote administration attack surface.",
        change="Validate an approved administration path such as Session Manager or VPN, then narrow or remove the exact SSH ingress rules in the owning security-group configuration. Preserve required access before closing the old path.",
        impact="A shared-group change can lock out administrators or disrupt automation. The existing rule style must be preserved to avoid competing inline and standalone rule owners.",
        context="rule IDs, every attached resource, IPv4/IPv6 CIDRs, existing administration and recovery paths, SSH automation, and all attached security groups.",
        verify="Verify authorized administration and recovery access, confirm internet SSH is blocked, and inspect all attached groups for alternate permissions.",
        reference=_SG_REFERENCE,
        caveat="The pinned check can report PASS without inspecting SSH when the all-ports check already failed, and can skip unused groups. Review related findings before interpreting PASS.",
    ),
    "awslambda_function_not_publicly_accessible": ChangePlan(
        what="Prowler classified the Lambda resource-based policy as public.",
        why="Broad invocation permission can permit untrusted callers to execute application behavior or incur cost.",
        change="Review every function and alias policy statement and invocation source. Remove or narrow public aws_lambda_permission statements to required principals, actions, qualifiers, source ARNs, and source accounts through the owning configuration.",
        impact="Removing permissions can interrupt API Gateway, S3, EventBridge, cross-account integrations, or URLs. Preserve required service-trigger conditions and legitimate callers.",
        context="complete function and alias policies, statement IDs, qualifiers, service triggers, URL configuration, cross-account consumers, and current Terraform permissions.",
        verify="Exercise approved triggers and verify unauthorized invocation is denied; investigate unexpected past invocation using available telemetry.",
        reference="https://docs.aws.amazon.com/lambda/latest/dg/access-control-resource-based.html",
        caveat="The pinned check skips absent policies and permits recognized cross-account access in its public-policy classification. It does not prove unauthorized invocation occurred.",
    ),
    "awslambda_function_url_public": ChangePlan(
        what="Prowler observed a function URL whose auth type is not AWS_IAM.",
        why="An unauthenticated URL needs an explicit public-service decision and appropriate application controls.",
        change="For a private invocation design, set authorization_type=AWS_IAM on the owning aws_lambda_function_url and reconcile function permissions and signed callers. If the endpoint is intentionally public, document that decision and assess its authentication and abuse controls.",
        impact="Requiring IAM authentication breaks unsigned clients. CORS is not authorization, and changing only the URL auth setting may leave other invocation permissions broad.",
        context="URL qualifier, resource policies, caller identities, signing support, public-service requirements, CORS, rate limits, and other function triggers.",
        verify="Test signed authorized and unauthorized requests and existing triggers. Confirm every intended client can authenticate.",
        reference="https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html",
        caveat="The check evaluates configured URL auth type, not application-layer authentication or effective public invocation permissions; functions without URLs are omitted.",
    ),
    "cloudfront_distributions_https_enabled": ChangePlan(
        what="Prowler did not observe redirect-to-https or https-only on the default cache behavior.",
        why="Requiring viewer HTTPS protects client traffic to the distribution.",
        change="Set the approved viewer_protocol_policy on default_cache_behavior and review every ordered_cache_behavior in the owning aws_cloudfront_distribution. Validate certificates and configure origin HTTPS separately where supported.",
        impact="HTTPS-only rejects HTTP clients; redirects can affect methods and older clients. Distribution updates and cache behavior ordering require testing across paths.",
        context="full distribution configuration, cache behaviors, paths and methods, viewer certificates, custom domains, origin protocols, and clients.",
        verify="Test HTTP and HTTPS for every behavior, including write methods and custom domains, and verify the origin transport policy independently.",
        reference="https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https-viewers-to-cloudfront.html",
        caveat="The pinned check evaluates only the default cache behavior. PASS does not establish HTTPS on ordered behaviors or the origin connection.",
    ),
    "emr_cluster_master_nodes_no_public_ip": ChangePlan(
        what="Prowler observed a public-address signal on an active EMR cluster.",
        why="Public primary-node access increases exposure of administrative and processing services.",
        change="Design private-subnet EMR deployment with the required managed service-access security group and private administration. Migrate jobs and data dependencies to a replacement cluster if the existing network placement cannot be changed safely.",
        impact="Changing cluster topology can interrupt jobs, HDFS data access, bootstrap downloads, S3 access, and service control traffic. Preserve outputs and recovery material before retiring the source.",
        context="EMR release, subnet placement, primary/core/task roles, active jobs, durable and local data, bootstrap scripts, IAM, managed groups, S3 routes, and administration.",
        verify="Run representative jobs and administrative operations on the private topology, verify output durability and service connectivity, and test denied public access.",
        reference="https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-clusters-in-a-vpc.html",
        caveat="The pinned check evaluates cluster.public and excludes terminated clusters. It does not prove listening-service reachability or complete private connectivity.",
    ),
}
