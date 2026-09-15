# ADR 0012: Require live topology for EC2 and EBS changes

- Status: Accepted
- Date: 2026-09-14

## Context

Four pinned checks cover public EBS snapshots, unencrypted EBS volumes, EC2 public IPs, and Systems Manager registration. Their scanner rows do not contain enough state to safely change snapshot permissions, migrate storage, remove addressing, or alter instance permissions and connectivity.

The checks are also narrow signals. A public IP does not prove a reachable port, Systems Manager registration does not prove patch compliance, and encrypting an existing EBS volume requires a replacement workflow.

## Decision

Remy provides reviewed investigation and change-planning guidance without generating Terraform for these checks.

- Public snapshots require exposure review and removal of the all-group permission; deletion is never proposed.
- Unencrypted volumes require an application-aware encrypted replacement, cutover, rollback, and explicit source-retirement decision.
- Public IP findings require full ENI, route, ACL, security-group, DNS, and client review before an address is removed.
- Systems Manager findings require diagnosis of agent, permissions, network, Region, proxy, and clock state before IAM changes.

## Consequences

The report cannot offer one-click changes for these findings. It does preserve the exact limits of the pinned checks and avoids disruptive or security-expanding guesses from incomplete scan data.
