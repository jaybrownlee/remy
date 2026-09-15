# Changelog

## Unreleased

- Added CSRF-protected organization switching with membership checks, atomic session rotation, unchanged expiry, and audit attribution. Added bounded expired-authentication cleanup and an indexed retention migration; active sessions and audit history are preserved.
- Verified database-backed tests on a temporary native PostgreSQL 16.15 instance, including prototype adoption, tenant isolation, concurrent authentication, and audit protections. Pinned CI to the verified PostgreSQL release.
- Added explicit Alembic migrations with a frozen baseline that preserves compatible prototype data and rejects detected schema drift. Application startup now checks schema version without creating tables or replacing triggers.
- Added migration/adoption regression tests and PostgreSQL 16 CI coverage for database-backed tests, including an audit TRUNCATE guard. Local PostgreSQL execution remains unverified because Docker did not respond.

- Added default-on local magic-link authentication, operator-provisioned organizations and memberships, tenant-bound sessions, CSRF checks, and persistent login-request limits. Explicit demo mode retains access to earlier sample reports.
- Added database-protected audit records for login, logout, provisioning, and downloads; tested session revocation, cross-tenant access, concurrent link consumption, secure cookies, and credential redaction from the response-time ASGI scope.
- Added a private development mailbox and setup instructions. Production delivery, migrations, organization switching, and PostgreSQL runtime verification remain pending; remote access stays disabled.

- Completed guidance-handler coverage for all 95 pinned framework checks, adding the remaining 36 monitoring, network, certificate, load-balancer, and data-service plans.
- Added explicit pinned-scanner limitations and AWS references to each new plan, including EKS/SageMaker default encryption, CloudFront default-behavior scope, and alarm-delivery limitations.
- Verified complete-framework report and ZIP export behavior while preserving unknown findings and manual/context-dependent recommendations.

- Added OpenSearch storage and node-to-node encryption guidance, including existing-domain eligibility, irreversible enablement, storage-tier prerequisites, and separate client HTTPS protection.
- Linked OpenSearch recommendations targeting the same verified domain in reports and exports, including guidance without Terraform files.

- Added reviewable Terraform guidance for all six IAM account password-policy checks in the pinned HIPAA framework.
- Added manual, secret-safe guidance for root access keys, root hardware MFA, and MFA for console-enabled IAM users.
- Added dependency-aware guidance for stale IAM access keys, unused console access, administrative policies, and AWS Marketplace subscription permissions.
- Added incident- and architecture-aware guidance for GuardDuty findings, aging EC2 instances, KMS rotation, and Nitro Enclave attestation findings.
- Added S3 default-encryption and server-logging Terraform guidance plus policy-safe public-access and secure-transport review paths.
- Moved scanner identifier validation into a shared recommendation module for service-specific catalogs.
- Added complete-trail review guidance for Bedrock events, CloudWatch delivery, KMS encryption, log validation, and S3 object data events.
- Added migration-aware RDS guidance for backups, log exports, Multi-AZ, public network paths, storage encryption, and public snapshots without generating incomplete stateful resources.
- Added investigation- and migration-aware guidance for public EBS snapshots, unencrypted EBS volumes, EC2 public IPs, and Systems Manager registration.
- Added EFS encrypted-replacement planning and backup-policy guidance with restore validation and no destructive source actions.
- Added DAX replacement, DynamoDB key-selection, and point-in-time recovery guidance, including the pinned check's managed-key detection limitation.
- Grouped password-policy findings that target the same AWS account so customers are warned to use one owning Terraform configuration.
- Increased framework recommendation coverage from 6 to 95 of 95 checks. The unchanged 48 generated Terraform examples passed the pinned validation harness; new plans do not generate Terraform.
