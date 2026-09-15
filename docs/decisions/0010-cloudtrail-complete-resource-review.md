# Decision: reconcile CloudTrail findings against one complete trail

Status: implemented, September 14, 2026.

Six additional CloudTrail checks now have reviewed context-dependent guidance: Bedrock event coverage, CloudWatch Logs delivery, KMS encryption, log-file validation, and S3 object read and write data events.

All settings belong to a complete CloudTrail trail configuration with shared destinations, roles, keys, event selectors, organization ownership, and cost. Remy emits no partial `aws_cloudtrail` resource for these checks. Applying a partial block as a complete resource can omit selectors or dependencies and reduce existing audit coverage. Each item instructs the customer to retrieve the current configuration, reconcile every finding into one proposed trail, test dependencies and costs, and update only the owning configuration.

The CloudWatch delivery check uses its latest CloudWatch Logs delivery timestamp and does not establish S3 trail delivery health. A missing or old timestamp can represent missing configuration, permission failure, delivery failure, or lack of recent qualifying activity; current status requires review.

The pinned Prowler 5.42.0 advanced-selector path for the S3 read and write checks recognizes `AWS::S3::Object` but does not fully prove `readOnly` direction or all-bucket resource coverage. Remy exposes that limitation and requires inspection of the actual selector rather than treating the check result as complete coverage evidence.

Sources reviewed September 14, 2026:

- Prowler 5.42.0 CloudTrail check implementations at pinned commit `73ae2eb1947a0912a05010a296f469bfa55ebe76`.
- [CloudTrail management events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-management-events-with-cloudtrail.html).
- [CloudTrail data events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html).
- [CloudTrail delivery to CloudWatch Logs](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/send-cloudtrail-events-to-cloudwatch-logs.html).
- [CloudTrail SSE-KMS encryption](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html).
- [CloudTrail log-file validation](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html).

Validation: tests require complete-trail reconciliation, no partial Terraform, separate CloudWatch and S3 delivery claims, and explicit advanced-selector coverage limitations.
