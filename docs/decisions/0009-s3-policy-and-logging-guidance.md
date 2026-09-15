# Decision: generate S3 subresources but not replacement bucket policies

Status: implemented, September 14, 2026.

Five additional S3 checks now have reviewed guidance: explicit default encryption, public write policy, effective public access, secure transport policy, and server access logging.

Default encryption and server access logging use dedicated Terraform subresources. Remy validates the source bucket name but requires the customer to choose encryption mode, KMS key, bucket-key behavior, logging destination, and prefix. The report explains that default encryption affects new writes rather than existing object versions and that server access logs are delayed, best-effort records rather than a complete API audit source.

Public access, public writes, and secure transport depend on the complete existing bucket policy, ACLs, access points, account controls, websites, CloudFront origins, delivery services, and cross-account consumers. Remy does not emit an `aws_s3_bucket_policy` resource because doing so would take ownership of and replace an unknown complete policy. The guidance instead requires retrieval from an authorized source, exact-statement review, merge in the owning configuration, policy validation, consumer testing, and effective-access verification.

Public-write findings also require investigation of recent writes and deletes before treating the issue as configuration-only. Secure-transport guidance records the exact pinned-check expectation without claiming that a standalone policy fragment is safe to deploy.

Sources reviewed September 14, 2026:

- Prowler 5.42.0 S3 check implementations at pinned commit `73ae2eb1947a0912a05010a296f469bfa55ebe76`.
- [AWS S3 default encryption](https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html).
- [AWS S3 Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html).
- [AWS S3 policy condition keys](https://docs.aws.amazon.com/AmazonS3/latest/userguide/amazon-s3-policy-keys.html).
- [AWS S3 server access logging](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html).

Validation: tests require unknown policy preservation, explicit encryption and logging inputs, existing-object and KMS impact notes, public-write investigation, and recursive-logging warnings. Terraform validation covers known, missing, and hostile observation identifiers.
