# HIPAA recommendation coverage

Source: [Prowler 5.42.0 framework](https://github.com/prowler-cloud/prowler/blob/73ae2eb1947a0912a05010a296f469bfa55ebe76/prowler/compliance/aws/hipaa_aws.json).

57 of 95 framework checks have guidance handlers. This counts implementation coverage, not validated fixes or compliance.

All mappings are upstream Prowler mappings requiring applicability review. Unsupported findings remain visible in reports.

| Check | Guidance handler | Upstream HIPAA mapping |
| --- | --- | --- |
| acm_certificates_expiration_check | Missing | 45 CFR 164.308(a)(4)(ii)(A); 45 CFR 164.312(e)(1) |
| apigateway_restapi_logging_enabled | Missing | 45 CFR 164.308(a)(1)(ii)(D); 45 CFR 164.308(a)(3)(ii)(A); 45 CFR 164.308(a)(6)(ii); 45 CFR 164.312(b) |
| awslambda_function_not_publicly_accessible | Missing | 45 CFR 164.308(a)(1)(ii)(B); 45 CFR 164.308(a)(3)(i); 45 CFR 164.312(a)(1); 45 CFR 164.312(e)(1) |
| awslambda_function_url_public | Missing | 45 CFR 164.308(a)(1)(ii)(B); 45 CFR 164.308(a)(3)(i); 45 CFR 164.312(a)(1) |
| cloudfront_distributions_https_enabled | Missing | 45 CFR 164.308(a)(4)(ii)(A); 45 CFR 164.312(e)(1) |
| cloudtrail_bedrock_logging_enabled | Available; review required | 45 CFR 164.308(a)(1)(ii)(D); 45 CFR 164.312(b) |
| cloudtrail_cloudwatch_logging_enabled | Available; review required | 45 CFR 164.308(a)(1)(ii)(D); 45 CFR 164.308(a)(6)(ii); 45 CFR 164.312(b); 45 CFR 164.312(e)(2)(i) |
| cloudtrail_kms_encryption_enabled | Available; review required | 45 CFR 164.308(a)(1)(ii)(B); 45 CFR 164.308(a)(1)(ii)(D); 45 CFR 164.308(a)(4)(ii)(A); 45 CFR 164.312(a)(2)(iv); 45 CFR 164.312(c)(1); 45 CFR 164.312(c)(2); 45 CFR 164.312(e)(2)(ii) |
| cloudtrail_log_file_validation_enabled | Available; review required | 45 CFR 164.308(a)(1)(ii)(B); 45 CFR 164.308(a)(1)(ii)(D); 45 CFR 164.312(b); 45 CFR 164.312(c)(1); 45 CFR 164.312(c)(2) |
| cloudtrail_multi_region_enabled | Available; review required | 45 CFR 164.308(a)(1)(ii)(D); 45 CFR 164.308(a)(3)(ii)(A); 45 CFR 164.308(a)(6)(ii); 45 CFR 164.312(b); 45 CFR 164.312(e)(2)(i) |
| cloudtrail_s3_dataevents_read_enabled | Available; review required | 45 CFR 164.308(a)(1)(ii)(D); 45 CFR 164.308(a)(3)(ii)(A); 45 CFR 164.308(a)(6)(ii); 45 CFR 164.312(a)(2)(i); 45 CFR 164.312(b); 45 CFR 164.312(e)(2)(i) |
| cloudtrail_s3_dataevents_write_enabled | Available; review required | 45 CFR 164.308(a)(1)(ii)(D); 45 CFR 164.308(a)(3)(ii)(A); 45 CFR 164.308(a)(6)(ii); 45 CFR 164.312(a)(2)(i); 45 CFR 164.312(b); 45 CFR 164.312(e)(2)(i) |
| cloudwatch_changes_to_network_acls_alarm_configured | Missing | 45 CFR 164.308(a)(6)(i) |
| cloudwatch_changes_to_network_gateways_alarm_configured | Missing | 45 CFR 164.308(a)(6)(i) |
| cloudwatch_changes_to_network_route_tables_alarm_configured | Missing | 45 CFR 164.308(a)(6)(i) |
| cloudwatch_changes_to_vpcs_alarm_configured | Missing | 45 CFR 164.308(a)(6)(i) |
| cloudwatch_log_group_kms_encryption_enabled | Missing | 45 CFR 164.308(a)(1)(ii)(B); 45 CFR 164.308(a)(4)(ii)(A); 45 CFR 164.312(a)(2)(iv); 45 CFR 164.312(e)(2)(ii) |
| cloudwatch_log_group_retention_policy_specific_days_enabled | Missing | 45 CFR 164.312(b) |
| cloudwatch_log_metric_filter_authentication_failures | Missing | 45 CFR 164.308(a)(5)(ii)(C); 45 CFR 164.308(a)(6)(i); 45 CFR 164.308(a)(6)(ii) |
| cloudwatch_log_metric_filter_root_usage | Missing | 45 CFR 164.308(a)(6)(i); 45 CFR 164.308(a)(6)(ii) |
| config_recorder_all_regions_enabled | Missing | 45 CFR 164.308(a)(1)(ii)(A) |
| dynamodb_accelerator_cluster_encryption_enabled | Available; review required | 45 CFR 164.308(a)(4)(ii)(A); 45 CFR 164.312(a)(2)(iv); 45 CFR 164.312(e)(2)(ii) |
| dynamodb_tables_kms_cmk_encryption_enabled | Available; review required | 45 CFR 164.308(a)(4)(ii)(A); 45 CFR 164.312(a)(2)(iv); 45 CFR 164.312(e)(2)(ii) |
| dynamodb_tables_pitr_enabled | Available; review required | 45 CFR 164.308(a)(1)(ii)(B); 45 CFR 164.308(a)(7)(i); 45 CFR 164.308(a)(7)(ii)(A); 45 CFR 164.308(a)(7)(ii)(B); 45 CFR 164.308(a)(7)(ii)(C); 45 CFR 164.312(a)(2)(ii) |
| ec2_confidential_workload_host_imdsv2_not_enforced | Missing | 45 CFR 164.312(a)(1) |
| ec2_confidential_workload_host_public_ip | Missing | 45 CFR 164.308(a)(1)(ii)(B); 45 CFR 164.312(a)(1) |
| ec2_confidential_workload_host_unrestricted_ingress | Missing | 45 CFR 164.312(e)(1) |
| ec2_confidential_workload_host_vsock_proxy_exposed | Missing | 45 CFR 164.312(e)(1) |
| ec2_ebs_default_encryption | Available; review required | 45 CFR 164.308(a)(1)(ii)(B); 45 CFR 164.308(a)(4)(ii)(A); 45 CFR 164.312(a)(2)(iv); 45 CFR 164.312(e)(2)(ii) |
| ec2_ebs_public_snapshot | Available; review required | 45 CFR 164.308(a)(1)(ii)(B); 45 CFR 164.308(a)(3)(i); 45 CFR 164.312(a)(1) |
| ec2_ebs_volume_encryption | Available; review required | 45 CFR 164.308(a)(1)(ii)(B); 45 CFR 164.308(a)(4)(ii)(A); 45 CFR 164.312(a)(2)(iv); 45 CFR 164.312(c)(1); 45 CFR 164.312(c)(2); 45 CFR 164.312(e)(2)(ii) |
| ec2_instance_managed_by_ssm | Available; review required | 45 CFR 164.308(a)(5)(ii)(B) |
| ec2_instance_older_than_specific_days | Available; review required | 45 CFR 164.308(a)(1)(ii)(B) |
| ec2_instance_public_ip | Available; review required | 45 CFR 164.308(a)(1)(ii)(B); 45 CFR 164.308(a)(3)(i); 45 CFR 164.312(a)(1) |
| ec2_networkacl_allow_ingress_any_port | Missing | 45 CFR 164.308(a)(1)(ii)(B); 45 CFR 164.312(e)(1) |
| ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22 | Missing | 45 CFR 164.308(a)(1)(ii)(B); 45 CFR 164.312(e)(1) |
| efs_encryption_at_rest_enabled | Available; review required | 45 CFR 164.308(a)(1)(ii)(B); 45 CFR 164.308(a)(4)(ii)(A); 45 CFR 164.312(a)(2)(iv); 45 CFR 164.312(e)(2)(ii) |
| efs_have_backup_enabled | Available; review required | 45 CFR 164.308(a)(7)(i); 45 CFR 164.308(a)(7)(ii)(A); 45 CFR 164.308(a)(7)(ii)(B); 45 CFR 164.308(a)(7)(ii)(C); 45 CFR 164.312(a)(2)(ii) |
| eks_cluster_kms_cmk_encryption_in_secrets_enabled | Missing | 45 CFR 164.308(a)(4)(ii)(A); 45 CFR 164.312(a)(2)(iv); 45 CFR 164.312(e)(2)(ii) |
| elb_logging_enabled | Missing | 45 CFR 164.308(a)(1)(ii)(D); 45 CFR 164.308(a)(3)(ii)(A); 45 CFR 164.308(a)(6)(ii); 45 CFR 164.312(b) |
| elb_ssl_listeners | Missing | 45 CFR 164.308(a)(1)(ii)(B); 45 CFR 164.308(a)(4)(ii)(A); 45 CFR 164.312(e)(1); 45 CFR 164.312(e)(2)(i); 45 CFR 164.312(e)(2)(ii) |
| elbv2_deletion_protection | Missing | 45 CFR 164.308(a)(1)(ii)(B) |
| elbv2_logging_enabled | Missing | 45 CFR 164.308(a)(1)(ii)(D); 45 CFR 164.308(a)(3)(ii)(A); 45 CFR 164.308(a)(6)(ii); 45 CFR 164.312(b) |
| emr_cluster_master_nodes_no_public_ip | Missing | 45 CFR 164.308(a)(1)(ii)(B); 45 CFR 164.312(a)(1) |
| guardduty_is_enabled | Available; review required | 45 CFR 164.308(a)(1)(ii)(A); 45 CFR 164.308(a)(1)(ii)(D); 45 CFR 164.308(a)(3)(ii)(A); 45 CFR 164.308(a)(5)(ii)(C); 45 CFR 164.308(a)(6)(i); 45 CFR 164.308(a)(6)(ii); 45 CFR 164.308(a)(8); 45 CFR 164.312(b); 45 CFR 164.312(e)(2)(i) |
| guardduty_no_high_severity_findings | Available; review required | 45 CFR 164.308(a)(6)(ii) |
| iam_aws_attached_policy_no_administrative_privileges | Available; review required | 45 CFR 164.308(a)(1)(ii)(B); 45 CFR 164.308(a)(3)(i); 45 CFR 164.308(a)(3)(ii)(B); 45 CFR 164.308(a)(4)(i); 45 CFR 164.308(a)(4)(ii)(B); 45 CFR 164.308(a)(4)(ii)(B); 45 CFR 164.312(a)(1) |
| iam_customer_attached_policy_no_administrative_privileges | Available; review required | 45 CFR 164.308(a)(1)(ii)(B); 45 CFR 164.308(a)(3)(i); 45 CFR 164.308(a)(3)(ii)(B); 45 CFR 164.308(a)(4)(i); 45 CFR 164.308(a)(4)(ii)(B); 45 CFR 164.308(a)(4)(ii)(B); 45 CFR 164.312(a)(1) |
| iam_inline_policy_no_administrative_privileges | Available; review required | 45 CFR 164.308(a)(1)(ii)(B); 45 CFR 164.308(a)(3)(i); 45 CFR 164.308(a)(3)(ii)(B); 45 CFR 164.308(a)(4)(i); 45 CFR 164.308(a)(4)(ii)(B); 45 CFR 164.308(a)(4)(ii)(B); 45 CFR 164.312(a)(1) |
| iam_inline_policy_no_wildcard_marketplace_subscribe | Available; review required | 45 CFR 164.308(a)(4)(ii)(B) |
| iam_no_root_access_key | Available; review required | 45 CFR 164.308(a)(1)(ii)(B); 45 CFR 164.308(a)(3)(i); 45 CFR 164.308(a)(3)(ii)(B); 45 CFR 164.308(a)(4)(ii)(B); 45 CFR 164.312(a)(2)(i) |
| iam_password_policy_lowercase | Available; review required | 45 CFR 164.308(a)(5)(ii)(D) |
| iam_password_policy_minimum_length_14 | Available; review required | 45 CFR 164.308(a)(5)(ii)(D) |
| iam_password_policy_number | Available; review required | 45 CFR 164.308(a)(5)(ii)(D) |
| iam_password_policy_reuse_24 | Available; review required | 45 CFR 164.308(a)(4)(ii)(B); 45 CFR 164.308(a)(5)(ii)(D); 45 CFR 164.312(d) |
| iam_password_policy_symbol | Available; review required | 45 CFR 164.308(a)(5)(ii)(D) |
| iam_password_policy_uppercase | Available; review required | 45 CFR 164.308(a)(5)(ii)(D) |
| iam_policy_no_wildcard_marketplace_subscribe | Available; review required | 45 CFR 164.308(a)(4)(ii)(B) |
| iam_root_hardware_mfa_enabled | Available; review required | 45 CFR 164.308(a)(3)(ii)(A); 45 CFR 164.312(d) |
| iam_root_mfa_enabled | Available; review required | 45 CFR 164.308(a)(3)(ii)(A); 45 CFR 164.312(d) |
| iam_rotate_access_key_90_days | Available; review required | 45 CFR 164.308(a)(3)(ii)(C); 45 CFR 164.308(a)(4)(ii)(B); 45 CFR 164.308(a)(5)(ii)(D) |
| iam_user_accesskey_unused | Available; review required | 45 CFR 164.308(a)(3)(ii)(B); 45 CFR 164.308(a)(4)(ii)(B); 45 CFR 164.308(a)(5)(ii)(D) |
| iam_user_console_access_unused | Available; review required | 45 CFR 164.308(a)(3)(ii)(B); 45 CFR 164.308(a)(4)(ii)(B); 45 CFR 164.308(a)(5)(ii)(D) |
| iam_user_mfa_enabled_console_access | Available; review required | 45 CFR 164.308(a)(3)(ii)(A); 45 CFR 164.312(a)(1); 45 CFR 164.312(d) |
| kms_cmk_rotation_enabled | Available; review required | 45 CFR 164.312(a)(2)(iv) |
| kms_key_enclave_attestation_bypassable_path | Available; review required | 45 CFR 164.312(a)(1) |
| kms_key_enclave_attestation_not_enforced | Available; review required | 45 CFR 164.312(a)(2)(iv) |
| kms_key_enclave_attestation_pcr_mismatch | Available; review required | 45 CFR 164.312(c)(1) |
| kms_key_enclave_attestation_unknown_image | Available; review required | 45 CFR 164.312(c)(2) |
| kms_key_enclave_debug_attestation_detected | Available; review required | 45 CFR 164.308(a)(1)(ii)(D); 45 CFR 164.312(b) |
| opensearch_service_domains_encryption_at_rest_enabled | Missing | 45 CFR 164.308(a)(1)(ii)(B); 45 CFR 164.308(a)(4)(ii)(A); 45 CFR 164.312(a)(2)(iv); 45 CFR 164.312(e)(2)(ii) |
| opensearch_service_domains_node_to_node_encryption_enabled | Missing | 45 CFR 164.308(a)(4)(ii)(A); 45 CFR 164.312(e)(1) |
| rds_instance_backup_enabled | Available; review required | 45 CFR 164.308(a)(1)(ii)(B); 45 CFR 164.308(a)(4)(ii)(A); 45 CFR 164.308(a)(7)(i); 45 CFR 164.308(a)(7)(ii)(A); 45 CFR 164.308(a)(7)(ii)(B); 45 CFR 164.308(a)(7)(ii)(C); 45 CFR 164.312(a)(2)(ii) |
| rds_instance_integration_cloudwatch_logs | Available; review required | 45 CFR 164.308(a)(4)(ii)(A); 45 CFR 164.312(b) |
| rds_instance_multi_az | Available; review required | 45 CFR 164.308(a)(1)(ii)(B); 45 CFR 164.308(a)(7)(i); 45 CFR 164.308(a)(7)(ii)(A); 45 CFR 164.308(a)(7)(ii)(B); 45 CFR 164.308(a)(7)(ii)(C) |
| rds_instance_no_public_access | Available; review required | 45 CFR 164.308(a)(3)(i); 45 CFR 164.312(a)(1) |
| rds_instance_storage_encrypted | Available; review required | 45 CFR 164.308(a)(1)(ii)(B); 45 CFR 164.308(a)(4)(ii)(A); 45 CFR 164.312(a)(2)(iv); 45 CFR 164.312(e)(2)(ii) |
| rds_snapshots_public_access | Available; review required | 45 CFR 164.308(a)(1)(ii)(B); 45 CFR 164.308(a)(3)(i); 45 CFR 164.312(a)(1) |
| redshift_cluster_audit_logging | Missing | 45 CFR 164.308(a)(1)(ii)(B); 45 CFR 164.308(a)(1)(ii)(D); 45 CFR 164.308(a)(3)(ii)(A); 45 CFR 164.308(a)(4)(ii)(A); 45 CFR 164.312(a)(2)(iv); 45 CFR 164.312(b); 45 CFR 164.312(e)(2)(ii) |
| redshift_cluster_automated_snapshot | Missing | 45 CFR 164.308(a)(4)(ii)(A); 45 CFR 164.308(a)(7)(i); 45 CFR 164.308(a)(7)(ii)(A); 45 CFR 164.308(a)(7)(ii)(B); 45 CFR 164.308(a)(7)(ii)(C); 45 CFR 164.312(a)(2)(ii) |
| redshift_cluster_public_access | Missing | 45 CFR 164.308(a)(1)(ii)(B); 45 CFR 164.308(a)(3)(i); 45 CFR 164.312(a)(1) |
| s3_account_level_public_access_blocks | Available; review required | 45 CFR 164.308(a)(1)(ii)(B); 45 CFR 164.308(a)(3)(i) |
| s3_bucket_default_encryption | Available; review required | 45 CFR 164.308(a)(1)(ii)(B); 45 CFR 164.308(a)(4)(ii)(A); 45 CFR 164.312(a)(2)(iv); 45 CFR 164.312(c)(1); 45 CFR 164.312(c)(2); 45 CFR 164.312(e)(2)(ii) |
| s3_bucket_object_versioning | Available; review required | 45 CFR 164.308(a)(1)(ii)(B); 45 CFR 164.308(a)(7)(i); 45 CFR 164.308(a)(7)(ii)(A); 45 CFR 164.308(a)(7)(ii)(B); 45 CFR 164.308(a)(7)(ii)(C); 45 CFR 164.312(a)(2)(ii); 45 CFR 164.312(c)(1); 45 CFR 164.312(c)(2) |
| s3_bucket_policy_public_write_access | Available; review required | 45 CFR 164.308(a)(1)(ii)(B); 45 CFR 164.308(a)(3)(i); 45 CFR 164.312(a)(1) |
| s3_bucket_public_access | Available; review required | 45 CFR 164.308(a)(1)(ii)(B); 45 CFR 164.308(a)(3)(i); 45 CFR 164.312(a)(1); 45 CFR 164.312(a)(2)(i) |
| s3_bucket_secure_transport_policy | Available; review required | 45 CFR 164.308(a)(1)(ii)(B); 45 CFR 164.312(a)(2)(iv); 45 CFR 164.312(c)(1); 45 CFR 164.312(c)(2); 45 CFR 164.312(e)(1); 45 CFR 164.312(e)(2)(i); 45 CFR 164.312(e)(2)(ii) |
| s3_bucket_server_access_logging_enabled | Available; review required | 45 CFR 164.308(a)(1)(ii)(D); 45 CFR 164.308(a)(3)(ii)(A); 45 CFR 164.308(a)(6)(ii); 45 CFR 164.312(b); 45 CFR 164.312(e)(2)(i) |
| sagemaker_notebook_instance_encryption_enabled | Missing | 45 CFR 164.308(a)(1)(ii)(B); 45 CFR 164.308(a)(4)(ii)(A); 45 CFR 164.312(a)(2)(iv); 45 CFR 164.312(e)(2)(ii) |
| sagemaker_notebook_instance_without_direct_internet_access_configured | Missing | 45 CFR 164.308(a)(1)(ii)(B); 45 CFR 164.308(a)(3)(i); 45 CFR 164.312(a)(1) |
| secretsmanager_automatic_rotation_enabled | Missing | 45 CFR 164.308(a)(4)(ii)(B) |
| securityhub_enabled | Missing | 45 CFR 164.308(a)(1)(ii)(D); 45 CFR 164.308(a)(3)(ii)(A); 45 CFR 164.308(a)(5)(ii)(C); 45 CFR 164.308(a)(6)(i); 45 CFR 164.308(a)(6)(ii); 45 CFR 164.308(a)(8); 45 CFR 164.312(b); 45 CFR 164.312(e)(2)(i) |
| sns_topics_kms_encryption_at_rest_enabled | Missing | 45 CFR 164.308(a)(1)(ii)(B); 45 CFR 164.308(a)(4)(ii)(A); 45 CFR 164.312(a)(2)(iv); 45 CFR 164.312(e)(2)(ii) |
| ssm_managed_compliant_patching | Missing | 45 CFR 164.308(a)(5)(ii)(B) |
| vpc_flow_logs_enabled | Missing | 45 CFR 164.308(a)(1)(ii)(D); 45 CFR 164.308(a)(3)(ii)(A); 45 CFR 164.308(a)(6)(ii); 45 CFR 164.312(b); 45 CFR 164.312(c)(2) |

Additional handlers outside this framework: accessanalyzer_enabled, account_maintain_different_contact_details_to_security_billing_and_operations, s3_bucket_level_public_access_block.
