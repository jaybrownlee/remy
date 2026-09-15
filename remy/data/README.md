# Upstream example provenance

`prowler-aws-example.json` is the unmodified public AWS OCSF example from
Prowler tag `5.42.0`, commit `73ae2eb1947a0912a05010a296f469bfa55ebe76`:
https://github.com/prowler-cloud/prowler/blob/73ae2eb1947a0912a05010a296f469bfa55ebe76/examples/output/example_output_aws.ocsf.json
Git blob SHA: `2fcc4951a4f0aa4cee352ba4f9f4895527a4b7cf`.
Retrieved September 14, 2026. Apache 2.0 license included in PROWLER-LICENSE.

This upstream illustrative output has placeholder account/resource identifiers.
It is not a scan of the user's AWS account, is not HIPAA-framework-complete, and
must not be described as live sandbox acceptance evidence. We do not invent OCSF
samples to demonstrate the import path. Tests mutate copies of this source to
exercise malformed input and boundary cases.

## Pinned HIPAA framework

`hipaa_aws.json` is the unmodified framework from the same Prowler 5.42.0 commit,
Git blob `01de916ec6a8a36edc3055fcfe991e77b40a73e1`. SHA-256:
`57fa186fe0e202147cd4a4c808a028240c7dd9fde472c81a099a5640743b26b3`.
It contains 32 requirements and 95 unique check IDs. The accompanying Apache 2.0
license applies. These are upstream scanner mappings, not reviewed legal conclusions.

Source: https://github.com/prowler-cloud/prowler/blob/73ae2eb1947a0912a05010a296f469bfa55ebe76/prowler/compliance/aws/hipaa_aws.json
