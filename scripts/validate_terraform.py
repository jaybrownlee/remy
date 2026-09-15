"""Validate generated catalog examples without credentials, backends, plans, or applies."""

import argparse
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from remy.recommendations.catalog import SUPPORTED_CHECK_IDS, recommend
from remy.reports.schema import Observation

TERRAFORM_VERSION = "1.14.0"
AWS_PROVIDER_VERSION = "6.0.0"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--terraform", default="terraform")
    args = parser.parse_args()
    executable = shutil.which(args.terraform)
    if executable is None:
        parser.error("Install Terraform 1.14.0 or pass --terraform /path/to/terraform")
    executable = str(Path(executable).resolve())
    with tempfile.TemporaryDirectory(prefix="remy-terraform-") as scratch:
        root = Path(scratch)
        (root / "cache").mkdir()
        # Do not pass AWS profiles, keys, Terraform variable overrides or user CLI config.
        env = {
            "PATH": os.defpath,
            "HOME": scratch,
            "TMPDIR": scratch,
            "TF_IN_AUTOMATION": "1",
            "TF_INPUT": "0",
            "TF_PLUGIN_CACHE_DIR": str(root / "cache"),
            "CHECKPOINT_DISABLE": "1",
            "AWS_EC2_METADATA_DISABLED": "true",
        }

        def run(*command: str) -> str:
            result = subprocess.run(
                [executable, *command],
                cwd=root,
                env=env,
                text=True,
                capture_output=True,
                timeout=300,
                check=False,
            )
            if result.returncode:
                raise RuntimeError(result.stdout + result.stderr)
            return result.stdout

        version = json.loads(run("version", "-json"))["terraform_version"]
        if version != TERRAFORM_VERSION:
            raise RuntimeError(f"Expected Terraform {TERRAFORM_VERSION}; found {version}")
        provider = f"""terraform {{
  required_version = "= {TERRAFORM_VERSION}"
  required_providers {{
    aws = {{ source = "hashicorp/aws", version = "= {AWS_PROVIDER_VERSION}" }}
  }}
}}
"""
        example_count = 0
        for check in sorted(SUPPORTED_CHECK_IDS):
            for variant, name, uid, account in [
                (
                    "known",
                    "example-audit-bucket",
                    "arn:aws:s3:::example-audit-bucket",
                    "123456789012",
                ),
                ("missing", "<resource_name>", "<resource_uid>", "<account_uid>"),
                ("hostile", '${file("/not-readable")}', '"}\ninvalid', '${env("KEY")}'),
            ]:
                if variant == "known" and check.startswith("cloudtrail_"):
                    name = "example-audit-trail"
                    uid = "arn:aws:cloudtrail:us-east-1:123456789012:trail/example-audit-trail"
                observation = Observation(
                    account_id=account,
                    check_id=check,
                    resource_uid=uid,
                    resource_name=name,
                    service=check.split("_")[0],
                    region=("us-east-1" if variant == "known" else name),
                    status="FAIL",
                    severity="high",
                    title="Validation fixture",
                    detail="Fixture",
                )
                recommendation = recommend(observation)
                if not recommendation.terraform:
                    continue
                module = f"{check}_{variant}"
                directory = root / module
                directory.mkdir()
                (directory / "main.tf").write_text(recommendation.terraform)
                (directory / "versions.tf").write_text(provider)
                example_count += 1
        # validate allows unset root inputs, but child modules require all arguments.
        # Initialize one directory for a shared provider, then validate each independently.
        (root / "versions.tf").write_text(provider)
        run("init", "-backend=false", "-input=false", "-no-color")
        for directory in sorted(root.iterdir()):
            if not directory.is_dir() or not (directory / "main.tf").exists():
                continue
            shutil.copy2(root / ".terraform.lock.hcl", directory / ".terraform.lock.hcl")
            (directory / ".terraform").symlink_to(root / ".terraform", target_is_directory=True)
            run(f"-chdir={directory}", "fmt", "-no-color")
            output = json.loads(run(f"-chdir={directory}", "validate", "-json"))
            if not output["valid"]:
                raise RuntimeError(json.dumps(output, indent=2))
            print(f"PASS {directory.name}", flush=True)
        print(
            f"Validated {example_count} examples with Terraform {version}, "
            f"AWS provider {AWS_PROVIDER_VERSION}."
        )
        print("Syntax and provider schema only; customer state and AWS behavior were not tested.")


if __name__ == "__main__":
    main()
