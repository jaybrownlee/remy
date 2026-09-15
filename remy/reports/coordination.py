"""Conservative overlap checks for the inputs of known recommendation templates.

Findings are never merged. No AWS state, Terraform state, or customer inputs are read.
"""

import re
from collections import defaultdict

from remy.recommendations.catalog import _bucket_name, _trail_name
from remy.reports.schema import ChangeTarget, ReportItem, SharedChange

_ACCOUNT_SETTINGS = {
    "s3_account_level_public_access_blocks": "S3 account public access block",
    "account_maintain_different_contact_details_to_security_billing_and_operations": (
        "AWS alternate contacts"
    ),
}
_REGIONAL_SETTINGS = {
    "ec2_ebs_default_encryption": "EBS default encryption",
    "guardduty_is_enabled": "GuardDuty detector",
    "accessanalyzer_enabled": "Account external access analyzer",
}
_BUCKET_SETTINGS = {
    "s3_bucket_level_public_access_block": "S3 bucket public access block",
    "s3_bucket_object_versioning": "S3 bucket versioning",
}


def target_for(item: ReportItem) -> ChangeTarget | None:
    observation = item.observation
    if not item.recommendation.terraform or not re.fullmatch(r"\d{12}", observation.account_id):
        return None
    check = observation.check_id
    account = observation.account_id
    if check in _ACCOUNT_SETTINGS:
        return ChangeTarget(account_id=account, setting=_ACCOUNT_SETTINGS[check], resource=account)
    if check in _BUCKET_SETTINGS:
        bucket = _bucket_name(observation)
        if bucket:
            return ChangeTarget(
                account_id=account, setting=_BUCKET_SETTINGS[check], resource=bucket
            )
        return None
    if not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d+", observation.region):
        return None
    if check in _REGIONAL_SETTINGS:
        return ChangeTarget(
            account_id=account,
            region=observation.region,
            setting=_REGIONAL_SETTINGS[check],
            resource=account,
        )
    if check == "cloudtrail_multi_region_enabled":
        trail = _trail_name(observation)
        if trail:
            home = re.fullmatch(
                r"arn:(?:aws|aws-cn|aws-us-gov):cloudtrail:([^:]+):([0-9]{12}):trail/(.+)",
                observation.resource_uid,
            )
            if home is None or home[2] != account or home[3] != trail:
                return None
            return ChangeTarget(
                account_id=account,
                region=home[1],
                setting="CloudTrail trail configuration",
                resource=trail,
            )
    return None


def assess_shared_changes(items: list[ReportItem]) -> list[SharedChange]:
    by_target: dict[str, list[ReportItem]] = defaultdict(list)
    for item in items:
        item.change_target = target_for(item)
        item.coordination_notes = []
        item.related_item_ids = []
        if not item.recommendation.terraform:
            continue
        if item.change_target is None:
            item.coordination_notes.append(
                "The target setting could not be identified from the available inputs. "
                "Check for overlap with other recommendations after supplying the missing context."
            )
            continue
        by_target[item.change_target.model_dump_json()].append(item)
    groups = []
    for key, related in sorted(by_target.items()):
        if len(related) < 2:
            continue
        related.sort(key=lambda item: str(item.item_id))
        ids = [item.item_id for item in related]
        message = (
            "These suggestions may manage the same setting. Review them together and select "
            "one owning Terraform configuration before applying. Findings remain separate; "
            "Remy has not merged or applied these changes."
        )
        for item in related:
            item.related_item_ids = [item_id for item_id in ids if item_id != item.item_id]
            item.coordination_notes.append(message)
        groups.append(
            SharedChange(
                target=ChangeTarget.model_validate_json(key), item_ids=ids, message=message
            )
        )
    return groups
