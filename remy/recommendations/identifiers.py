"""Validate scanner identifiers before using them as recommendation inputs."""

import re

from remy.reports.schema import Observation

AWS_REGION_RE = re.compile(r"^(?:af|ap|ca|cn|eu|il|me|mx|sa|us)-[a-z0-9-]+-\d+$")
_IP_ADDRESS_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_S3_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
_S3_ARN_RE = re.compile(r"^arn:(?:aws|aws-cn|aws-us-gov):s3:::(?P<bucket>[^/]+)$")
_TRAIL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,126}[A-Za-z0-9]$")
_TRAIL_ARN_RE = re.compile(
    r"^arn:(?:aws|aws-cn|aws-us-gov):cloudtrail:[^:]+:\d{12}:trail/(?P<name>[^/]+)$"
)


def valid_bucket_name(value: str) -> bool:
    """Return whether a value can safely identify a general-purpose S3 bucket."""
    if not _S3_BUCKET_RE.fullmatch(value):
        return False
    if ".." in value or _IP_ADDRESS_RE.fullmatch(value):
        return False
    return not (
        value.startswith("xn--")
        or value.startswith("sthree-")
        or value.startswith("amzn_s3_demo_")
        or value.endswith("-s3alias")
        or value.endswith("--ol-s3")
        or value.endswith(".mrap")
        or value.endswith("--x-s3")
        or value.endswith("--table-s3")
    )


def bucket_name(observation: Observation) -> str | None:
    """Extract a validated general-purpose bucket name from an observation."""
    if valid_bucket_name(observation.resource_name):
        return observation.resource_name
    match = _S3_ARN_RE.fullmatch(observation.resource_uid)
    if match and valid_bucket_name(match.group("bucket")):
        return match.group("bucket")
    return None


def trail_name(observation: Observation) -> str | None:
    """Extract a validated CloudTrail name from an observation."""
    if _TRAIL_NAME_RE.fullmatch(observation.resource_name):
        return observation.resource_name
    match = _TRAIL_ARN_RE.fullmatch(observation.resource_uid)
    if match and _TRAIL_NAME_RE.fullmatch(match.group("name")):
        return match.group("name")
    return None
