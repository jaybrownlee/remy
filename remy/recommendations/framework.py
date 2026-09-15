"""Source-pinned Prowler framework membership; not a legal compliance determination."""

import hashlib
from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel, Field

from remy.reports.schema import Citation

PROWLER_VERSION = "5.42.0"
COMMIT = "73ae2eb1947a0912a05010a296f469bfa55ebe76"
SOURCE_URL = (
    f"https://github.com/prowler-cloud/prowler/blob/{COMMIT}/prowler/compliance/aws/hipaa_aws.json"
)


class Requirement(BaseModel):
    name: str = Field(alias="Name")
    checks: list[str] = Field(alias="Checks")


class Framework(BaseModel):
    requirements: list[Requirement] = Field(alias="Requirements")


@lru_cache(maxsize=1)
def framework() -> Framework:
    raw = (Path(__file__).resolve().parents[1] / "data" / "hipaa_aws.json").read_bytes()
    # Verify the Git blob ID against the pinned source tree, including Git's framing.
    blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    if blob != "01de916ec6a8a36edc3055fcfe991e77b40a73e1":
        raise ValueError("Pinned HIPAA framework has changed; review and update its provenance.")
    return Framework.model_validate_json(raw)


def check_ids() -> frozenset[str]:
    return frozenset(
        check for requirement in framework().requirements for check in requirement.checks
    )


def citations_for(check_id: str) -> list[Citation]:
    citations = []
    for requirement in framework().requirements:
        if check_id not in requirement.checks:
            continue
        section, _, title = requirement.name.partition(" ")
        parent = section.split("(", 1)[0]
        citations.append(
            Citation(
                section=f"45 CFR {section}",
                title=title,
                url=(
                    "https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/"
                    f"part-164/subpart-C/section-{parent}"
                ),
                confidence="low",
                source_url=SOURCE_URL,
                note=(
                    f"Prowler {PROWLER_VERSION} framework mapping; applicability requires review. "
                    "This technical result does not establish HIPAA noncompliance. "
                ),
            )
        )
    return citations
