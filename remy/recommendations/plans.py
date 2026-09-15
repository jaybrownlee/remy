"""Structured change plans for checks requiring customer configuration."""

from dataclasses import dataclass
from typing import Literal

from remy.recommendations.framework import COMMIT, citations_for
from remy.reports.schema import Observation, Recommendation


@dataclass(frozen=True)
class ChangePlan:
    what: str
    why: str
    change: str
    impact: str
    context: str
    verify: str
    reference: str
    caveat: str
    status: Literal["needs_context", "manual_action"] = "needs_context"

    def build(self, observation: Observation) -> Recommendation:
        check = observation.check_id
        service = check.split("_", 1)[0]
        source = (
            f"https://github.com/prowler-cloud/prowler/blob/{COMMIT}/"
            f"prowler/providers/aws/services/{service}/{check}/{check}.py"
        )
        return Recommendation(
            status=self.status,
            what=self.what,
            why=self.why,
            change=self.change,
            impact=self.impact,
            citations=citations_for(check),
            terraform=None,
            filename=None,
            assumptions=[
                self.caveat,
                "Required configuration is absent from the saved finding: " + self.context,
                "No executable configuration is generated until these inputs are confirmed. "
                "Update an existing Terraform resource in its owning workspace; import an "
                "unmanaged resource only after confirming ownership and its complete state.",
            ],
            steps=[
                "Confirm the observation's account, Region, resource, and current setting "
                "with the owner. Review " + self.context,
                self.change,
                "Review dependencies and related findings together, test the proposed change "
                "in a representative environment, and schedule it through the owner's process.",
                self.verify,
                "Rerun the pinned check and retain the verification evidence. Report "
                "generation alone does not mark the finding resolved.",
                f"AWS reference: {self.reference}",
                f"Pinned scanner implementation: {source}",
            ],
            template_version="reviewed-plans-1",
        )
