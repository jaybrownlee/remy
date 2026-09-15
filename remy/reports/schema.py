"""Public contracts for the first saved-scan report workflow."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Observation(StrictModel):
    account_id: str
    check_id: str
    resource_uid: str
    resource_name: str
    service: str
    region: str
    status: Literal["FAIL", "PASS", "MANUAL"]
    severity: str
    title: str
    detail: str
    observed_at: datetime | None = None


class Citation(StrictModel):
    source_url: str | None = None
    section: str
    title: str
    url: str
    confidence: Literal["high", "medium", "low"] = "low"
    note: str = "Draft mapping; requires review before production use."


class Recommendation(StrictModel):
    status: Literal["terraform_guidance", "needs_context", "manual_action", "unsupported"]
    what: str
    why: str
    change: str
    impact: str
    citations: list[Citation] = Field(default_factory=list)
    terraform: str | None = None
    filename: str | None = None
    assumptions: list[str] = Field(default_factory=list)
    steps: list[str] = Field(default_factory=list)
    template_version: str = "prototype-2"
    validation: str = "Not validated against your environment. Review and adapt before applying."


class ChangeTarget(StrictModel):
    account_id: str
    region: str | None = None
    setting: str
    resource: str


class SharedChange(StrictModel):
    target: ChangeTarget
    item_ids: list[UUID]
    message: str


class ReportItem(StrictModel):
    item_id: UUID
    line_number: int
    observation: Observation
    priority_score: int
    priority_reasons: list[str]
    recommendation: Recommendation
    change_target: ChangeTarget | None = None
    coordination_notes: list[str] = Field(default_factory=list)
    related_item_ids: list[UUID] = Field(default_factory=list)


class Report(StrictModel):
    schema_version: str = "1.1"
    report_id: UUID
    org_id: UUID
    created_at: datetime
    source_name: str
    source_sha256: str
    source_kind: str = "Imported Prowler output; scan completeness not independently verified."
    items: list[ReportItem]
    observation_count: int
    pass_count: int
    manual_count: int
    warnings: list[str] = Field(default_factory=list)
    shared_changes: list[SharedChange] = Field(default_factory=list)
    coordination_assessed: bool = False
    content_sha256: str = ""
