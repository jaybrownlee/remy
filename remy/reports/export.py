"""Portable report exports. No execution, network calls, or customer-state access."""

import hashlib
import io
import json
import textwrap
from typing import cast
from xml.sax.saxutils import escape
from zipfile import ZIP_DEFLATED, ZipFile

from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import (
    BaseDocTemplate,
    Flowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
)

from remy.reports.schema import Report


def json_export(report: Report) -> bytes:
    return report.model_dump_json(indent=2, exclude_unset=True).encode("utf-8")


def terraform_export(report: Report) -> bytes:
    stream = io.BytesIO()
    manifest: list[dict[str, object]] = []
    with ZipFile(stream, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr("report.json", json_export(report))
        archive.writestr(
            "README.md",
            """# Remy suggested Terraform

This ZIP is guidance, not a single deployable Terraform module.
Read report.json or the PDF for every item's explanation, draft HIPAA mapping,
assumptions, missing inputs, impact, and verification instructions.

1. Identify the item by its stable UUID in manifest.json.
2. Have an administrator review the recommendation and confirm its applicability.
3. Reconcile existing Terraform ownership and state before introducing resources.
4. Replace variables/placeholders; add the required provider and dependencies.
5. Review your own terraform plan. Run apply only in your own trusted workflow.
6. Re-scan afterward to check the technical result.

Files in separate item directories are independent suggestions; do not combine
or apply them blindly. Shared/conflicting changes are NOT automatically reconciled
in this prototype. Template validation and HIPAA review remain incomplete.
Manual/unsupported items have no .tf file and remain listed in the manifest.
Remy did not apply or authorize any change. No GitHub account is required.
""",
        )
        for item in report.items:
            code = item.recommendation.terraform
            entry: dict[str, object] = {
                "item_id": str(item.item_id),
                "line_number": item.line_number,
                "check_id": item.observation.check_id,
                "status": item.recommendation.status,
                "validation": item.recommendation.validation,
                "change_target": item.change_target.model_dump(mode="json")
                if item.change_target
                else None,
                "coordination_notes": item.coordination_notes,
                "related_item_ids": [str(item_id) for item_id in item.related_item_ids],
                "path": None,
                "sha256": None,
            }
            if code:
                # Never trust an uploaded name or recommendation filename as a path.
                path = f"items/{item.item_id}/suggestion.tf"
                entry.update(path=path, sha256=hashlib.sha256(code.encode()).hexdigest())
                archive.writestr(path, code)
            manifest.append(entry)
        archive.writestr(
            "manifest.json",
            json.dumps(
                {
                    "schema_version": "1.1",
                    "report_id": str(report.report_id),
                    "report_content_sha256": report.content_sha256,
                    "items": manifest,
                    "coordination_assessed": report.coordination_assessed,
                    "shared_changes": [
                        group.model_dump(mode="json") for group in report.shared_changes
                    ],
                },
                indent=2,
            ),
        )
    return stream.getvalue()


def pdf_export(report: Report) -> bytes:
    stream = io.BytesIO()
    doc = SimpleDocTemplate(
        stream,
        pagesize=(8.5 * inch, 11 * inch),
        leftMargin=0.65 * inch,
        rightMargin=0.65 * inch,
        topMargin=0.65 * inch,
        bottomMargin=0.65 * inch,
        title="Remy remediation report",
    )
    styles = getSampleStyleSheet()
    body = ParagraphStyle(
        "RemyBody",
        parent=styles["BodyText"],
        fontSize=9.5,
        leading=13,
        spaceAfter=7,
        splitLongWords=True,
    )
    code_style = ParagraphStyle(
        "RemyCode",
        fontName="Courier",
        fontSize=7.5,
        leading=10,
        backColor=colors.HexColor("#f0f4f6"),
        borderPadding=7,
        spaceBefore=6,
        spaceAfter=10,
    )
    story: list[Flowable] = []

    def paragraph(text: str, style: ParagraphStyle = body) -> None:
        story.append(Paragraph(escape(text).replace("\n", "<br/>"), style))

    paragraph("Remy remediation report", cast(ParagraphStyle, styles["Title"]))
    paragraph(report.source_name, cast(ParagraphStyle, styles["Heading2"]))
    paragraph(f"Generated {report.created_at:%Y-%m-%d %H:%M UTC} | Report {report.report_id}")
    paragraph(report.source_kind)
    paragraph(
        f"{len(report.items)} failed findings | {report.pass_count} passed | "
        f"{report.manual_count} manual | {report.observation_count} total observations"
    )
    paragraph("Source and coverage notes", cast(ParagraphStyle, styles["Heading2"]))
    for warning in report.warnings:
        paragraph(f"• {warning}")
    paragraph(
        "Suggested Terraform requires review and adaptation. No changes have been applied. "
        "HIPAA mappings are draft; a report is not a compliance certification."
    )
    if not report.items:
        paragraph(
            "No failed observations were present. This does not establish overall compliance."
        )
    for item in report.items:
        story.append(PageBreak())
        obs, rec = item.observation, item.recommendation
        paragraph(f"Item {item.line_number}: {obs.title}", cast(ParagraphStyle, styles["Heading1"]))
        paragraph(f"Stable item ID: {item.item_id}")
        paragraph(
            f"Check: {obs.check_id} | Priority {item.priority_score} | "
            f"Guidance: {rec.status.replace('_', ' ')}"
        )
        paragraph(f"Account: {obs.account_id} | Region: {obs.region} | Service: {obs.service}")
        paragraph(f"Resource: {obs.resource_uid}")
        if item.coordination_notes:
            paragraph("Shared-setting review", cast(ParagraphStyle, styles["Heading2"]))
            for note in item.coordination_notes:
                paragraph(note)
            if item.related_item_ids:
                paragraph("Review with item IDs: " + ", ".join(map(str, item.related_item_ids)))
        for title, text in [
            ("Observed finding", obs.detail),
            ("Explanation", rec.what),
            ("Why it matters", rec.why),
            ("Suggested change", rec.change),
            ("Potential impact", rec.impact),
        ]:
            paragraph(title, cast(ParagraphStyle, styles["Heading2"]))
            paragraph(text)
        paragraph("HIPAA references (draft)", cast(ParagraphStyle, styles["Heading2"]))
        if not rec.citations:
            paragraph("No reviewed citation available for this check. Mapping work remains.")
        for citation in rec.citations:
            citation_start = len(story)
            paragraph(f"{citation.section}: {citation.title} (HIPAA mapping - needs review)")
            paragraph(citation.url)
            paragraph(citation.note)
            if citation.source_url:
                paragraph("Mapping source: " + citation.source_url)
            citation_block = story[citation_start:]
            del story[citation_start:]
            story.append(KeepTogether(citation_block))
        paragraph("Assumptions and inputs", cast(ParagraphStyle, styles["Heading2"]))
        for assumption in rec.assumptions:
            paragraph(f"• {assumption}")
        if rec.terraform:
            paragraph("Suggested Terraform", cast(ParagraphStyle, styles["Heading2"]))
            paragraph(rec.validation)
            wrapped = "\n".join(
                "\n".join(
                    textwrap.wrap(
                        line.expandtabs(2),
                        width=85,
                        replace_whitespace=False,
                        drop_whitespace=False,
                    )
                )
                if line
                else ""
                for line in rec.terraform.splitlines()
            )
            # Preformatted does not parse markup. Code is display-only; ZIP preserves exact bytes.
            story.append(Preformatted(wrapped, code_style))
            paragraph("PDF line wrapping is for readability. Use the ZIP for exact code text.")
        paragraph("Customer review and verification", cast(ParagraphStyle, styles["Heading2"]))
        for index, step in enumerate(rec.steps, 1):
            paragraph(f"{index}. {step}")
        paragraph("Priority reasons: " + "; ".join(item.priority_reasons))
        story.append(Spacer(1, 10))

    def footer(canvas: Canvas, _document: BaseDocTemplate) -> None:
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#64717a"))
        canvas.drawString(0.65 * inch, 0.35 * inch, "Remy | Suggested remediation")
        canvas.drawRightString(7.85 * inch, 0.35 * inch, f"Page {canvas.getPageNumber()}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return stream.getvalue()
