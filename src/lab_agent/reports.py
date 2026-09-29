"""DOCX and PDF reporting from recorded state, evidence, and screenshots."""

from __future__ import annotations

import json
from pathlib import Path

from .evidence import list_evidence, validate_evidence
from .models import RunState


def _state(workspace: Path) -> RunState:
    return RunState.model_validate_json((workspace / "state" / "state.json").read_text(encoding="utf-8"))


def _output_paths(workspace: Path, state: RunState) -> tuple[Path, Path]:
    folder = workspace / "reports"
    folder.mkdir(parents=True, exist_ok=True)
    return folder / f"{state.assignment}_Report.docx", folder / f"{state.assignment}_Report.pdf"


def _valid_image(path: Path) -> bool:
    try:
        from PIL import Image
        with Image.open(path) as image:
            image.verify()
        return True
    except (ImportError, OSError, ValueError):
        return False


def generate_report(workspace: Path) -> Path:
    try:
        from docx import Document
        from docx.image.exceptions import UnrecognizedImageError
        from docx.shared import Inches
    except ImportError as exc:
        raise RuntimeError("DOCX reports require the documents extra: pip install -e .[documents]") from exc
    state = _state(workspace); evidence = list_evidence(workspace); checks = {entry["id"]: entry for entry in validate_evidence(workspace)}
    doc = Document(); section = doc.sections[0]
    section.top_margin = Inches(0.75); section.bottom_margin = Inches(0.75)
    doc.add_heading(f"{state.assignment} Laboratory Report", 0)
    doc.add_paragraph("Execution record, verified evidence, and captured screens")
    doc.add_heading("Objective", level=1); doc.add_paragraph(state.plan.objective)
    doc.add_heading("Execution status", level=1)
    doc.add_paragraph(f"Run status: {state.status}. Completed steps: {len(state.completed_steps)} of {len(state.plan.steps)}.")
    doc.add_heading("Checklist", level=1)
    table = doc.add_table(rows=1, cols=3); table.style = "Table Grid"
    for cell, label in zip(table.rows[0].cells, ("Step", "Action", "Status")): cell.text = label
    for task in state.plan.steps:
        cells = table.add_row().cells; cells[0].text = f"{task.id}. {task.title}"; cells[1].text = task.action; cells[2].text = task.status.value
    doc.add_heading("Evidence and screenshots", level=1)
    if not evidence: doc.add_paragraph("No evidence has been registered.")
    for item in evidence:
        check = checks.get(item.id, {}); doc.add_heading(f"{item.id}  {item.description}", level=2)
        doc.add_paragraph(f"Type: {item.type}. Integrity verified: {check.get('verified', False)}. SHA-256: {item.sha256 or 'not recorded'}.")
        image = (workspace / item.path).resolve()
        if item.type == "screenshot" and image.is_relative_to(workspace.resolve()) and image.is_file() and _valid_image(image):
            try: doc.add_picture(str(image), width=Inches(6.2))
            except (OSError, ValueError, UnrecognizedImageError) as exc: doc.add_paragraph(f"Screenshot could not be embedded: {exc}")
    if state.errors:
        doc.add_heading("Execution errors", level=1)
        for error in state.errors: doc.add_paragraph(json.dumps(error, ensure_ascii=False), style="List Bullet")
    doc.add_paragraph("Source evidence remains unchanged. The manifest records each original path and SHA-256 hash.")
    docx, _ = _output_paths(workspace, state); doc.save(docx)
    return docx


def generate_pdf_report(workspace: Path) -> Path:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import inch
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        from reportlab.platypus import (
            Image,
            PageBreak,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError as exc:
        raise RuntimeError("PDF reports require the documents extra: pip install -e .[documents]") from exc
    state = _state(workspace); evidence = list_evidence(workspace); styles = getSampleStyleSheet(); _, output = _output_paths(workspace, state)
    font_candidates = [Path("C:/Windows/Fonts/arial.ttf"), Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf")]
    font_path = next((path for path in font_candidates if path.is_file()), None)
    font_name = "Helvetica"
    if font_path:
        font_name = "LabAgentUnicode"
        pdfmetrics.registerFont(TTFont(font_name, str(font_path)))
        for style in (styles["Title"], styles["Heading1"], styles["Heading2"], styles["Normal"]): style.fontName = font_name
    story = [Paragraph(f"{state.assignment} Laboratory Report", styles["Title"]), Spacer(1, 0.2 * inch), Paragraph("Execution record, verified evidence, and captured screens", styles["Normal"]), Spacer(1, 0.15 * inch), Paragraph("Objective", styles["Heading1"]), Paragraph(state.plan.objective, styles["Normal"]), Paragraph("Checklist", styles["Heading1"])]
    rows = [["Step", "Action", "Status"]] + [[f"{task.id}. {task.title}", task.action, task.status.value] for task in state.plan.steps]
    grid = Table(rows, colWidths=[3.6 * inch, 1.4 * inch, 1.0 * inch]); grid.setStyle(TableStyle([("GRID", (0,0), (-1,-1), 0.25, colors.lightgrey), ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#1F4E78")), ("TEXTCOLOR", (0,0), (-1,0), colors.white), ("FONTNAME", (0,0), (-1,-1), font_name), ("VALIGN", (0,0), (-1,-1), "TOP")]))
    story.extend([grid, PageBreak(), Paragraph("Evidence and screenshots", styles["Heading1"])])
    for item in evidence:
        story.extend([Paragraph(f"{item.id}  {item.description}", styles["Heading2"]), Paragraph(f"Type: {item.type}; SHA-256: {item.sha256 or 'not recorded'}", styles["Normal"]), Spacer(1, 0.08 * inch)])
        image = (workspace / item.path).resolve()
        if item.type == "screenshot" and image.is_relative_to(workspace.resolve()) and image.is_file() and _valid_image(image):
            try:
                picture = Image(str(image)); picture._restrictSize(6.3 * inch, 8.0 * inch); story.extend([picture, Spacer(1, 0.14 * inch)])
            except OSError: story.append(Paragraph("Screenshot could not be embedded.", styles["Normal"]))
    SimpleDocTemplate(str(output), pagesize=letter, rightMargin=0.7 * inch, leftMargin=0.7 * inch, topMargin=0.7 * inch, bottomMargin=0.7 * inch).build(story)
    return output


def generate_reports(workspace: Path) -> dict[str, str]:
    docx = generate_report(workspace); pdf = generate_pdf_report(workspace)
    return {"docx": str(docx), "pdf": str(pdf)}
